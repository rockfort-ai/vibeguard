#!/usr/bin/env node
'use strict';

// VibeGuard: plain-English, color-coded cards for Claude Code permission
// prompts, written for people who are not developers.
//
// Runs as a PreToolUse hook. Only PreToolUse can put text inside the permission
// dialog (via permissionDecisionReason), so everything goes through here.
//
// Rules:
//   - Tools that never prompt (Read, Grep, ...) are always silent.
//   - GREEN and ORANGE respect your allowlist. If Claude would have auto-run
//     it, VibeGuard stays quiet. If Claude was going to ask anyway, the card
//     rides along with the prompt.
//   - RED always breaks through, even if allowlisted, and raises a notification.
//
// If the editor extension is running, every card it needs is also written to
// ~/.vibeguard/events.jsonl. That is one-way and non-blocking unless interactive
// mode is on, in which case a Deny in the editor popup denies the tool call.

const fs = require('fs');
const path = require('path');
const os = require('os');

const G = require('../lib/classify.js');
const bridge = require('../lib/bridge.js');

// Permission modes where nothing gets prompted anyway.
const QUIET_MODES = new Set(['bypassPermissions', 'dontAsk', 'acceptAll', 'auto']);

const INTERACTIVE = process.env.VIBEGUARD_INTERACTIVE === '1';
const NOTIFY = process.env.VIBEGUARD_NOTIFY !== '0';
// Comfortably inside the 20s hook timeout declared in hooks.json.
const DECISION_TIMEOUT_MS = Number(process.env.VIBEGUARD_TIMEOUT_MS || 12000);

let raw = '';
process.stdin.on('data', (d) => (raw += d));
process.stdin.on('end', async () => {
  let out = null;
  try {
    out = await evaluate(JSON.parse(raw));
  } catch (e) {
    // Never break Claude Code because of a hook bug.
  }
  if (out) process.stdout.write(JSON.stringify(out));
  process.exit(0);
});

async function evaluate(input) {
  const tool = input.tool_name || '';
  const ti = input.tool_input || {};
  if (!tool) return null;
  if (!G.isPromptingTool(tool)) return null;

  const verdict = G.verdictFor(tool, ti);
  const autoRun = wouldAutoRun(input, tool, ti);

  // Green and orange defer to the allowlist; red never does.
  if (verdict.level !== 'red' && autoRun) return null;

  const live = bridge.extensionAlive();
  const interactive = INTERACTIVE && live;

  const id = bridge.emit({
    level: verdict.level,
    code: verdict.code,
    msg: verdict.msg,
    action: verdict.action || G.ACTIONS[verdict.level],
    tool,
    target: G.targetOf(tool, ti),
    cwd: input.cwd || '',
    session_id: input.session_id || '',
    interactive,
  });

  // The editor popup replaces the OS banner when an editor is listening.
  if (verdict.level === 'red' && NOTIFY && !live) {
    notify('VibeGuard: HIGH RISK', verdict.msg);
  }

  if (interactive && id) {
    const d = await bridge.waitForDecision(id, DECISION_TIMEOUT_MS);
    if (d && d.decision === 'deny') {
      return decision('deny', d.reason || `Denied in your editor. ${G.card(verdict)}`);
    }
    if (d && d.decision === 'allow') {
      return decision('allow', `Approved in your editor. ${G.card(verdict)}`);
    }
    // No answer in time: fall through to a normal prompt.
  }

  return decision('ask', G.card(verdict));
}

function decision(permissionDecision, permissionDecisionReason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason,
    },
  };
}

// ---------------------------------------------------------------------------
// Would Claude have run this without asking?
// ---------------------------------------------------------------------------

function wouldAutoRun(input, tool, ti) {
  const mode = input.permission_mode || input.permissionMode || '';
  if (QUIET_MODES.has(mode)) return true;
  if (mode === 'acceptEdits' && G.EDIT_TOOLS.test(tool)) return true;
  if (tool === 'Bash' && G.isReadOnlyBash(String(ti.command || ''))) return true;

  const target = tool === 'Bash' ? String(ti.command || '') : String(ti.file_path || ti.url || '');
  return allowRules(input.cwd).some((rule) => ruleMatches(rule, tool, target));
}

function allowRules(cwd) {
  const files = [
    path.join(os.homedir(), '.claude', 'settings.json'),
    path.join(os.homedir(), '.claude', 'settings.local.json'),
  ];
  if (cwd) {
    files.push(path.join(cwd, '.claude', 'settings.json'));
    files.push(path.join(cwd, '.claude', 'settings.local.json'));
  }
  const rules = [];
  for (const f of files) {
    try {
      const j = JSON.parse(fs.readFileSync(f, 'utf8'));
      const allow = j && j.permissions && j.permissions.allow;
      if (Array.isArray(allow)) rules.push(...allow.filter((r) => typeof r === 'string'));
    } catch {
      // missing or unreadable settings file is fine
    }
  }
  return rules;
}

function ruleMatches(rule, tool, target) {
  const m = rule.match(/^([A-Za-z_][\w-]*)(?:\((.*)\))?$/);
  if (!m) return false;
  const [, ruleTool, arg] = m;
  if (ruleTool !== tool) return false;
  if (arg === undefined) return true; // bare tool name allows everything
  if (arg.endsWith('*')) return target.startsWith(arg.slice(0, -1));
  return target === arg;
}

// ---------------------------------------------------------------------------
// Fire and forget desktop notification for red items.
// ---------------------------------------------------------------------------

function notify(title, msg) {
  try {
    const { spawn } = require('child_process');
    const opts = { detached: true, stdio: 'ignore' };
    if (process.platform === 'darwin') {
      const script = `display notification ${JSON.stringify(msg.slice(0, 200))} with title ${JSON.stringify(title)} sound name "Basso"`;
      spawn('osascript', ['-e', script], opts).unref();
    } else if (process.platform === 'linux') {
      spawn('notify-send', ['-u', 'critical', title, msg.slice(0, 200)], opts).unref();
    }
  } catch {
    // notifications are best effort
  }
}
