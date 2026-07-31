#!/usr/bin/env node
'use strict';

// Claude Code PreToolUse adapter.
//
// Install:
//   "hooks": { "PreToolUse": [ { "matcher": "*", "hooks": [
//     { "type": "command", "command": "node \"$HOME/.vibeguard/adapters/claude-code.js\"", "timeout": 10 } ] } ] }
//
// Claude Code is the strongest enforcement point of the four harnesses: a
// PreToolUse hook can return permissionDecision "deny" and the call never
// runs. Everything else here is about staying quiet when there is nothing
// worth saying.

const fs = require('fs');
const path = require('path');
const os = require('os');

const { load } = require('../lib/policy');
const { extract } = require('../lib/extract');
const { decide, card } = require('../lib/decide');
const audit = require('../lib/audit');
const skills = require('../lib/skills');
const bridge = require('../lib/bridge');
const remember = require('../lib/remember');

// Editor bridge. The VS Code / Cursor extension tails ~/.vibeguard/events.jsonl
// and writes decisions back as files. Every card the user sees has to be
// emitted here or the extension's panel goes silently dead — it has no other
// source of events.
const INTERACTIVE = process.env.VIBEGUARD_INTERACTIVE === '1';
const NOTIFY = process.env.VIBEGUARD_NOTIFY !== '0';
const DECISION_TIMEOUT_MS = Number(process.env.VIBEGUARD_TIMEOUT_MS || 12000);

// Tools that never prompt, and never touch the network.
const SILENT_TOOLS = new Set([
  'Read', 'Glob', 'Grep', 'TodoWrite', 'NotebookRead', 'ExitPlanMode', 'KillShell',
]);

const QUIET_MODES = new Set(['bypassPermissions', 'dontAsk', 'acceptAll', 'auto']);

let raw = '';
process.stdin.on('data', (d) => (raw += d));
process.stdin.on('end', async () => {
  let out = null;
  try {
    out = await run(JSON.parse(raw));
  } catch {
    // Never break the agent because of a hook bug.
  }
  if (out) process.stdout.write(JSON.stringify(out));
  process.exit(0);
});

async function run(input) {
  const tool = input.tool_name || '';
  const ti = input.tool_input || {};
  if (!tool || SILENT_TOOLS.has(tool)) return null;

  const policy = load(input.cwd);

  // Skill guard runs first and is not overridable by an allowlist. SessionStart
  // could only report drift; this is where the report becomes enforcement. A
  // skill whose files moved after you pinned them does not get to run its
  // scripts because someone once approved `Bash(python:*)`.
  const guard = skillGuard(tool, ti);
  if (guard) {
    // `ask` by default, `deny` under the strict profile. A hard block is the
    // right answer for a managed fleet and the wrong one for someone who just
    // installed the plugin: they cannot clear it without a terminal, so a
    // deny they cannot lift is worse than a red card they can read and refuse.
    const decision = policy.defaults.skillDrift === 'deny' ? 'deny' : 'ask';
    audit.record(policy, {
      harness: 'claude-code',
      tool,
      decision,
      rule: 'skill.unpinned',
      hosts: [],
      skill: guard.id,
      cwd: input.cwd || '',
      session: input.session_id || '',
    });
    return surface(
      { decision, level: 'red', rule: 'skill.unpinned', msg: guard.msg, action: guard.action },
      input, tool, ti);
  }

  const ext = extract(tool, ti, input.cwd);
  const call = { tool, text: tool === 'Bash' ? String(ti.command || '') : '' };
  const v = decide(policy, call, ext);

  audit.record(policy, {
    harness: 'claude-code',
    tool,
    decision: v.decision,
    rule: v.rule,
    hosts: v.destinations.map((d) => d.host).filter(Boolean),
    cwd: input.cwd || '',
    session: input.session_id || '',
  });

  if (v.decision === 'deny') return surface(v, input, tool, ti, ext);

  if (v.decision === 'allow') return null;

  // Already answered once with "always allow". Nothing red or skill-related can
  // reach this — keyFor refuses to produce a key for those.
  if (remember.has(remember.keyFor(v, ext))) return null;

  // decision === 'ask'. Red always breaks through, and so does anything the
  // egress engine flagged — an allowlisted `Bash(*)` rule must not silently
  // waive a call to an unknown domain. Routine local warnings stay polite and
  // defer to whatever the user already allowlisted.
  const mustSurface = v.level === 'red' || v.rule.startsWith('egress.');
  if (!mustSurface && wouldAutoRun(input, tool, ti)) return null;

  return surface(v, input, tool, ti, ext);
}

// --- the editor bridge ------------------------------------------------------
//
// Every card the user sees goes through here, because the VS Code / Cursor
// extension has no other source of events — miss one call site and the panel
// goes quiet with no error. When the extension is listening it can also answer
// the prompt, which is what the Approve / Deny buttons in the popup do.

async function surface(v, input, tool, ti, ext) {
  const live = bridge.extensionAlive();
  // Whether the popup should offer a third button. Null for red and for skill
  // drift, which is how "always allow" stays off the things it must not cover.
  const rememberKey = remember.keyFor(v, ext);

  // A hard deny is not negotiable from the editor. The panel still shows it,
  // but there is no approve button — otherwise an enforcement guarantee is only
  // as strong as a popup click, and `egress.secret-exfiltration` stops meaning
  // anything. Only `ask` is interactive, which is what the old hook did too.
  const interactive = INTERACTIVE && live && v.decision === 'ask';

  const id = bridge.emit({
    level: v.level,
    code: v.rule,
    msg: v.msg,
    action: v.action || '',
    tool,
    target: targetOf(tool, ti),
    cwd: input.cwd || '',
    session_id: input.session_id || '',
    interactive,
    // The extension renders an "Always allow <what>" button from these.
    allowAlways: interactive && !!rememberKey,
    allowAlwaysLabel: rememberKey ? remember.describe(rememberKey) : '',
  });

  // The editor popup replaces the OS banner when an editor is listening.
  if (v.level === 'red' && NOTIFY && !live) {
    notifyMac(v.decision === 'deny' ? 'VibeGuard blocked a request' : 'VibeGuard: HIGH RISK', v.msg);
  }

  if (interactive && id) {
    const d = await bridge.waitForDecision(id, DECISION_TIMEOUT_MS);
    if (d && d.decision === 'deny') return out('deny', d.reason || `Denied in your editor. ${card(v)}`);
    if (d && d.decision === 'always' && rememberKey) {
      remember.add(rememberKey, { rule: v.rule, tool });
      return out('allow', `Approved in your editor, and VibeGuard will stop asking about ${remember.describe(rememberKey)}.`);
    }
    if (d && (d.decision === 'allow' || d.decision === 'always')) {
      return out('allow', `Approved in your editor. ${card(v)}`);
    }
    // No answer in time: fall through to a normal prompt.
  }

  return out(v.decision, card(v));
}

function out(permissionDecision, permissionDecisionReason) {
  return {
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason },
  };
}

function targetOf(tool, ti) {
  if (tool === 'Bash') return String(ti.command || '');
  return String(ti.file_path || ti.url || ti.path || ti.notebook_path || '');
}

// --- would Claude have run this without asking? ----------------------------

function wouldAutoRun(input, tool, ti) {
  const mode = input.permission_mode || input.permissionMode || '';
  if (QUIET_MODES.has(mode)) return true;
  if (mode === 'acceptEdits' && /^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool)) return true;
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
      /* missing settings file is fine */
    }
  }
  return rules;
}

function ruleMatches(rule, tool, target) {
  const m = rule.match(/^([A-Za-z_][\w-]*)(?:\((.*)\))?$/);
  if (!m) return false;
  const [, ruleTool, arg] = m;
  if (ruleTool !== tool) return false;
  if (arg === undefined) return true;
  if (arg.endsWith('*')) return target.startsWith(arg.slice(0, -1));
  return target === arg;
}

// --- skill guard -----------------------------------------------------------
//
// Reads the small state file SessionStart wrote, so the per-call cost is one
// tiny JSON read rather than re-hashing every installed skill.

function skillGuard(tool, ti) {
  if (tool === 'Skill') {
    const name = String(ti.skill || ti.name || '');
    if (!name) return null;
    const bare = name.split(':').pop();
    const hit = skills.readState().find((f) => f.id.split(':').pop() === bare);
    if (!hit) return null;
    return {
      id: hit.id,
      msg: `Invokes the skill "${bare}", which VibeGuard flagged because ${hit.reason}.`,
      action: `Blocked. Review it, then run: ${hit.remedy}`,
    };
  }
  return skills.guardPaths([
    tool === 'Bash' ? ti.command : '',
    ti.file_path,
    ti.path,
    ti.notebook_path,
  ]);
}

// macOS only, and deliberately not polyfilled. The banner is a secondary
// channel — the deny card in the permission dialog is the primary one and works
// on every platform. A Windows toast needs either a PowerShell WinRT
// incantation that varies by build or a third-party module, and an alert that
// fires unreliably is worse than one that is documented as absent.
function notifyMac(title, msg) {
  if (process.platform !== 'darwin') return;
  try {
    const { spawn } = require('child_process');
    const script = `display notification ${JSON.stringify(String(msg).slice(0, 200))} with title ${JSON.stringify(title)} sound name "Basso"`;
    spawn('osascript', ['-e', script], { detached: true, stdio: 'ignore' }).unref();
  } catch {
    /* notifications are best effort */
  }
}
