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

  // A green verdict still deserves a card *if Claude Code was going to ask
  // anyway*. `mkdir test` is harmless, but it does raise a prompt — and a bare
  // prompt with no explanation is the exact problem VibeGuard exists to solve.
  // Returning null here made those prompts silent, which was a regression from
  // v1.0.0. The two guards below are what stop this from inventing a prompt
  // that would not otherwise have existed.
  if (v.decision === 'allow') {
    if (wouldAutoRun(input, tool, ti)) return null;
    if (!wouldPrompt(tool, ti)) return null;
    return surface(v, input, tool, ti, ext);
  }

  // Already answered once with "always allow". Nothing red or skill-related can
  // reach this — keyFor refuses to produce a key for those.
  if (remember.has(remember.keyFor(v, ext))) return null;

  // decision === 'ask'. The job is to explain prompts the user was already
  // going to see, not to manufacture new ones — a tool that adds friction to
  // work you already approved gets uninstalled, and then it protects nobody.
  //
  // Exactly one thing breaks through an allowlist by default: red. That set is
  // tiny and irreversible — sudo, force-push, erasing a disk, dropping a table
  // — and "I allowlisted Bash" should not silently include them. This is v1.0.0
  // behaviour and is documented in the README.
  //
  // Egress asks defer to the allowlist under the friendly profile: if you told
  // Claude Code that curl is fine, VibeGuard does not second-guess it for
  // api.stripe.com. Strict mode flips this, because a managed fleet does want
  // the network policy to win over a developer's local convenience.
  const egressWins = policy.defaults.egressOverridesAllowlist === true;
  const mustSurface = v.level === 'red' || (egressWins && v.rule.startsWith('egress.'));
  if (!mustSurface && wouldAutoRun(input, tool, ti)) return null;

  // We are about to put a real question in front of a human. Leave a marker so
  // PostToolUse can tell an approval apart from a tool that simply ran — an
  // auto-approved call reaches PostToolUse identically, and treating that as
  // consent silently disabled the guardrails.
  if (remember.autoLearnable(v)) {
    remember.notePending(remember.keyFor(v, ext), input.session_id);
  }

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

  // If we are showing a card at all, the user decides — never us. A green
  // verdict returned as `allow` would auto-approve the call and remove the
  // prompt it was meant to annotate, which is the opposite of the job and
  // breaks the promise that VibeGuard cannot approve anything on your behalf.
  // Only an explicit answer from the editor, handled above, produces `allow`.
  return out(v.decision === 'allow' ? 'ask' : v.decision, card(v));
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

// --- would Claude Code prompt for this on its own? --------------------------
//
// Only speak up for tools the docs say always need approval. Anything else
// stays silent rather than guessing, because inventing a prompt turns a silent
// auto-run into a nag — worse than saying nothing.
//
// Sources: /docs/en/permissions (file modification always prompts; Bash prompts
// except a built-in read-only set) and /docs/en/security (network tools require
// approval).

const PROMPTING_TOOLS = new Set([
  'Bash', 'PowerShell',
  'Edit', 'Write', 'MultiEdit', 'NotebookEdit',
  'WebFetch', 'WebSearch',
]);

const READ_ONLY_CMDS = new Set([
  'ls', 'cat', 'echo', 'pwd', 'head', 'tail', 'grep', 'find',
  'wc', 'which', 'diff', 'stat', 'du', 'cd',
]);
const READ_ONLY_GIT = new Set([
  'status', 'log', 'diff', 'show', 'branch', 'remote', 'blame', 'describe',
]);

function isReadOnlyBash(cmd) {
  if (!cmd.trim()) return false;
  if (/>|>>/.test(cmd)) return false; // a redirect writes somewhere
  return cmd.split(/&&|\|\||;|\|/).every((part) => {
    const words = part.trim().split(/\s+/).filter(Boolean);
    if (!words.length) return false;
    const [name, sub] = words;
    if (name === 'git') return READ_ONLY_GIT.has(sub);
    return READ_ONLY_CMDS.has(name);
  });
}

function wouldPrompt(tool, ti) {
  if (!PROMPTING_TOOLS.has(tool)) return false;
  if (tool === 'Bash' && isReadOnlyBash(String(ti.command || ''))) return false;
  return true;
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

// The macOS notification banner was removed deliberately.
//
// Claude Code already raises its own OS notification when it needs permission,
// so a second banner from VibeGuard was pure duplication — two alerts for one
// decision, on a dialog the user is already looking at. The card inside the
// prompt is the signal; a banner on top of it is noise, and noise is what makes
// people stop reading the cards.
//
// It was also the only platform-specific behaviour in the runtime, so removing
// it makes macOS, Linux and Windows behave identically.
