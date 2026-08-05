#!/usr/bin/env node
'use strict';

// Claude Code PreToolUse adapter.
//
// Install:
//   "hooks": { "PreToolUse": [ { "matcher": "*", "hooks": [
//     { "type": "command", "command": "node \"$HOME/.rlegend/adapters/claude-code.js\"", "timeout": 10 } ] } ] }
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
const session = require('../lib/session');
const safelist = require('../lib/safelist');

// Editor bridge. The VS Code / Cursor extension tails ~/.rlegend/events.jsonl
// and writes decisions back as files. Every card the user sees has to be
// emitted here or the extension's panel goes silently dead — it has no other
// source of events.
const INTERACTIVE = process.env.RLEGEND_INTERACTIVE === '1';
const DECISION_TIMEOUT_MS = Number(process.env.RLEGEND_TIMEOUT_MS || 12000);

// Tools that never prompt, and never touch the network.
const SILENT_TOOLS = new Set([
  'Read', 'Glob', 'Grep', 'TodoWrite', 'NotebookRead', 'ExitPlanMode', 'KillShell',
]);

// Modes in which Claude Code runs tools without asking. The full enum shipped
// in 2.1.220 is none | auto | plan | dontAsk | bypassPermissions | acceptEdits;
// `plan` and `none` still prompt, and `acceptEdits` is handled separately below
// because it only auto-runs the edit family.
const QUIET_MODES = new Set(['bypassPermissions', 'dontAsk', 'auto']);

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
  const mode = input.permission_mode || input.permissionMode || '';
  const ctx = { input, tool, ti, mode };

  // Invoking a skill is the one moment Rockfort Legend knows for certain which skill
  // is about to be loaded, so that is where it checks — live, on that one
  // skill, rather than consulting a state file SessionStart wrote an hour ago
  // and which only ever held red rows. It speaks for drift and for unaccepted
  // red signals, and stays quiet otherwise: a card on every skill use is a nag,
  // and a nag gets a security tool uninstalled.
  if (tool === 'Skill') return invokedSkill(policy, input, ti, ctx);

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
    const v = {
      decision, level: 'red', rule: 'skill.unpinned',
      msg: guard.msg, action: guard.action, destinations: [],
    };
    // A deny blocks in every mode. An ask is a question, and a fully quiet mode
    // is the user having said not to ask — so it goes to the recap instead.
    if (decision === 'ask' && fullyQuiet(input)) {
      return finish(policy, v, {
        ...ctx, surfaced: false, quiet: `mode:${mode}`, skill: guard.id,
      });
    }
    return finish(policy, v, { ...ctx, surfaced: true, skill: guard.id });
  }

  const ext = extract(tool, ti, input.cwd);
  const call = { tool, text: tool === 'Bash' ? String(ti.command || '') : '' };
  let v = decide(policy, call, ext);
  ctx.ext = ext;

  // A server Rockfort Legend has never seen before. This is the only honest thing it
  // can say about MCP: it cannot see inside the call, or where the server sends
  // what it is given, but it does know whether this one has ever run here.
  //
  // Recorded at PreToolUse rather than after, so a server whose first call is
  // denied still lands in the inventory — otherwise `rlegend mcp` only ever knows
  // about the calls that worked. `count: false` keeps the calls column honest.
  //
  // The verdict is substituted rather than returned, so it goes through the
  // same quiet path as everything else: allowlist an MCP server and Rockfort Legend
  // does not second-guess you. Breaking through here would be inventing a
  // prompt, which is the one thing it must not do.
  if (tool.startsWith('mcp__') && v.decision !== 'deny') {
    const server = remember.serverOf(tool);
    const first = server && !remember.seenMcp(server);
    if (server) remember.noteMcp(tool, input.cwd || '', { count: false });
    if (first && v.decision === 'allow') {
      v = {
        decision: 'ask', level: 'orange', rule: 'mcp.new-server', destinations: ext.destinations,
        msg: `First use of the MCP server "${server}" on this machine. Rockfort Legend cannot see what an MCP server sends, or where.`,
        action: 'Approve if you installed this server on purpose.',
      };
    }
  }

  if (v.decision === 'deny') return finish(policy, v, { ...ctx, surfaced: true });

  // A green verdict still deserves a card *if Claude Code was going to ask
  // anyway*. `mkdir test` is harmless, but it does raise a prompt — and a bare
  // prompt with no explanation is the exact problem Rockfort Legend exists to solve.
  // Returning null here made those prompts silent, which was a regression from
  // v1.0.0. The two guards below are what stop this from inventing a prompt
  // that would not otherwise have existed.
  if (v.decision === 'allow') {
    const quiet = wouldAutoRun(input, tool, ti, v.level);
    if (quiet) return finish(policy, v, { ...ctx, surfaced: false, quiet });
    // The safe-list runs before the wouldPrompt guess below, and that ordering
    // was wrong the other way round. `wouldPrompt` is a *model* of when Claude
    // Code prompts, and the model is not reliable: it says `ls -la` and
    // `cat package.json` run silently, and they do not — they prompt. So a
    // bare prompt appeared with no card on it, which is the product looking
    // absent at the exact moment someone is watching it.
    //
    // Answering here is safe in both directions. If a prompt was coming, this
    // removes it. If Claude Code was going to run the call anyway, `allow`
    // changes nothing — it was already going to run. What it cannot do is
    // enable something that was not going to happen, because `wouldAutoRun`
    // above has already taken the genuinely-silent cases out.
    const safe = safelist.match(tool, ti, ext, v, policy);
    if (safe) return finish(policy, v, { ...ctx, approve: true, quiet: `safe-list:${safe.id}` });

    if (!wouldPrompt(tool, ti)) return finish(policy, v, { ...ctx, surfaced: false, quiet: 'green:no-prompt' });

    return finish(policy, v, { ...ctx, surfaced: true });
  }

  // Already answered once with "always allow". Nothing red or skill-related can
  // reach this — keyFor refuses to produce a key for those.
  const rememberKey = remember.keyFor(v, ext);
  if (remember.has(rememberKey)) {
    return finish(policy, v, { ...ctx, surfaced: false, quiet: `remembered:${rememberKey}` });
  }

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
  // Claude Code that curl is fine, Rockfort Legend does not second-guess it for
  // api.stripe.com. Strict mode flips this, because a managed fleet does want
  // the network policy to win over a developer's local convenience.
  //
  // An allowlist entry and a permission mode are not the same statement, and
  // v1.2.0 stopped treating them as one. `Bash(npm install *)` says "this
  // command is fine" — it is a claim about a command, and red is not covered by
  // it. `bypassPermissions` says "stop asking me": it is a claim about the
  // session, made deliberately, and honouring it is the whole reason someone
  // turns it on. Interrupting anyway is inventing a prompt, which is the one
  // thing this must not do.
  //
  // So in a fully quiet mode nothing asks. It is recorded instead, and the Stop
  // recap reports it afterwards. Hard denies are unaffected: a deny blocks, and
  // blocking is not the same as asking.
  const egressWins = policy.defaults.egressOverridesAllowlist === true;
  const quiet = wouldAutoRun(input, tool, ti, v.level);
  const mustSurface = !fullyQuiet(input)
    && (v.level === 'red' || (egressWins && v.rule.startsWith('egress.')));
  if (!mustSurface && quiet) return finish(policy, v, { ...ctx, surfaced: false, quiet });

  // We are about to put a real question in front of a human. Leave a marker so
  // PostToolUse can tell an approval apart from a tool that simply ran — an
  // auto-approved call reaches PostToolUse identically, and treating that as
  // consent silently disabled the guardrails.
  if (remember.autoLearnable(v)) {
    remember.notePending(rememberKey, input.session_id);
  }

  return finish(policy, v, { ...ctx, surfaced: true });
}

// --- the active skill check --------------------------------------------------

function invokedSkill(policy, input, ti, ctx) {
  const ref = String(ti.skill || ti.name || '');
  let res;
  try {
    res = skills.checkInvocation(input.cwd, ref, policy);
  } catch {
    // A broken check must not become a silent pass that looks like a clean one.
    res = { status: 'not-inspectable', rows: [] };
  }
  session.noteSkill(input.session_id, ref, res);

  const risks = skills.invocationRisks(res);
  const id = res.id || ref;

  if (!risks.length) {
    // Nothing to say. `quiet` records *why* there was nothing to say, which is
    // the difference between "inspected and clean" and "could not look" — the
    // second must never be reported as the first.
    return finish(policy, {
      decision: 'allow', level: 'green', rule: `skill.${res.status}`, destinations: [],
    }, { ...ctx, surfaced: false, quiet: `skill:${res.status}`, skill: id });
  }

  const r = risks[0];
  const decision = policy.defaults.skillDrift === 'deny' ? 'deny' : 'ask';
  const name = r.name;
  const live = skills.liveSignals(r);

  const v = r.status === 'changed'
    ? {
      decision, level: 'red', rule: 'skill.changed', destinations: [],
      msg: `The skill "${name}" has changed since you approved it — its files no longer match the version you pinned (${r.previousHash} → ${r.hash}).`,
      action: `Review it, then accept with: rlegend skills pin ${r.id}`,
    }
    : {
      decision, level: 'red', rule: live[0].code, destinations: [],
      msg: `The skill "${name}" is about to load. ${live[0].msg}`,
      action: `Review it, then accept with: rlegend skills pin ${r.id} --accept-risk`,
    };

  // Same rule as everywhere else: a deny blocks in any mode, an ask defers to
  // the recap when the user has said not to ask.
  if (v.decision === 'ask' && fullyQuiet(input)) {
    return finish(policy, v, {
      ...ctx, surfaced: false, quiet: `mode:${ctx.mode}`, skill: r.id,
    });
  }
  return finish(policy, v, { ...ctx, surfaced: true, skill: r.id });
}

// --- one exit, one audit row ------------------------------------------------
//
// Every return path in run() comes through here, for two reasons. First, the
// log has to record whether the user actually saw anything: without that there
// is no way to tell them afterwards what ran unattended under acceptEdits or
// bypassPermissions, which is the whole point of the recap. Second, two
// separate record() call sites had already drifted — the skill-guard branch
// wrote a row with a different shape from the main one.
//
// The row is written *before* surface(), which can block for up to 12s waiting
// on an editor click. A hook that gets killed mid-wait still leaves a trace.
// `decision` therefore keeps its v1.1.0 meaning — what the engine judged, not
// what the editor may later flip it to. Editor answers are already recorded in
// events.jsonl by the bridge.

async function finish(policy, v, ctx) {
  audit.record(policy, {
    harness: 'claude-code',
    tool: ctx.tool,
    decision: v.decision,
    level: v.level,
    rule: v.rule,
    surfaced: !!ctx.surfaced,
    quiet: ctx.quiet || '',
    mode: ctx.mode || '',
    hosts: (v.destinations || []).map((d) => d.host).filter(Boolean),
    ...(ctx.skill ? { skill: ctx.skill } : {}),
    cwd: ctx.input.cwd || '',
    session: ctx.input.session_id || '',
  });
  // The safe-list answer. No bridge event: no card was shown, so the editor
  // panel must not claim one was.
  if (ctx.approve) return out('allow', card(v));
  if (!ctx.surfaced) return null;
  return surface(v, ctx.input, ctx.tool, ctx.ti, ctx.ext);
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
      return out('allow', `Approved in your editor, and Rockfort Legend will stop asking about ${remember.describe(rememberKey)}.`);
    }
    if (d && (d.decision === 'allow' || d.decision === 'always')) {
      return out('allow', `Approved in your editor. ${card(v)}`);
    }
    // No answer in time: fall through to a normal prompt.
  }

  // If we are showing a card at all, the user decides — never us. A green
  // verdict returned as `allow` would auto-approve the call and remove the
  // prompt it was meant to annotate, which is the opposite of the job and
  // breaks the promise that Rockfort Legend cannot approve anything on your behalf.
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
//
// Returns the *reason* it would have run silently, or '' if a prompt was
// coming. Callers still read it as a boolean, but the reason is what lets the
// log say "this was silenced by bypassPermissions" rather than just omitting
// the row. v1.0.0 recorded this; v1.1.0 dropped it and the recap became
// impossible to build.

// "Stop asking me for the rest of this session." Deliberately narrower than
// wouldAutoRun: acceptEdits is not in here, because it says only that edits are
// fine — closer to an allowlist entry than to a blanket instruction — and an
// edit to Claude's own config should still raise a card.
function fullyQuiet(input) {
  return QUIET_MODES.has(input.permission_mode || input.permissionMode || '');
}

function wouldAutoRun(input, tool, ti, level) {
  const mode = input.permission_mode || input.permissionMode || '';
  if (QUIET_MODES.has(mode)) return `mode:${mode}`;

  // acceptEdits auto-accepts the edit family — but only green edits are
  // uninteresting. v1.0.0 gated this arm on green; v1.1.0 dropped the gate,
  // which silently swallowed `local.edit-agent-config`: Claude rewriting its
  // own settings.json or hooks.json, in the one mode where nobody is watching.
  // Red already breaks through via mustSurface; this restores orange.
  if (mode === 'acceptEdits' && /^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool)) {
    if (level === 'green') return 'mode:acceptEdits';
  }

  const target = tool === 'Bash' ? String(ti.command || '') : String(ti.file_path || ti.url || '');
  const hit = allowRules(input.cwd).find((rule) => ruleMatches(rule, tool, target));
  return hit ? `allow-rule:${hit}` : '';
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
  // A bare wildcard on the tool name itself: `mcp__linear__*`, or `Bash*`. The
  // pattern below only allowed a wildcard *inside* parentheses, so every MCP
  // entry people actually write was silently inert — it matched nothing, gave
  // no error, and looked like it was working. Checked first because `*` is not
  // a word character and would fail the pattern outright.
  if (rule.endsWith('*') && !rule.includes('(')) {
    return tool.startsWith(rule.slice(0, -1));
  }
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
// The enforcement half, for every tool that is not `Skill`: running something
// out of a flagged skill's directory. Reads the small state file SessionStart
// wrote, so the per-call cost is one tiny JSON read rather than re-hashing
// every installed skill.
//
// Invocation itself is handled by invokedSkill() above, which can afford a live
// check because it happens once per skill rather than once per tool call.

function skillGuard(tool, ti) {
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
// so a second banner from Rockfort Legend was pure duplication — two alerts for one
// decision, on a dialog the user is already looking at. The card inside the
// prompt is the signal; a banner on top of it is noise, and noise is what makes
// people stop reading the cards.
//
// It was also the only platform-specific behaviour in the runtime, so removing
// it makes macOS, Linux and Windows behave identically.
