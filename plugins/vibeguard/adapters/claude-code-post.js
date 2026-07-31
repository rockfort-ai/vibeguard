#!/usr/bin/env node
'use strict';

// Claude Code PostToolUse adapter — learn from what you approved.
//
// Why this exists: when a *hook* returns `ask`, Claude Code shows a reduced
// permission dialog — "Deny" and "Allow once", with no "Yes, and don't ask
// again". So every question VibeGuard raises is a question it will raise again
// tomorrow, and the user has no way to make it stop. That is a fast route to
// being uninstalled.
//
// PostToolUse only fires after a tool has actually run, which means the user
// said yes. That is the signal. Re-deriving the verdict from the same inputs
// tells us what they said yes *to*, and it gets remembered so the same card
// does not come back.
//
// A denial produces no PostToolUse event at all, so "no" is never learned as
// "yes" — the asymmetry is what makes this safe to do automatically.
//
// The same two exclusions as the editor's Always-allow button apply, because
// they are enforced in one place (remember.keyFor): nothing red, and never
// skill drift.

const { load } = require('../lib/policy');
const { extract } = require('../lib/extract');
const { decide } = require('../lib/decide');
const remember = require('../lib/remember');

const SILENT_TOOLS = new Set([
  'Read', 'Glob', 'Grep', 'TodoWrite', 'NotebookRead', 'ExitPlanMode', 'KillShell',
]);

let raw = '';
process.stdin.on('data', (d) => (raw += d));
process.stdin.on('end', () => {
  try {
    run(JSON.parse(raw));
  } catch {
    // A learning step must never break the tool that already succeeded.
  }
  process.exit(0);
});

function run(input) {
  const tool = input.tool_name || '';
  const ti = input.tool_input || {};
  if (!tool || SILENT_TOOLS.has(tool)) return;

  const policy = load(input.cwd);
  if (policy.defaults.learnFromApprovals === false) return;

  // MCP tools are inventoried rather than judged. VibeGuard cannot see inside
  // an MCP call, so it says so instead of pretending — and an unrecognised
  // tool is not evidence of anything. Recording which servers are actually in
  // use is the honest version of "allowlist my MCPs".
  if (tool.startsWith('mcp__')) {
    remember.noteMcp(tool, input.cwd || '');
    return;
  }

  const ext = extract(tool, ti, input.cwd);
  const v = decide(policy, { tool, text: tool === 'Bash' ? String(ti.command || '') : '' }, ext);

  // `allow` had nothing to learn; `deny` never reached here.
  if (v.decision !== 'ask') return;

  // Destructive and security-relevant rules are never inferred from behaviour,
  // only from an explicit click. One yes to `rm` is not yes to every delete.
  if (!remember.autoLearnable(v)) return;

  const key = remember.keyFor(v, ext);
  if (!key) return;

  // The decisive check. A tool reaching PostToolUse proves it ran, not that a
  // human agreed — acceptEdits, an allowlist entry, or bypassPermissions all
  // get here with nobody having seen a card. Only a marker left by PreToolUse
  // when it actually asked authorises a lesson, and it is consumed on use.
  if (!remember.takePending(key, input.session_id)) return;

  remember.add(key, { rule: v.rule, tool, learned: 'approved-once' });
}
