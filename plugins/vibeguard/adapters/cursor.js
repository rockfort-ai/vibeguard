#!/usr/bin/env node
'use strict';

// Cursor hooks adapter — beforeShellExecution, beforeMCPExecution,
// beforeReadFile.
//
// Install (.cursor/hooks.json, committed to the repo so cloud agents inherit it):
//   { "version": 1, "hooks": {
//       "beforeShellExecution": [{ "command": "node ./.vibeguard/adapters/cursor.js" }],
//       "beforeMCPExecution":   [{ "command": "node ./.vibeguard/adapters/cursor.js" }],
//       "beforeReadFile":       [{ "command": "node ./.vibeguard/adapters/cursor.js" }] } }
//
// Two Cursor-specific notes:
//   - `deny` is the verb that reliably wins. Cursor's own command allow-list
//     has been observed to take precedence over a hook returning allow/ask, so
//     never rely on this adapter to *grant* anything.
//   - In an unattended run (cloud agent, background composer) nobody can answer
//     an "ask". Set VIBEGUARD_STRICT=1 there and every ask becomes a deny.

const { load } = require('../lib/policy');
const { extract } = require('../lib/extract');
const { decide, card } = require('../lib/decide');
const audit = require('../lib/audit');

const STRICT = process.env.VIBEGUARD_STRICT === '1';

let raw = '';
process.stdin.on('data', (d) => (raw += d));
process.stdin.on('end', () => {
  let out = { permission: 'allow' };
  try {
    out = run(JSON.parse(raw)) || { permission: 'allow' };
  } catch {
    // Fail open on a hook bug; fail closed only on an explicit policy hit.
  }
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
});

function run(input) {
  const event = input.hook_event_name || input.event || 'beforeShellExecution';
  const cwd = input.workspace_roots ? input.workspace_roots[0] : input.cwd || process.cwd();

  const { tool, toolInput, text } = normalise(event, input);
  if (!tool) return { permission: 'allow' };

  const policy = load(cwd);
  const ext = extract(tool, toolInput, cwd);
  const v = decide(policy, { tool, text }, ext);

  audit.record(policy, {
    harness: 'cursor',
    event,
    tool,
    decision: v.decision,
    rule: v.rule,
    hosts: v.destinations.map((d) => d.host).filter(Boolean),
    cwd,
    session: input.conversation_id || '',
  });

  if (v.decision === 'allow') return { permission: 'allow' };

  const permission = v.decision === 'deny' || STRICT ? 'deny' : 'ask';
  return {
    permission,
    userMessage: card(v),
    agentMessage: permission === 'deny'
      ? `Blocked by VibeGuard policy [${v.rule}]: ${v.msg} Do not retry this, and do not attempt an equivalent command. Tell the user what you were trying to reach and why.`
      : `VibeGuard flagged this for review [${v.rule}]: ${v.msg}`,
  };
}

function normalise(event, input) {
  if (event === 'beforeShellExecution') {
    const command = String(input.command || '');
    return { tool: 'Bash', toolInput: { command }, text: command };
  }
  if (event === 'beforeMCPExecution') {
    const name = input.tool_name || input.server_name || 'unknown';
    return { tool: `mcp__${name}`, toolInput: input.tool_input || input.input || {}, text: '' };
  }
  if (event === 'beforeReadFile') {
    // Reading a credentials file is not itself egress, but it is the first
    // half of one, and it is the half you can still stop.
    return { tool: 'Read', toolInput: { file_path: input.file_path || '' }, text: input.file_path || '' };
  }
  return { tool: null };
}
