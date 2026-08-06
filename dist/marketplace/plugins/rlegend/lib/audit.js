'use strict';

// Append-only decision log. Three jobs:
//   1. an audit trail of every network destination an agent reached for
//   2. the input to `rlegend learn`, which turns real traffic into allowlist
//      entries instead of you guessing domains up front
//   3. the record of what ran *without the user seeing anything*, which is the
//      only way to tell them afterwards what happened in an auto-accept mode
//
// Row shape written by adapters/claude-code.js:
//
//   ts        ISO timestamp
//   harness   'claude-code' | 'cursor'
//   tool      tool name as the harness spelled it
//   decision  what the engine judged: allow | ask | deny
//   level     green | orange | red
//   rule      dotted rule id, e.g. egress.pipe-to-shell
//   surfaced  true if a card was put in front of the user
//   quiet     why nothing was shown: mode:bypassPermissions, mode:acceptEdits,
//             allow-rule:Bash(git *), remembered:host:api.stripe.com,
//             green:no-prompt. Empty when surfaced.
//   mode      the harness permission mode, verbatim
//   hosts     destination hostnames, if any
//   skill     set only when the skill guard fired
//   cwd, session
//
// `surfaced`, `level`, `quiet` and `mode` are additive — older rows lack them,
// so readers must treat a missing field as unknown rather than false.
//
// Writes are best effort and must never break the agent.

const fs = require('fs');
const path = require('path');
const os = require('os');
const { statePath } = require('./paths');

function resolvePath(p) {
  if (!p) return null;
  return p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : p;
}

function record(policy, entry) {
  try {
    const tel = policy.telemetry || {};
    if (entry.decision === 'allow' && tel.logAllowed === false) return;
    const file = resolvePath(tel.logPath) || statePath('egress.jsonl');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
  } catch {
    /* logging is never worth a crash */
  }
}

function read(policy) {
  const file = resolvePath((policy.telemetry || {}).logPath) ||
    statePath('egress.jsonl');
  try {
    return fs.readFileSync(file, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch {
    return [];
  }
}

// One session's rows, newest last. `read` slurps the whole log, which grows
// forever and is already hundreds of KB on a machine that has been running this
// a week — fine for `rlegend learn` once, wrong for a hook that fires at the end of
// every turn. So tail the last chunk and drop the partial line at the front.
const TAIL_BYTES = 256 * 1024;

function readSession(policy, sessionId, sinceTs) {
  const file = resolvePath((policy.telemetry || {}).logPath) ||
    statePath('egress.jsonl');
  let text = '';
  try {
    const fd = fs.openSync(file, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      const start = Math.max(0, size - TAIL_BYTES);
      const buf = Buffer.alloc(Math.min(size, TAIL_BYTES));
      fs.readSync(fd, buf, 0, buf.length, start);
      text = buf.toString('utf8');
      if (start > 0) text = text.slice(text.indexOf('\n') + 1);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return [];
  }
  const out = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    if (sessionId && row.session !== sessionId) continue;
    if (sinceTs && !(row.ts > sinceTs)) continue;
    out.push(row);
  }
  return out;
}

module.exports = { record, read, readSession, resolvePath };
