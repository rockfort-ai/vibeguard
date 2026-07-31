'use strict';

// Append-only decision log. Two jobs:
//   1. an audit trail of every network destination an agent reached for
//   2. the input to `vg learn`, which turns real traffic into allowlist
//      entries instead of you guessing domains up front
//
// Writes are best effort and must never break the agent.

const fs = require('fs');
const path = require('path');
const os = require('os');

function resolvePath(p) {
  if (!p) return null;
  return p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : p;
}

function record(policy, entry) {
  try {
    const tel = policy.telemetry || {};
    if (entry.decision === 'allow' && tel.logAllowed === false) return;
    const file = resolvePath(tel.logPath) || path.join(os.homedir(), '.vibeguard', 'egress.jsonl');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
  } catch {
    /* logging is never worth a crash */
  }
}

function read(policy) {
  const file = resolvePath((policy.telemetry || {}).logPath) ||
    path.join(os.homedir(), '.vibeguard', 'egress.jsonl');
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

module.exports = { record, read, resolvePath };
