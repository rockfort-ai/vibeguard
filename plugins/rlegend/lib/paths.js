'use strict';

// Where Rockfort Legend keeps its state, and the one-time move from the old
// name.
//
// The product was called VibeGuard until v1.2.0. Renaming the directory is the
// easy half; the hard half is that the directory holds things a user earned
// rather than things the tool generated. skills.lock.json is the record of
// which skill contents they reviewed and approved — throw it away and every
// skill reports as new, the drift baseline resets to whenever they upgraded,
// and the one signal install-time scanning cannot produce is silently gone.
// remembered.json is every "always allow" they clicked.
//
// So state migrates, once, on first use. The old directory is copied and never
// deleted: if this goes wrong the user still has everything, and a rename is
// not a good enough reason to be the tool that lost your approvals.

const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR_NAME = '.rlegend';
const LEGACY_DIR_NAME = '.vibeguard';

// Only user-earned state. Deliberately not events.jsonl or decisions/ — those
// are the editor bridge's transient chatter — and not engine/, which is a
// deployed copy that gets rewritten by the next build anyway.
const MIGRATE = [
  'skills.lock.json',
  'skills.state.json',
  'remembered.json',
  'policy.json',
];

let migrated = false;

function stateDir() {
  const dir = path.join(os.homedir(), DIR_NAME);
  if (!migrated) {
    migrated = true;
    try { migrate(dir); } catch { /* never worth breaking a hook over */ }
  }
  return dir;
}

function migrate(dir) {
  if (fs.existsSync(dir)) return; // already ours, or already migrated
  const legacy = path.join(os.homedir(), LEGACY_DIR_NAME);
  if (!fs.existsSync(legacy)) return;

  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const name of MIGRATE) {
    const from = path.join(legacy, name);
    const to = path.join(dir, name);
    try {
      if (fs.existsSync(from) && !fs.existsSync(to)) fs.copyFileSync(from, to);
    } catch {
      /* one unreadable file must not abort the rest */
    }
  }
  // The egress log lives under ~/.claude rather than here, because that is what
  // the shipped policy points telemetry at. It is what `rlegend learn` and
  // `rlegend session` read, so a rename that abandons it silently resets the
  // observed-traffic history those two are built on.
  try {
    const from = path.join(os.homedir(), '.claude', 'vibeguard', 'egress.jsonl');
    const to = path.join(os.homedir(), '.claude', 'rlegend', 'egress.jsonl');
    if (fs.existsSync(from) && !fs.existsSync(to)) {
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.copyFileSync(from, to);
    }
  } catch {
    /* history is nice to keep, never worth failing over */
  }

  // A breadcrumb, so "where did my pins come from" has an answer later.
  try {
    fs.writeFileSync(path.join(dir, 'MIGRATED-FROM-VIBEGUARD.txt'),
      `State copied from ${legacy} on ${new Date().toISOString()}.\n`
      + 'The old directory was left in place and can be deleted once you are happy.\n');
  } catch {
    /* cosmetic */
  }
}

function statePath(...parts) {
  return path.join(stateDir(), ...parts);
}

// The per-project policy layer, which travels with a checkout. Both spellings
// are read so a repo that committed the old one keeps working; the new name
// wins when both exist.
const PROJECT_DIR_NAME = '.rlegend';
const LEGACY_PROJECT_DIR_NAME = '.vibeguard';

function projectPolicyPaths(cwd) {
  if (!cwd) return [];
  return [
    path.join(cwd, LEGACY_PROJECT_DIR_NAME, 'policy.json'),
    path.join(cwd, PROJECT_DIR_NAME, 'policy.json'),
  ];
}

module.exports = {
  stateDir, statePath, projectPolicyPaths,
  DIR_NAME, LEGACY_DIR_NAME, PROJECT_DIR_NAME,
};
