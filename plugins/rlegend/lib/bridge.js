'use strict';

// The channel between the hook and the editor extension.
//
// Deliberately dumb: an append-only JSONL file the extension tails, and a
// directory of small decision files it writes back. No ports to negotiate, no
// server to keep alive, nothing to clean up if the editor never starts.
//
// The hook must never hang because of anything in here. Every function either
// succeeds quickly or gives up silently.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { stateDir } = require('./paths');
const HOME = stateDir();
const EVENTS = path.join(HOME, 'events.jsonl');
const DECISIONS = path.join(HOME, 'decisions');
const HEARTBEAT = path.join(HOME, 'extension.alive');

// The extension rewrites its heartbeat every 10s. Anything older than this and
// we assume no editor is listening.
const HEARTBEAT_STALE_MS = 30000;

// Keep the log small enough to read in one gulp. The extension only needs
// recent history; anything older is noise.
const MAX_LOG_BYTES = 256 * 1024;

function ensureHome() {
  fs.mkdirSync(HOME, { recursive: true, mode: 0o700 });
  fs.mkdirSync(DECISIONS, { recursive: true, mode: 0o700 });
}

// Is an editor extension listening right now?
function extensionAlive() {
  try {
    return Date.now() - fs.statSync(HEARTBEAT).mtimeMs < HEARTBEAT_STALE_MS;
  } catch {
    return false;
  }
}

// Append one event. Returns its id, or null if the write failed.
function emit(event) {
  const id = crypto.randomUUID();
  const record = { v: 1, id, ts: Date.now(), ...event };
  try {
    ensureHome();
    rotateIfLarge();
    fs.appendFileSync(EVENTS, JSON.stringify(record) + '\n', { mode: 0o600 });
    return id;
  } catch {
    return null;
  }
}

// Events can carry command lines and file paths, so the log is 0600 in a 0700
// directory. Trim from the front rather than deleting, so a tailing extension
// does not lose its place any more often than it has to.
function rotateIfLarge() {
  try {
    if (fs.statSync(EVENTS).size <= MAX_LOG_BYTES) return;
    const lines = fs.readFileSync(EVENTS, 'utf8').split('\n').filter(Boolean);
    fs.writeFileSync(EVENTS, lines.slice(-200).join('\n') + '\n', { mode: 0o600 });
  } catch {
    // no log yet, or unreadable: nothing to rotate
  }
}

// Wait for the extension to write a decision for this event.
//
// Only ever called when a heartbeat is fresh, and always with a deadline well
// inside the hook's own timeout. On timeout we return null and the caller falls
// back to a plain "ask", which is exactly what would have happened anyway.
async function waitForDecision(id, timeoutMs) {
  const file = path.join(DECISIONS, `${id}.json`);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const d = JSON.parse(fs.readFileSync(file, 'utf8'));
      fs.unlinkSync(file);
      return d;
    } catch {
      // not answered yet
    }
    if (!extensionAlive()) return null; // editor quit mid-prompt
    await sleep(60);
  }
  return null;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

module.exports = {
  HOME,
  EVENTS,
  DECISIONS,
  HEARTBEAT,
  HEARTBEAT_STALE_MS,
  ensureHome,
  extensionAlive,
  emit,
  waitForDecision,
};
