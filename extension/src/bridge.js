'use strict';

// The editor half of the channel described in plugins/vibeguard/lib/bridge.js.
//
// Tails ~/.vibeguard/events.jsonl and writes decisions back. Kept free of any
// vscode imports so it can be exercised without an editor running.

const fs = require('fs');
const os = require('os');
const path = require('path');

const HOME = path.join(os.homedir(), '.vibeguard');
const EVENTS = path.join(HOME, 'events.jsonl');
const DECISIONS = path.join(HOME, 'decisions');
const HEARTBEAT = path.join(HOME, 'extension.alive');

const HEARTBEAT_INTERVAL_MS = 10000;
// fs.watch misses events on some filesystems and over network mounts, so a slow
// poll runs alongside it. Between the two, nothing is lost.
const POLL_INTERVAL_MS = 1500;
// An event from before we started listening is history, not a live prompt.
// Claude Code waits on the hook, so a real one is always fresh.
const LIVE_WINDOW_MS = 20000;

class Bridge {
  constructor(onEvent) {
    this.onEvent = onEvent;
    this.seen = new Set();
    this.timers = [];
    this.watcher = null;
    this.started = 0;
  }

  start() {
    this.started = Date.now();
    fs.mkdirSync(HOME, { recursive: true, mode: 0o700 });
    fs.mkdirSync(DECISIONS, { recursive: true, mode: 0o700 });

    // Everything already in the log predates this session: remember the ids so
    // it loads into history without firing a popup for each one.
    this.drain(true);

    this.beat();
    this.timers.push(setInterval(() => this.beat(), HEARTBEAT_INTERVAL_MS));
    this.timers.push(setInterval(() => this.drain(false), POLL_INTERVAL_MS));

    try {
      // Watching the directory rather than the file survives log rotation.
      this.watcher = fs.watch(HOME, (_e, name) => {
        if (!name || name === 'events.jsonl') this.drain(false);
      });
    } catch {
      // The poll is enough on its own.
    }
  }

  stop() {
    this.timers.forEach(clearInterval);
    this.timers = [];
    if (this.watcher) this.watcher.close();
    this.watcher = null;
    try {
      fs.unlinkSync(HEARTBEAT);
    } catch {
      // already gone
    }
  }

  // Tell the hook an editor is listening.
  beat() {
    try {
      fs.writeFileSync(HEARTBEAT, String(Date.now()), { mode: 0o600 });
    } catch {
      // if this fails the hook simply falls back to notify-only
    }
  }

  // Read the whole log and hand over anything not seen before. The log is
  // capped at 256KB by the hook, so re-reading it is cheaper than tracking a
  // byte offset that rotation would invalidate.
  drain(backfill) {
    let text;
    try {
      text = fs.readFileSync(EVENTS, 'utf8');
    } catch {
      return; // no log yet
    }
    for (const line of text.split('\n')) {
      if (!line) continue;
      let ev;
      try {
        ev = JSON.parse(line);
      } catch {
        continue; // torn write; the poll will pick it up next time round
      }
      if (!ev.id || this.seen.has(ev.id)) continue;
      this.seen.add(ev.id);
      const live = !backfill && Date.now() - ev.ts < LIVE_WINDOW_MS;
      this.onEvent(ev, live);
    }
    this.trimSeen();
  }

  trimSeen() {
    if (this.seen.size <= 1000) return;
    const keep = [...this.seen].slice(-500);
    this.seen = new Set(keep);
  }

  // Answer a prompt that is still waiting in Claude Code.
  decide(id, decision, reason) {
    try {
      fs.writeFileSync(
        path.join(DECISIONS, `${id}.json`),
        JSON.stringify({ decision, reason: reason || '' }),
        { mode: 0o600 }
      );
      return true;
    } catch {
      return false;
    }
  }

  // For the diagnostics command.
  info() {
    let lastWrite = null;
    try {
      lastWrite = fs.statSync(EVENTS).mtimeMs;
    } catch {
      // never written
    }
    return { home: HOME, events: EVENTS, lastWrite, seen: this.seen.size };
  }
}

module.exports = { Bridge, HOME, EVENTS, DECISIONS, HEARTBEAT };
