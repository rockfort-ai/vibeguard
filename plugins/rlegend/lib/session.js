'use strict';

// Per-session notes, so a recap can say what happened without re-deriving it.
//
// Right now this holds skill invocations. The recap wants to put them next to
// the tool calls that followed, and that is where a security tool can very
// easily start lying: Rockfort Legend sees a Skill call, and it sees Bash calls after
// it, and it has no way whatsoever to know whether the skill asked for them.
// Once a skill's instructions are in context they are indistinguishable from
// the user's own. So the caveat below is a constant rather than a sentence
// somebody retypes, and every surface that shows a marker appends it.

const fs = require('fs');
const path = require('path');
const os = require('os');

const { statePath } = require('./paths');
const DIR = statePath('session');

// Never edit this into something more confident.
const ATTRIBUTION_CAVEAT =
  'Rockfort Legend cannot tell which of these a skill asked for — it sees tool calls, ' +
  'not their origin. This is a time window, not a causal link.';

const MAX_SKILLS = 20;
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

function fileFor(sessionId) {
  // Session ids come from the harness; never let one escape the directory.
  const safe = String(sessionId || 'unknown').replace(/[^\w.-]/g, '_').slice(0, 120);
  return path.join(DIR, `${safe}.json`);
}

function read(sessionId) {
  try {
    const j = JSON.parse(fs.readFileSync(fileFor(sessionId), 'utf8'));
    if (j && Array.isArray(j.skills)) return j;
  } catch {
    /* no notes yet is the normal case */
  }
  return { ts: new Date().toISOString(), lastRecapTs: '', skills: [] };
}

function write(sessionId, state) {
  try {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(fileFor(sessionId), JSON.stringify(state), { mode: 0o600 });
    sweep();
    return true;
  } catch {
    return false; // a note is never worth breaking a tool call over
  }
}

// Record that a skill was invoked. `res` is a skills.checkInvocation result, so
// the marker carries what was actually known at the time — including that the
// skill could not be inspected, which must never later read as "checked".
function noteSkill(sessionId, ref, res) {
  const state = read(sessionId);
  const row = (res && res.rows && res.rows[0]) || null;
  state.skills.push({
    ref: String(ref || ''),
    id: (res && res.id) || (row && row.id) || '',
    at: new Date().toISOString(),
    inspected: !!row,
    why: (res && res.status) || 'unknown',
    hash: row ? row.hash : '',
    status: row ? row.status : '',
    signals: row ? row.signals.map((s) => s.code) : [],
  });
  if (state.skills.length > MAX_SKILLS) state.skills = state.skills.slice(-MAX_SKILLS);
  return write(sessionId, state);
}

function markRecapped(sessionId, ts) {
  const state = read(sessionId);
  state.lastRecapTs = ts || new Date().toISOString();
  return write(sessionId, state);
}

// Sessions end without telling us, so notes are pruned by age on write rather
// than cleaned up by anything.
function sweep() {
  try {
    const now = Date.now();
    for (const f of fs.readdirSync(DIR)) {
      const full = path.join(DIR, f);
      try {
        if (now - fs.statSync(full).mtimeMs > MAX_AGE_MS) fs.unlinkSync(full);
      } catch {
        /* another process got there first */
      }
    }
  } catch {
    /* nothing to sweep */
  }
}

// --- what is worth interrupting a finished turn for --------------------------
//
// A Stop hook fires at the end of every turn, so the bar has to be high enough
// that an ordinary turn produces nothing at all. The question it answers is
// narrow: did something elevated run *without the user being asked*.
//
// Deliberately not triggers: anything surfaced (they saw the card and decided),
// green rows, safe-list answers, and orange local rules quiet under an
// allowlist entry the user wrote themselves. Under a normal permission mode
// this set is empty and the hook says nothing. Under bypassPermissions it is
// exactly the list of things that got no say.
function elevatedUnseen(rows) {
  return rows.filter((r) => {
    if (r.surfaced !== false) return false;
    if (String(r.quiet || '').startsWith('safe-list:')) return false;
    if (r.level === 'red') return true;
    if (String(r.rule || '').startsWith('egress.') && r.decision !== 'allow') return true;
    if (String(r.rule || '').startsWith('skill.') && r.level === 'red') return true;
    return false;
  });
}

// One line per row, short enough to read at a glance.
function describeRow(r) {
  const what = r.rule === 'skill.changed' || r.rule === 'skill.unpinned'
    ? `the skill ${r.skill || '(unknown)'}`
    : (r.hosts && r.hosts.length ? `${r.tool} → ${r.hosts.join(', ')}` : r.tool);
  return `${what} — ${r.rule}`;
}

module.exports = {
  read, write, noteSkill, markRecapped, elevatedUnseen, describeRow,
  ATTRIBUTION_CAVEAT, DIR,
};
