#!/usr/bin/env node
'use strict';

// Claude Code Stop adapter — say what ran while nobody was being asked.
//
// A PreToolUse hook can only speak at the moment of a call, and in an
// auto-accept mode that moment is exactly when it has been told to stay quiet.
// bypassPermissions silences everything but a hard deny; acceptEdits silences
// the edit family. The calls still happen. Until v1.2.0 nothing recorded that
// they had been silenced, so there was nothing to tell anyone afterwards.
//
// Output shape matters here and is easy to get wrong. Verified against the
// 2.1.220 binary's own schema text:
//
//   hookSpecificOutput.additionalContext  "the conversation continues so the
//                                          model can act on it"  → restarts the turn
//   decision: "block" + reason            → same, harder
//   systemMessage                         "Display a message to the user (all hooks)"
//
// Only the last one tells the user something without putting the agent back to
// work, so that is the one used. A recap that restarts the turn it is
// recapping would be its own bug.

const audit = require('../lib/audit');
const session = require('../lib/session');
const { load } = require('../lib/policy');

let raw = '';
process.stdin.on('data', (d) => (raw += d));
process.stdin.on('end', () => {
  let out = null;
  try {
    out = run(JSON.parse(raw));
  } catch {
    // Never break the agent because of a hook bug.
  }
  if (out) process.stdout.write(JSON.stringify(out));
  process.exit(0);
});

function run(input) {
  // Claude Code sets this when a Stop hook has already fired for this stop. A
  // recap must never be the reason a turn keeps going.
  if (input.stop_hook_active) return null;

  const sessionId = input.session_id || '';
  if (!sessionId) return null;

  const policy = load(input.cwd);
  const notes = session.read(sessionId);

  // Only rows newer than the last recap. Stop fires at the end of every turn,
  // and repeating the same three lines each time is how a warning becomes
  // wallpaper.
  const rows = audit.readSession(policy, sessionId, notes.lastRecapTs || '');
  const elevated = session.elevatedUnseen(rows);
  if (!elevated.length) return null;

  const newest = rows.reduce((max, r) => (r.ts > max ? r.ts : max), notes.lastRecapTs || '');
  session.markRecapped(sessionId, newest);

  const modes = [...new Set(elevated.map((r) => r.mode).filter(Boolean))];
  const L = [];
  L.push(`Rockfort Legend — ${elevated.length} elevated action${elevated.length === 1 ? '' : 's'} ran `
    + `without a prompt${modes.length ? ` (permission mode: ${modes.join(', ')})` : ''}:`);
  for (const r of elevated.slice(0, 8)) L.push(`  • ${session.describeRow(r)}`);
  if (elevated.length > 8) L.push(`  … and ${elevated.length - 8} more`);

  // Skills invoked in the same window. Correlation, and labelled as such —
  // Rockfort Legend sees tool calls, never their origin.
  const since = notes.lastRecapTs || '';
  const invoked = notes.skills.filter((s) => !since || s.at > since);
  if (invoked.length) {
    L.push(`Skills invoked in the same window: ${invoked.map((s) => s.ref).join(', ')}.`);
    L.push(session.ATTRIBUTION_CAVEAT);
  }

  L.push('Run /rlegend-session for the full list. Rockfort Legend did not approve these; it was not asked.');
  return { systemMessage: L.join('\n') };
}
