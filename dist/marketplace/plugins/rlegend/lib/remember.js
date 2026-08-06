'use strict';

// "Always allow" — remembered answers, so the same card does not appear twice.
//
// The interruption budget of a security tool is small and non-renewable. Every
// prompt that turns out to be fine spends some of it, and once it is gone
// people stop reading the prompts rather than stop using the tool. So an answer
// the user has already given should stick.
//
// Two things are deliberately NOT rememberable, because remembering them would
// quietly convert this from a guardrail into a decoration:
//
//   • anything red — `sudo`, force-push, disk writes. "Always allow admin
//     access to my Mac" is not a preference, it is an uninstall with extra
//     steps.
//   • skill drift — the entire value is noticing that something changed since
//     you approved it. A standing approval defeats the feature by definition.
//
// Everything green and orange is fair game.

const fs = require('fs');
const path = require('path');
const os = require('os');

const { statePath } = require('./paths');
const FILE = statePath('remembered.json');

// What the answer is remembered *about*. Deliberately coarser than the exact
// command — remembering `npm install lodash` would not silence
// `npm install react`, so the prompt would come straight back and the button
// would feel broken.
// Rules that may only ever be silenced by an explicit click, never inferred
// from behaviour. Destructive, irreversible, or security-relevant: one yes to
// `rm` must not mean yes to every future delete, and "publishes your code" is
// not something to infer from a single push.
//
// Auto-learning is therefore for the genuinely noisy and low-stakes — package
// installs, stopping a process. Everything here still gets the Always-allow
// button in the editor, where the user is looking at the specific command.
const NEVER_AUTO_LEARN = new Set([
  'local.rm', 'local.git-push', 'local.git-discard', 'local.docker-rm',
  'local.perms', 'local.persistence', 'local.read-secrets',
  'local.edit-shell-profile', 'local.edit-agent-config',
  // Both are about a boundary Rockfort Legend cannot see past. One approval of one
  // call is not standing consent to keep handing an opaque server credentials,
  // and "I used this server once" is not "stop telling me about new servers".
  'mcp.secret-argument', 'mcp.new-server',
]);

function autoLearnable(verdict) {
  if (!verdict || !verdict.rule) return false;
  if (NEVER_AUTO_LEARN.has(verdict.rule)) return false;
  // Network answers are per-destination and sensitive by construction —
  // payments, cloud control planes. Those get an explicit click too.
  if (verdict.rule.startsWith('egress.')) return false;
  return true;
}

function keyFor(verdict, ext) {
  if (!verdict || verdict.level === 'red') return null;
  if (verdict.rule.startsWith('skill.')) return null;
  // "Always allow" on this would mean "stop telling me about new MCP servers",
  // which is the opposite of what someone clicking it wants — they mean "yes,
  // this server". There is no key that expresses that, so there is no button.
  if (verdict.rule === 'mcp.new-server') return null;

  if (verdict.rule.startsWith('egress.')) {
    const dest = (ext && ext.destinations || []).find((d) => d.host);
    return dest ? `host:${dest.host.toLowerCase()}` : null;
  }
  return `rule:${verdict.rule}`;
}

// Plain English for the button and the confirmation, so "always allow" never
// means something broader than the user pictured.
function describe(key) {
  if (!key) return '';
  if (key.startsWith('host:')) return `anything talking to ${key.slice(5)}`;
  const rule = key.slice(5);
  const LABELS = {
    'local.install': 'installing packages',
    'local.rm': 'deleting files',
    'local.git-push': 'pushing code',
    'local.git-discard': 'discarding uncommitted edits',
    'local.kill': 'stopping running programs',
    'local.perms': 'changing file permissions',
    'local.persistence': 'changing settings on this Mac',
    'local.docker-rm': 'removing Docker containers',
    'local.read-secrets': 'reading your credentials files',
    'local.edit-shell-profile': 'editing your shell profile',
  };
  return LABELS[rule] || rule.replace(/^local\./, '').replace(/-/g, ' ');
}

function load() {
  try {
    const j = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    return j && typeof j.allow === 'object' ? j : { version: 1, allow: {} };
  } catch {
    return { version: 1, allow: {} };
  }
}

function has(key) {
  return !!(key && load().allow[key]);
}

function add(key, meta = {}) {
  if (!key) return false;
  try {
    const store = load();
    store.allow[key] = { at: new Date().toISOString(), what: describe(key), ...meta };
    fs.mkdirSync(path.dirname(FILE), { recursive: true });
    fs.writeFileSync(FILE, JSON.stringify(store, null, 2) + '\n');
    return true;
  } catch {
    return false; // never break a tool call over a preference
  }
}

function forget(key) {
  const store = load();
  if (key) delete store.allow[key];
  else store.allow = {};
  try {
    fs.mkdirSync(path.dirname(FILE), { recursive: true });
    fs.writeFileSync(FILE, JSON.stringify(store, null, 2) + '\n');
    return true;
  } catch {
    return false;
  }
}

function list() {
  const store = load();
  return Object.entries(store.allow).map(([key, v]) => ({ key, ...v }));
}

// --- proof that a human was actually asked -----------------------------------
//
// PostToolUse fires whenever a tool succeeds — including tools that ran with no
// prompt at all, under acceptEdits, an allowlist entry, or bypassPermissions.
// Treating "it ran" as "they approved it" was wrong, and it silenced real
// guardrails: a background cleanup script running `rm -rf /tmp/x` taught
// Rockfort Legend that deleting files is always fine, without a human ever seeing a
// card.
//
// So PreToolUse leaves a marker only when it actually surfaced a question, and
// PostToolUse will only learn if it finds one. Auto-run leaves no marker and
// therefore teaches nothing.

const PENDING = statePath('pending.json');
const PENDING_TTL_MS = 10 * 60 * 1000;

function notePending(key, session) {
  if (!key) return false;
  try {
    const now = Date.now();
    let store = {};
    try { store = JSON.parse(fs.readFileSync(PENDING, 'utf8')) || {}; } catch { /* first */ }
    for (const [k, ts] of Object.entries(store)) {
      if (now - ts > PENDING_TTL_MS) delete store[k];
    }
    store[`${session || ''}|${key}`] = now;
    fs.mkdirSync(path.dirname(PENDING), { recursive: true });
    fs.writeFileSync(PENDING, JSON.stringify(store));
    return true;
  } catch {
    return false;
  }
}

// Consumes the marker: a single question authorises a single lesson.
function takePending(key, session) {
  if (!key) return false;
  try {
    const store = JSON.parse(fs.readFileSync(PENDING, 'utf8')) || {};
    const id = `${session || ''}|${key}`;
    const ts = store[id];
    if (!ts || Date.now() - ts > PENDING_TTL_MS) return false;
    delete store[id];
    fs.writeFileSync(PENDING, JSON.stringify(store));
    return true;
  } catch {
    return false;
  }
}

// --- MCP inventory -----------------------------------------------------------
//
// Rockfort Legend cannot see inside an MCP call — it gets a tool name and an opaque
// argument object, with no way to tell a screenshot from a file upload. So it
// does not judge them, and it does not pretend to: it records which servers and
// tools are actually being used, so "which MCPs am I running?" has an answer
// grounded in observation rather than in a config file nobody has read.

function serverOf(tool) {
  const m = /^mcp__([^_]+(?:_[^_]+)*?)__(.+)$/.exec(String(tool || ''));
  return m ? m[1] : '';
}

// Has this server ever been used on this machine? Read-only, so PreToolUse can
// ask before it records. A server appearing for the first time is the one thing
// about MCP that Rockfort Legend can honestly tell you: it cannot see inside the
// call, but it knows whether it has ever seen this one before.
function seenMcp(server) {
  if (!server) return true; // unparseable is not news
  const store = load();
  return !!(store.mcp && store.mcp[server]);
}

// `count: false` registers a server without crediting it a successful call.
// PreToolUse uses it, so a server whose very first call is denied still shows
// up in `rlegend mcp` — inventorying only what succeeded means the calls you blocked
// leave no trace. PostToolUse still counts, so the "calls" column keeps meaning
// "actually ran".
function noteMcp(tool, cwd, { count = true } = {}) {
  const m = /^mcp__([^_]+(?:_[^_]+)*?)__(.+)$/.exec(tool);
  if (!m) return false;
  const [, server, name] = m;
  try {
    const store = load();
    store.mcp = store.mcp || {};
    const s = store.mcp[server] || { firstSeen: new Date().toISOString(), tools: {}, projects: [] };
    if (count) s.tools[name] = (s.tools[name] || 0) + 1;
    else if (!(name in s.tools)) s.tools[name] = 0;
    s.lastSeen = new Date().toISOString();
    if (cwd && !s.projects.includes(cwd) && s.projects.length < 20) s.projects.push(cwd);
    store.mcp[server] = s;
    fs.mkdirSync(path.dirname(FILE), { recursive: true });
    fs.writeFileSync(FILE, JSON.stringify(store, null, 2) + '\n');
    return true;
  } catch {
    return false;
  }
}

function mcpServers() {
  const store = load();
  return Object.entries(store.mcp || {}).map(([server, v]) => ({
    server,
    calls: Object.values(v.tools || {}).reduce((a, b) => a + b, 0),
    tools: Object.entries(v.tools || {}).sort((a, b) => b[1] - a[1]),
    firstSeen: v.firstSeen,
    lastSeen: v.lastSeen,
    projects: v.projects || [],
  })).sort((a, b) => b.calls - a.calls);
}

module.exports = {
  keyFor, describe, has, add, forget, list, load, FILE,
  autoLearnable, notePending, takePending, NEVER_AUTO_LEARN,
  noteMcp, mcpServers, seenMcp, serverOf,
};
