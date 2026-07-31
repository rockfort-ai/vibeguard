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

const FILE = path.join(os.homedir(), '.vibeguard', 'remembered.json');

// What the answer is remembered *about*. Deliberately coarser than the exact
// command — remembering `npm install lodash` would not silence
// `npm install react`, so the prompt would come straight back and the button
// would feel broken.
function keyFor(verdict, ext) {
  if (!verdict || verdict.level === 'red') return null;
  if (verdict.rule.startsWith('skill.')) return null;

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

module.exports = { keyFor, describe, has, add, forget, list, load, FILE };
