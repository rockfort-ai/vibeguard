'use strict';

// Policy loading, layering and destination matching.
//
// Layers, lowest precedence first:
//   1. the bundled default policy
//   2. ~/.vibeguard/policy.json          (user)
//   3. <cwd>/.vibeguard/policy.json      (project — travels with the repo,
//                                         which is how cloud agents get it)
//   4. VIBEGUARD_POLICY env var pointing at a file (CI / managed push)
//
// A `deny` entry always wins over `ask`, which always wins over `allow`,
// regardless of which layer contributed it. Layers can add to a list, and can
// remove from one via a leading "!" (e.g. "!class:crypto").

const fs = require('fs');
const path = require('path');
const os = require('os');

const BUNDLED = path.join(__dirname, '..', 'policy', 'policy.json');

function layerPaths(cwd) {
  const out = [BUNDLED, path.join(os.homedir(), '.vibeguard', 'policy.json')];
  if (cwd) out.push(path.join(cwd, '.vibeguard', 'policy.json'));
  if (process.env.VIBEGUARD_POLICY) out.push(process.env.VIBEGUARD_POLICY);
  return out;
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function load(cwd) {
  let policy = null;
  const sources = [];
  for (const file of layerPaths(cwd)) {
    const layer = readJson(file);
    if (!layer) continue;
    policy = policy ? merge(policy, layer) : layer;
    sources.push(file);
  }
  if (!policy) throw new Error('vibeguard: no readable policy');
  policy._sources = sources;
  return policy;
}

function merge(base, layer) {
  const out = { ...base, ...layer };
  out.defaults = { ...base.defaults, ...(layer.defaults || {}) };
  out.classes = { ...base.classes, ...(layer.classes || {}) };
  out.secretIndicators = mergeSecrets(base.secretIndicators, layer.secretIndicators);
  for (const list of ['allow', 'ask', 'deny']) {
    out[list] = mergeList(base[list] || [], layer[list] || []);
  }
  return out;
}

function mergeSecrets(base = {}, layer = {}) {
  const out = {};
  for (const k of new Set([...Object.keys(base), ...Object.keys(layer)])) {
    out[k] = mergeList(base[k] || [], layer[k] || []);
  }
  return out;
}

function mergeList(base, layer) {
  const set = new Set(base);
  for (const entry of layer) {
    if (typeof entry !== 'string') continue;
    if (entry.startsWith('!')) set.delete(entry.slice(1));
    else set.add(entry);
  }
  return [...set];
}

// --- expansion -------------------------------------------------------------

function expand(policy, list) {
  const out = [];
  for (const entry of policy[list] || []) {
    if (entry.startsWith('class:')) {
      const members = policy.classes[entry.slice(6)];
      if (Array.isArray(members)) out.push(...members.map((m) => ({ pattern: m, via: entry })));
    } else {
      out.push({ pattern: entry, via: entry });
    }
  }
  return out;
}

// --- matching --------------------------------------------------------------

// A pattern matches a destination if it matches the host, or — when the
// pattern carries a path (discord.com/api/webhooks) — the host plus path.
function patternMatches(pattern, dest) {
  const [patHost, ...patPathParts] = pattern.split('/');
  const patPath = patPathParts.join('/');

  if (!hostMatches(patHost, dest.host)) return false;
  if (!patPath) return true;
  return String(dest.path || '').replace(/^\//, '').startsWith(patPath);
}

function hostMatches(pattern, host) {
  if (!host) return false;
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p === '*') return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(2);
    return h === suffix || h.endsWith('.' + suffix);
  }
  return h === p;
}

// Returns { decision, pattern, via } or null when nothing matched.
function classify(policy, dest) {
  for (const list of ['deny', 'ask', 'allow']) {
    for (const { pattern, via } of expand(policy, list)) {
      if (patternMatches(pattern, dest)) return { decision: list, pattern, via };
    }
  }
  return null;
}

// Flat, deduped domain list for a decision list — what vendor consoles and
// proxy configs actually want.
function domainsFor(policy, list) {
  return [...new Set(expand(policy, list).map((e) => e.pattern.split('/')[0]))].sort();
}

module.exports = { load, merge, expand, classify, hostMatches, patternMatches, domainsFor, BUNDLED };
