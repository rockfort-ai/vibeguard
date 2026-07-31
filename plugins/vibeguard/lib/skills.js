'use strict';

// Skill inventory, content pinning and drift detection.
//
// Worth being blunt about the premise: install-time scanning of agent skills
// does not hold. Trail of Bits bypassed every major skill scanner — ClawHub via
// VirusTotal Code Insight, Cisco AI Defense, Vercel skills.sh, Socket, Snyk —
// in under an hour each, using whitespace inflation, precompiled .pyc payloads,
// archive indirection, and prompt injection aimed at the scanner's own LLM
// judge. Socket raised nothing above Medium under any tested condition. A
// verdict computed once, at install, over text the author controls, is not a
// security boundary.
//
// What holds is duller:
//   1. know exactly which skills are loadable in this session
//   2. pin their content hashes
//   3. shout when one changes underneath you
//
// (3) is the attack install-time scanning structurally cannot see: ship a clean
// skill, get approved, mutate at v1.4. Nothing rescans on update.
//
// The signals below are reported as *signals*, never as a safety verdict. We do
// not tell anyone a skill is safe. See COVERAGE.md.

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const { classify } = require('./policy');
const { secretReads } = require('./extract');
const { classifyBash } = require('./decide');

const LOCKFILE = path.join(os.homedir(), '.vibeguard', 'skills.lock.json');
const STATEFILE = path.join(os.homedir(), '.vibeguard', 'skills.state.json');

// SessionStart runs on every session and has to stay fast, so the walk is
// bounded. A skill that blows these limits is itself worth a signal.
const MAX_FILES = 400;
const MAX_BYTES = 2 * 1024 * 1024;

// --- discovery ---------------------------------------------------------------

// Only places a skill can actually be loaded from. Deliberately not
// ~/.claude/plugins/marketplaces — those are catalogue clones of plugins that
// are available, not installed, and reporting them is noise about code that
// never enters a context window.
function roots(cwd) {
  const out = [{ source: 'user', dir: path.join(os.homedir(), '.claude', 'skills') }];
  if (cwd) out.push({ source: 'project', dir: path.join(cwd, '.claude', 'skills') });
  for (const p of installedPlugins()) {
    out.push({ source: `plugin:${p.name}`, dir: path.join(p.installPath, 'skills') });
  }
  return out;
}

function installedPlugins() {
  const file = path.join(os.homedir(), '.claude', 'plugins', 'installed_plugins.json');
  let j;
  try {
    j = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
  const out = [];
  for (const [name, entries] of Object.entries(j.plugins || {})) {
    for (const e of Array.isArray(entries) ? entries : [entries]) {
      if (e && e.installPath) out.push({ name, installPath: e.installPath, version: e.version || '' });
    }
  }
  return out;
}

function discover(cwd) {
  const out = [];
  for (const { source, dir } of roots(cwd)) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // a root that does not exist is the normal case
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const skillDir = path.join(dir, e.name);
      if (!fs.existsSync(path.join(skillDir, 'SKILL.md'))) continue;
      out.push(inspect(source, e.name, skillDir));
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

function inspect(source, name, dir) {
  const files = walk(dir);
  const meta = frontmatter(readText(path.join(dir, 'SKILL.md')));
  return {
    id: `${source}:${name}`,
    name,
    source,
    dir,
    files,
    hash: hashSkill(files),
    description: meta.description || '',
  };
}

function walk(dir) {
  const out = [];
  const stack = [dir];
  let truncated = false;
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (out.length >= MAX_FILES) {
        truncated = true;
        break;
      }
      const full = path.join(d, e.name);
      const rel = path.relative(dir, full);
      // Never follow a symlink. Where it points is part of the hash, because
      // repointing it is a content change that leaves every real file intact.
      if (e.isSymbolicLink()) {
        out.push({ rel, path: full, symlink: readlink(full) });
        continue;
      }
      if (e.isDirectory()) {
        if (e.name !== '.git') stack.push(full);
        continue;
      }
      if (!e.isFile()) continue;
      let size = 0;
      try {
        size = fs.statSync(full).size;
      } catch {
        continue;
      }
      out.push({ rel, path: full, size });
    }
  }
  const sorted = out.sort((a, b) => a.rel.localeCompare(b.rel));
  if (truncated) sorted.truncated = true;
  return sorted;
}

// --- hashing -----------------------------------------------------------------

// Deterministic over (relative path, content) pairs, sorted. Renaming a file,
// repointing a symlink, or flipping one byte all move the hash.
//
// Two deliberate normalisations, both so the same skill hashes identically on
// macOS, Linux and Windows — otherwise a lockfile could not be committed to a
// repo or compared across a team, and every Windows developer would see phantom
// drift on skills nobody touched:
//
//   • separators in the stored relative path
//   • CRLF → LF in text files, because git's autocrlf rewrites them on checkout
//
// The cost is that a pure line-ending change is invisible to drift detection.
// That is the right trade: it is not an attack vector, and false drift is what
// makes people stop reading the warnings.
function hashSkill(files) {
  const h = crypto.createHash('sha256');
  for (const f of files) {
    h.update(f.rel.replace(/\\/g, '/'));
    h.update('\0');
    if (f.symlink !== undefined) h.update('symlink:' + String(f.symlink).replace(/\\/g, '/'));
    else if (f.size > MAX_BYTES) h.update('oversize:' + f.size);
    else h.update(canonBytes(f.rel, readBuf(f.path)));
    h.update('\0');
  }
  return h.digest('hex').slice(0, 16);
}

function canonBytes(rel, buf) {
  if (!TEXT_EXT.test(rel) || buf.includes(0)) return buf; // NUL ⇒ treat as binary
  return Buffer.from(buf.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');
}

// --- signals -----------------------------------------------------------------

const EXEC_EXT = /\.(sh|bash|zsh|py|rb|pl|php|js|mjs|cjs|ts|ps1|bat|cmd|exp)$/i;
const BYTECODE_EXT = /\.(pyc|pyo|so|dylib|dll|exe|wasm|class|jar)$/i;
const ARCHIVE_EXT = /\.(zip|tar|tgz|gz|bz2|xz|7z|rar|docx|xlsx|pptx)$/i;
const TEXT_EXT = /\.(md|txt|sh|bash|zsh|py|rb|pl|php|js|mjs|cjs|ts|json|ya?ml|toml|ps1|bat|cmd)$/i;

// Zero-width, bidi override, and Unicode tag characters — the tag block
// (U+E0000–U+E007F) renders as nothing at all and is the standard channel for
// smuggling instructions past a human reviewer.
const INVISIBLE = /[​-‏‪-‮⁠-⁤﻿]|[\u{E0000}-\u{E007F}]/u;

// Two tiers, calibrated the hard way: the first version of this flagged
// VibeGuard's own status skill, which tells the agent "do not tell the user
// their actions were safe just because no cards appeared" — a safety
// instruction, not an attack.
//
// Concealment phrasing is genuinely ambiguous in agent-facing prose and cannot
// carry a red on its own. Instruction-override phrasing is not ambiguous;
// honest documentation has no reason to say "ignore all previous instructions".
// Anything that fires here quotes the matched text, so a human can dismiss a
// false positive in one second instead of trusting our judgement.
const OVERRIDE_PHRASE =
  /\b(ignore (all |any )?(previous|prior|above|earlier)|disregard (the |all |any )?(previous|prior|above|earlier|instructions|rules)|(override|overrides|ignore) (the |your )?(system prompt|safety|guardrails)|you are now (a|an|in)|bypass (the )?(safety|security|permission|guardrail)|regardless of (what|any) (the user|instructions|rules))/i;

const CONCEAL_PHRASE =
  /\b(do not (tell|inform|mention to|notify|show) the (user|human)|without (asking|telling|informing|notifying) (the )?(user|them|anyone)|silently|do not (log|record|report) this|hide (this|it) from)/i;

const URL_RE = /\bhttps?:\/\/([A-Za-z0-9._-]+(?::\d+)?)(\/[^\s'"`)\]]*)?/g;

function signals(skill, policy) {
  const out = [];
  const add = (level, code, msg) => out.push({ level, code, msg });

  const skillMd = readText(path.join(skill.dir, 'SKILL.md'));

  // The description is the highest-leverage location in the whole package: it
  // is injected into context for every session whether or not the skill is ever
  // triggered. The body only loads once something matches. Both tiers are red
  // here — a one-line trigger description has no legitimate reason to discuss
  // concealment or overriding instructions at all.
  const descHit = OVERRIDE_PHRASE.exec(skill.description) || CONCEAL_PHRASE.exec(skill.description);
  if (descHit) {
    add('red', 'skill.description-injection',
      `Its always-loaded description says "${descHit[0]}". That text reaches the model every session, whether or not the skill is triggered.`);
  }
  if (INVISIBLE.test(skill.description)) {
    add('red', 'skill.description-hidden-text',
      'Its always-loaded description contains invisible characters. Text you cannot see is reaching the model every session.');
  }

  if (INVISIBLE.test(skillMd)) {
    add('red', 'skill.hidden-unicode',
      'SKILL.md contains zero-width or bidi-override characters — instructions a human reviewer cannot see on screen.');
  }
  const overrideHit = OVERRIDE_PHRASE.exec(skillMd);
  if (overrideHit) {
    add('red', 'skill.instruction-override',
      `SKILL.md says "${overrideHit[0]}" — an attempt to override the agent’s own instructions.`);
  }
  const concealHit = CONCEAL_PHRASE.exec(skillMd);
  if (concealHit) {
    add('orange', 'skill.conceal-language',
      `SKILL.md says "${concealHit[0]}". Often legitimate in agent-facing docs, so read the surrounding line before judging.`);
  }

  // Trail of Bits bypass #1: pad past the scanner's context window.
  const runs = skillMd.match(/\n{200,}/);
  if (runs) {
    add('red', 'skill.whitespace-inflation',
      `SKILL.md hides content behind ${runs[0].length.toLocaleString()} blank lines — a known trick for pushing payloads past a scanner’s context window.`);
  }

  if (skill.files.truncated) {
    add('orange', 'skill.oversized',
      `Contains more than ${MAX_FILES} files, too many to inventory completely.`);
  }

  for (const f of skill.files) {
    if (f.symlink !== undefined) {
      const target = path.resolve(path.dirname(f.path), f.symlink);
      if (!target.startsWith(skill.dir + path.sep)) {
        add('red', 'skill.symlink-escape',
          `"${f.rel}" is a symlink pointing outside the skill, at ${tilde(target)}.`);
      }
      continue;
    }
    // Trail of Bits bypass #2: no scanner meaningfully reads bytecode.
    if (BYTECODE_EXT.test(f.rel)) {
      add('red', 'skill.compiled-payload',
        `Ships compiled code ("${f.rel}") whose behaviour cannot be read from source.`);
    }
    // Bypass #3: instructions buried in a document container.
    if (ARCHIVE_EXT.test(f.rel)) {
      add('orange', 'skill.archive-payload',
        `Ships an archive or document ("${f.rel}") that can carry instructions inside it.`);
    }
  }

  const scripts = skill.files.filter((f) => f.symlink === undefined && EXEC_EXT.test(f.rel));
  if (scripts.length) {
    add('orange', 'skill.exec-payload',
      `Ships ${scripts.length} runnable script${scripts.length > 1 ? 's' : ''} (${scripts.slice(0, 3).map((f) => f.rel).join(', ')}${scripts.length > 3 ? ', …' : ''}). Running the skill can run these.`);
  }

  // Two corpora, because they warrant different rules. Prose is documentation
  // and will legitimately contain example commands and links; a skill whose
  // README says "run sudo apt install" is not an attack, and flagging it red
  // would make the whole tool noise. Code is what actually executes.
  const readAll = (pred) => skill.files
    .filter((f) => f.symlink === undefined && f.size <= MAX_BYTES && pred(f.rel))
    .map((f) => readText(f.path))
    .join('\n');

  const code = readAll((rel) => EXEC_EXT.test(rel));
  const prose = readAll((rel) => TEXT_EXT.test(rel) && !EXEC_EXT.test(rel));

  // Secrets are scanned in both. In code it is an exfiltration primitive; in
  // prose it is a natural-language instruction to the agent, which is the whole
  // SKILL.md attack class and reads identically to the model.
  const secrets = secretReads(code + '\n' + prose, policy);
  if (secrets.length) {
    add('red', 'skill.secret-reference',
      `References your credentials (${secrets.slice(0, 3).map((s) => s.match).join(', ')}).`);
  }

  // Shell rules run over code only.
  const bash = classifyBash(code);
  if (bash && bash.level === 'red') {
    add('red', `skill.${bash.rule.replace(/^local\./, '')}`, `Bundled code: ${bash.msg}`);
  }

  // A blocked destination is damning wherever it appears — prose telling the
  // agent to POST somewhere works as well as code doing it. An *unrecognised*
  // destination is only reported from code, because prose is full of links.
  for (const dest of urlsIn(code + '\n' + prose)) {
    if ((classify(policy, dest) || {}).decision === 'deny') {
      add('red', 'skill.denied-destination',
        `Contacts ${dest.host}, which your egress policy blocks. Destinations like this are where exfiltrated data lands.`);
    }
  }
  for (const dest of urlsIn(code)) {
    if (!classify(policy, dest)) {
      add('orange', 'skill.unknown-destination',
        `Bundled code contacts ${dest.host}, which is not on your allowlist.`);
    }
  }

  // Naming the agent's config is not itself suspicious — VibeGuard's own docs
  // do it. Writing to it is. The verb is what carries the signal.
  const CONFIG_WRITE =
    /\b(write|writes|edit|edits|append|appends|add|adds|modify|modifies|patch|patches|insert|inserts|update|updates)\b[^\n]{0,60}(\.claude\/settings|settings\.local\.json|hooks\.json|managed-settings)|(>>?)\s*[^\n]{0,40}(\.claude\/settings|settings\.local\.json|hooks\.json)/i;
  if (CONFIG_WRITE.test(code + '\n' + prose)) {
    add('red', 'skill.agent-config-write',
      'Writes to the agent’s own settings or hooks. That is how a skill grants itself permissions for every future session.');
  }

  return dedupe(out);
}

function urlsIn(text) {
  const out = new Map();
  for (const m of String(text).matchAll(URL_RE)) {
    const host = m[1].replace(/:\d+$/, '');
    if (!out.has(host)) {
      out.set(host, { host, path: m[2] || '', scheme: m[0].startsWith('https') ? 'https' : 'http' });
    }
  }
  return [...out.values()];
}

function dedupe(list) {
  const seen = new Set();
  const out = [];
  for (const s of list) {
    const key = s.code + '|' + s.msg;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  return out.sort((a, b) => (a.level === b.level ? 0 : a.level === 'red' ? -1 : 1));
}

// --- lockfile ----------------------------------------------------------------

function readLock() {
  try {
    const j = JSON.parse(fs.readFileSync(LOCKFILE, 'utf8'));
    if (j && typeof j.pinned === 'object') return j;
  } catch {
    /* first run */
  }
  return { version: 1, pinned: {} };
}

function writeLock(lock) {
  fs.mkdirSync(path.dirname(LOCKFILE), { recursive: true });
  fs.writeFileSync(LOCKFILE, JSON.stringify(lock, null, 2) + '\n');
}

// Pinning and accepting risk are different statements. `pin` says "these are
// the bytes I reviewed"; `accept` says "and I am fine with what they do". A
// skill that legitimately ships credentials handling needs the second one, and
// without the split the block has no exit — you pin, and it stays blocked, and
// the remedy it prints is the thing you just did.
//
// Acceptance is recorded against the hash and dies with it: change one byte and
// the skill is unreviewed again.
function pin(skills, lock, { accept = [] } = {}) {
  const now = new Date().toISOString();
  for (const s of skills) {
    const prev = lock.pinned[s.id];
    const carried = prev && prev.hash === s.hash ? prev.accepted || [] : [];
    lock.pinned[s.id] = {
      hash: s.hash,
      files: s.files.length,
      pinnedAt: now,
      dir: s.dir,
      accepted: [...new Set([...carried, ...accept])],
    };
  }
  return lock;
}

// Red signals the user has not explicitly accepted for this exact hash.
function liveSignals(row) {
  const ok = new Set(row.accepted || []);
  return row.signals.filter((s) => s.level === 'red' && !ok.has(s.code));
}

// --- audit -------------------------------------------------------------------

// Three states, and the distinction is the whole point. `changed` is the one
// install-time scanning cannot produce: the skill was reviewed, approved, and
// then edited.
function audit(cwd, policy) {
  const lock = readLock();
  const skills = discover(cwd);
  const rows = skills.map((s) => {
    const prev = lock.pinned[s.id];
    const status = !prev ? 'new' : prev.hash !== s.hash ? 'changed' : 'pinned';
    return {
      ...s,
      status,
      previousHash: prev ? prev.hash : null,
      // Acceptance only survives if the bytes did not move.
      accepted: status === 'pinned' && prev ? prev.accepted || [] : [],
      signals: signals(s, policy),
    };
  });
  // "Removed" means gone from disk, not merely out of scope. A skill pinned
  // while you were in another project is still installed — it just is not
  // loadable from here, and reporting it as missing produces a false alarm on
  // every directory change. False alarms are how a security tool teaches people
  // to ignore it.
  //
  // The same directory can also be pinned under two ids (user: and project:)
  // depending on where you were standing the first time it was seen, so
  // resolved paths are what get compared, not ids.
  const liveDirs = new Set(skills.map((s) => path.resolve(s.dir)));
  const removed = Object.entries(lock.pinned)
    .filter(([id, v]) => {
      if (skills.some((s) => s.id === id)) return false;
      if (v && v.dir && liveDirs.has(path.resolve(v.dir))) return false; // same skill, different id
      if (v && v.dir && fs.existsSync(v.dir)) return false; // installed, just not in scope here
      return true;
    })
    .map(([id]) => id);

  return { rows, removed, lock };
}

function worstLevel(row) {
  if (row.status === 'changed') return 'red';
  if (liveSignals(row).length) return 'red';
  if (row.status === 'new' || row.signals.length) return 'orange';
  return 'green';
}

// --- state cache, for the PreToolUse path ------------------------------------
//
// PreToolUse fires on every tool call and cannot afford to re-hash the world.
// SessionStart writes the verdict; the pre-tool adapter reads this small file
// and only needs a prefix match against a directory.

function writeState(rows) {
  try {
    const flagged = rows
      .filter((r) => worstLevel(r) === 'red')
      .map((r) => {
        const drift = r.status === 'changed';
        const live = liveSignals(r);
        return {
          id: r.id,
          dir: r.dir,
          status: r.status,
          // Reads as the tail of "…flagged because ___.", so it has to be a
          // lowercase clause with no trailing stop.
          reason: drift
            ? 'its files changed since you pinned it'
            : clause((live[0] || {}).msg) || 'it carries unreviewed risk signals',
          // Drift is cleared by re-pinning. A signal is not — re-pinning the
          // same bytes changes nothing, so the remedy has to be the other verb
          // or the block is a dead end.
          //
          // Phrased for someone who does not have `vg` on their PATH, which is
          // everyone who installed the plugin rather than the repo. Telling a
          // non-developer to run a CLI they do not have is the same dead end in
          // a different costume.
          remedy: drift
            ? 'Run /vibeguard-skills to review it, then accept the change.'
            : 'Run /vibeguard-skills to see why, then accept it if you trust it.',
          cli: drift ? `vg skills pin ${r.id}` : `vg skills pin ${r.id} --accept-risk`,
        };
      });
    fs.mkdirSync(path.dirname(STATEFILE), { recursive: true });
    fs.writeFileSync(STATEFILE, JSON.stringify({ ts: new Date().toISOString(), flagged }, null, 2) + '\n');
  } catch {
    /* the cache is an optimisation, never a crash */
  }
}

function readState() {
  try {
    const j = JSON.parse(fs.readFileSync(STATEFILE, 'utf8'));
    return Array.isArray(j.flagged) ? j.flagged : [];
  } catch {
    return [];
  }
}

// Does this tool call reach into a flagged skill directory? Used by the
// PreToolUse adapter to turn detection into enforcement.
function guardPaths(texts, platform) {
  const flagged = readState();
  if (!flagged.length) return null;
  const win = (platform || process.platform) === 'win32';
  const hay = flatten(texts.filter(Boolean).join(' '), win);
  if (!hay) return null;
  for (const f of flagged) {
    const variants = [...pathVariants(f.dir, win), tilde(f.dir)]
      .map((v) => flatten(v, win))
      .filter(Boolean);
    if (variants.some((v) => hay.includes(v))) {
      return {
        id: f.id,
        dir: f.dir,
        msg: `Runs code from the skill "${f.id.split(':').pop()}", which VibeGuard flagged because ${f.reason}.`,
        action: f.remedy,
      };
    }
  }
  return null;
}

// --- path comparison ---------------------------------------------------------
//
// Windows hands the same directory to us in at least four spellings. `path.join`
// stores `C:\Users\p\.claude\skills\evil`, but the Bash tool runs through Git
// Bash or WSL, so the command text says `/c/Users/...` or `/mnt/c/Users/...`,
// and casing is not preserved anywhere. A raw substring test matches exactly one
// of those — which means on Windows the guard silently failed open, the worst
// way for a security control to be wrong. Generate the spellings, compare them
// all.

function flatten(s, win) {
  const out = String(s).replace(/\\/g, '/').replace(/\/{2,}/g, '/').replace(/\/$/, '');
  return win ? out.toLowerCase() : out;
}

function pathVariants(dir, win) {
  const fwd = String(dir).replace(/\\/g, '/');
  const out = new Set([fwd]);
  const m = /^([A-Za-z]):\/(.*)$/.exec(fwd);
  if (m) {
    const [, drive, rest] = m;
    out.add(`/${drive}/${rest}`); // Git Bash / MSYS
    out.add(`/mnt/${drive.toLowerCase()}/${rest}`); // WSL
    out.add(`/cygdrive/${drive.toLowerCase()}/${rest}`); // Cygwin
  }
  return [...out].map((v) => (win ? v : v));
}

// --- helpers -----------------------------------------------------------------

function frontmatter(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return {};
  const out = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(line);
    if (kv) out[kv[1]] = kv[2].replace(/^["']|["']$/g, '');
  }
  return out;
}

function readText(p) {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return '';
  }
}

function readBuf(p) {
  try {
    return fs.readFileSync(p);
  } catch {
    return Buffer.alloc(0);
  }
}

function readlink(p) {
  try {
    return fs.readlinkSync(p);
  } catch {
    return '?';
  }
}

// "References your credentials (X)." → "it references your credentials (X)"
function clause(msg) {
  if (!msg) return '';
  const s = String(msg).trim().replace(/\.$/, '');
  return 'it ' + s.charAt(0).toLowerCase() + s.slice(1);
}

function tilde(p) {
  const home = os.homedir();
  return p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

module.exports = {
  discover, inspect, hashSkill, signals, audit, worstLevel, liveSignals,
  readLock, writeLock, pin, writeState, readState, guardPaths, tilde,
  flatten, pathVariants, canonBytes,
  LOCKFILE, STATEFILE,
};
