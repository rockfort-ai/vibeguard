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

const { statePath } = require('./paths');

const LOCKFILE = statePath('skills.lock.json');
const STATEFILE = statePath('skills.state.json');

// SessionStart runs on every session and has to stay fast, so the walk is
// bounded. A skill that blows these limits is itself worth a signal.
const MAX_FILES = 400;
const MAX_BYTES = 2 * 1024 * 1024;

// --- discovery ---------------------------------------------------------------

// Some skills in a session are provided by the app itself and have no SKILL.md
// on disk anywhere. Nothing here can see them, and a tool that quietly omits
// them reads as "checked and clean". Say so instead.
const NOT_INVENTORIED_NOTE =
  'Some skills are provided by the app itself and are not on disk where ' +
  'Rockfort Legend can read them. They are not inventoried, and not checked.';

// Only places a skill can actually be loaded from. Deliberately not
// ~/.claude/plugins/marketplaces — those are catalogue clones of plugins that
// are available, not installed, and reporting them is noise about code that
// never enters a context window.
//
// A root is { source, dir, only? }. `only` names the subdirectories that are
// actually loadable, for trees where the manifest enables skills one by one
// rather than by installing a whole plugin.
function roots(cwd) {
  const out = [{ source: 'user', dir: path.join(os.homedir(), '.claude', 'skills') }];
  if (cwd) out.push({ source: 'project', dir: path.join(cwd, '.claude', 'skills') });
  for (const p of installedPlugins(cwd)) {
    out.push({ source: `plugin:${p.name}`, dir: path.join(p.installPath, 'skills') });
  }
  out.push(...desktopRoots());
  return out;
}

// Plugins the user has switched off are not loadable, so reporting them is the
// same false alarm as reporting a marketplace clone. Keys are "<plugin>@<market>".
function disabledPlugins(cwd) {
  const files = [
    path.join(os.homedir(), '.claude', 'settings.json'),
    path.join(os.homedir(), '.claude', 'settings.local.json'),
  ];
  if (cwd) {
    files.push(path.join(cwd, '.claude', 'settings.json'));
    files.push(path.join(cwd, '.claude', 'settings.local.json'));
  }
  const off = new Set();
  for (const f of files) {
    try {
      const j = JSON.parse(fs.readFileSync(f, 'utf8'));
      for (const [k, v] of Object.entries(j.enabledPlugins || {})) {
        if (v === false) off.add(String(k).split('@')[0]);
      }
    } catch {
      /* missing settings file is the normal case */
    }
  }
  return off;
}

function installedPlugins(cwd) {
  const file = path.join(os.homedir(), '.claude', 'plugins', 'installed_plugins.json');
  let j;
  try {
    j = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
  const off = disabledPlugins(cwd);
  const out = [];
  for (const [name, entries] of Object.entries(j.plugins || {})) {
    if (off.has(String(name).split('@')[0])) continue;
    for (const e of Array.isArray(entries) ? entries : [entries]) {
      if (e && e.installPath) out.push({ name, installPath: e.installPath, version: e.version || '' });
    }
  }
  return out;
}

// --- Claude Desktop plugins --------------------------------------------------
//
// The desktop app keeps its plugins somewhere ~/.claude knows nothing about, so
// until v1.2.0 `rlegend skills` reported one skill on a machine with two dozen
// loadable ones — an inventory that quietly omits most of its subject.
//
// The rule that makes this safe is: descend only via a manifest, never by
// globbing. The same tree holds 236 SKILL.md files, most of them uploads left
// behind by old chat sessions. Globbing would inventory all of them and pin
// them as a baseline, which is worse than reporting nothing: it buries the
// handful of skills that can actually load in a pile of files that cannot.
//
// The macOS base is verified. The other two are the documented per-platform
// locations and have not been tested on a real machine — same standing as the
// Codex and Windows wiring in HANDOVER.md.
function desktopBase() {
  const home = os.homedir();
  if (process.platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'Claude', 'local-agent-mode-sessions');
  }
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    return path.join(appData, 'Claude', 'local-agent-mode-sessions');
  }
  return path.join(home, '.config', 'Claude', 'local-agent-mode-sessions');
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

// Session directories rotate. Several can be left on disk, so take the newest
// of each kind by the manifest's own lastUpdated rather than reporting the
// union — stale sessions are not loadable and would show up as duplicates.
function newest(candidates) {
  return candidates.sort((a, b) => (b.lastUpdated || 0) - (a.lastUpdated || 0))[0] || null;
}

function desktopRoots() {
  const base = desktopBase();
  let top;
  try {
    top = fs.readdirSync(base, { withFileTypes: true }).filter((e) => e.isDirectory());
  } catch {
    return []; // no desktop app, or a platform whose path we guessed wrong
  }

  const bundled = [];   // <base>/<a>/<b>/rpm/manifest.json — whole plugins
  const perSkill = [];  // <base>/skills-plugin/<a>/<b>/manifest.json — skill by skill

  for (const t of top.slice(0, 50)) {
    const dir = path.join(base, t.name);
    let mid;
    try {
      mid = fs.readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory());
    } catch {
      continue;
    }
    for (const m of mid.slice(0, 50)) {
      // <base>/skills-plugin/<a>/<b>/manifest.json — one level deeper than the
      // bundled form, and the nesting order of the two ids is not the same.
      if (t.name === 'skills-plugin') {
        let inner;
        try {
          inner = fs.readdirSync(path.join(dir, m.name), { withFileTypes: true }).filter((e) => e.isDirectory());
        } catch {
          continue;
        }
        for (const i of inner.slice(0, 50)) {
          const home = path.join(dir, m.name, i.name);
          const j = readJson(path.join(home, 'manifest.json'));
          if (j && Array.isArray(j.skills)) perSkill.push({ home, lastUpdated: j.lastUpdated, manifest: j });
        }
        continue;
      }
      // <base>/<a>/<b>/rpm/manifest.json — a whole plugin per entry.
      const home = path.join(dir, m.name, 'rpm');
      const j = readJson(path.join(home, 'manifest.json'));
      if (j && Array.isArray(j.plugins)) bundled.push({ home, lastUpdated: j.lastUpdated, manifest: j });
    }
  }

  const out = [];

  const b = newest(bundled);
  if (b) {
    for (const p of b.manifest.plugins) {
      if (!p || !p.id || !p.name) continue;
      if (p.installationPreference === 'disabled') continue;
      out.push({ source: `desktop-plugin:${p.name}`, dir: path.join(b.home, p.id, 'skills') });
    }
  }

  const s = newest(perSkill);
  if (s) {
    const meta = readJson(path.join(s.home, '.claude-plugin', 'plugin.json')) || {};
    const name = meta.name || 'desktop';
    const only = new Set(s.manifest.skills.filter((k) => k && k.enabled === true).map((k) => k.skillId));
    if (only.size) out.push({ source: `desktop-plugin:${name}`, dir: path.join(s.home, 'skills'), only });
  }

  return out;
}

// Names and directories only — a few readdir calls, no walking and no hashing.
// The PreToolUse path needs to answer "which skill is this?" on a tool call,
// and hashing two dozen skills to identify one of them is not a thing a hook
// can afford to do.
function list(cwd) {
  const out = [];
  for (const { source, dir, only } of roots(cwd)) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // a root that does not exist is the normal case
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (only && !only.has(e.name)) continue; // present on disk, not enabled
      const skillDir = path.join(dir, e.name);
      if (!fs.existsSync(path.join(skillDir, 'SKILL.md'))) continue;
      out.push({ id: `${source}:${e.name}`, name: e.name, source, dir: skillDir });
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

function discover(cwd) {
  return list(cwd).map((e) => inspect(e.source, e.name, e.dir));
}

function inspect(source, name, dir, prewalked) {
  const files = prewalked || walk(dir);
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
// Rockfort Legend's own status skill, which tells the agent "do not tell the user
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

  // Naming the agent's config is not itself suspicious — Rockfort Legend's own docs
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

const LOCK_VERSION = 2;

function readLock() {
  try {
    const j = JSON.parse(fs.readFileSync(LOCKFILE, 'utf8'));
    if (j && typeof j.pinned === 'object') return j;
  } catch {
    /* first run */
  }
  return { version: LOCK_VERSION, pinned: {} };
}

// A pin is a statement about bytes, not about the label those bytes were filed
// under. Discovery gained new sources in v1.2.0, so ids that were `user:pdf`
// became `desktop-plugin:anthropic-skills:pdf` — and matching on id alone would
// have reported every previously-approved skill as brand new on one upgrade.
// A wall of false drift is exactly how a tool teaches people to click through it.
//
// Two fallbacks, in order:
//   1. the resolved directory — the same reasoning `audit` already uses to
//      decide a skill is not "removed", just filed differently
//   2. the trailing name plus an identical hash — the hash is the proof, and
//      this is what survives the desktop app rotating its session directories
//
// Neither can promote an unpinned skill: both require an existing entry, and
// the second requires the bytes to match it exactly.
function lockIndex(lock) {
  const byDir = new Map();
  const byNameHash = new Map();
  for (const [id, v] of Object.entries(lock.pinned || {})) {
    if (!v) continue;
    if (v.dir) byDir.set(path.resolve(v.dir), v);
    if (v.hash) byNameHash.set(`${id.split(':').pop()} ${v.hash}`, v);
  }
  return {
    find(skill) {
      return lock.pinned[skill.id]
        || byDir.get(path.resolve(skill.dir))
        || byNameHash.get(`${skill.name} ${skill.hash}`)
        || null;
    },
  };
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
  const idx = lockIndex(lock);
  for (const s of skills) {
    const prev = idx.find(s);
    const carried = prev && prev.hash === s.hash ? prev.accepted || [] : [];

    // Rewrite to the current id and drop any older entry for the same
    // directory. The live lockfile already carried the same skill twice, under
    // `user:` and `project:`, because ids depend on where you were standing the
    // first time it was seen.
    for (const [id, v] of Object.entries(lock.pinned)) {
      if (id !== s.id && v && v.dir && path.resolve(v.dir) === path.resolve(s.dir)) {
        delete lock.pinned[id];
      }
    }

    lock.pinned[s.id] = {
      hash: s.hash,
      files: s.files.length,
      pinnedAt: now,
      dir: s.dir,
      accepted: [...new Set([...carried, ...accept])],
    };
  }
  lock.version = LOCK_VERSION;
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
  const idx = lockIndex(lock);
  const rows = skills.map((s) => {
    const prev = idx.find(s);
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
  const liveNameHash = new Set(skills.map((s) => `${s.name} ${s.hash}`));
  const removed = Object.entries(lock.pinned)
    .filter(([id, v]) => {
      if (skills.some((s) => s.id === id)) return false;
      if (v && v.dir && liveDirs.has(path.resolve(v.dir))) return false; // same skill, different id
      if (v && v.hash && liveNameHash.has(`${id.split(':').pop()} ${v.hash}`)) return false; // same bytes, moved
      if (v && v.dir && fs.existsSync(v.dir)) return false; // installed, just not in scope here
      return true;
    })
    .map(([id]) => id);

  return { rows, removed, lock };
}

// --- one skill, checked at the moment it is invoked --------------------------
//
// SessionStart's state file answers "was anything red when the session began".
// That is a different question from "is this skill, the one being invoked right
// now, in the state I approved" — the file can be an hour stale, it only ever
// held red rows, and on most machines it is empty. So the Skill tool gets a
// live check of that one skill instead.
//
// It stays cheap because identification uses `list` (readdir only) and exactly
// one skill is walked and hashed.

// A skill dir larger than this is not inspected. `signals` re-reads what
// `hashSkill` already read, so the honest ceiling is half of what a hook can
// afford. Bailing is fine; reporting a skill we did not read as clean is not.
const INSPECT_BUDGET_BYTES = 8 * 1024 * 1024;

// Claude Code spells an invocation several ways — `pdf`, `anthropic-skills:pdf`,
// or the full id. Match most specific first. The old code lowered both sides to
// a bare name, so two skills with the same directory name silently collided and
// whichever sorted first won.
function resolveInvoked(cwd, ref) {
  const raw = String(ref || '').trim();
  if (!raw) return [];
  const all = list(cwd);
  const exact = all.filter((e) => e.id === raw);
  if (exact.length) return byDir(exact);
  const suffix = all.filter((e) => e.id.endsWith(`:${raw}`));
  if (suffix.length) return byDir(suffix);
  const bare = raw.split(':').pop();
  return byDir(all.filter((e) => e.name === bare));
}

// One directory is one skill, however many labels point at it. The user and
// project roots are the same folder whenever you are standing in your home
// directory, and calling that a name collision would report an ambiguity that
// does not exist.
function byDir(entries) {
  const seen = new Set();
  return entries.filter((e) => {
    const key = path.resolve(e.dir);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Returns { status, rows }. `status` is one of:
//   ok               exactly one candidate, inspected
//   ambiguous        several skills answer to this name — itself worth noticing
//   not-inspectable  nothing on disk answers to it. App-provided skills land
//                    here, and they are never reported as checked
//   too-large        over budget; deliberately says nothing about contents
function checkInvocation(cwd, ref, policy) {
  const cands = resolveInvoked(cwd, ref);
  if (!cands.length) return { status: 'not-inspectable', rows: [] };

  const idx = lockIndex(readLock());
  const rows = [];
  for (const c of cands.slice(0, 4)) {
    let files;
    try {
      files = walk(c.dir);
    } catch {
      return { status: 'not-inspectable', rows: [], id: c.id };
    }
    const bytes = files.reduce((n, f) => n + (f.size || 0), 0);
    if (bytes > INSPECT_BUDGET_BYTES) return { status: 'too-large', rows: [], id: c.id };

    const s = inspect(c.source, c.name, c.dir, files);
    const prev = idx.find(s);
    const status = !prev ? 'new' : prev.hash !== s.hash ? 'changed' : 'pinned';
    rows.push({
      ...s,
      status,
      previousHash: prev ? prev.hash : null,
      accepted: status === 'pinned' && prev ? prev.accepted || [] : [],
      signals: signals(s, policy),
    });
  }
  return { status: cands.length > 1 ? 'ambiguous' : 'ok', rows, id: rows[0] && rows[0].id };
}

// What is worth interrupting for, and nothing else.
//
// Drift is the flagship case: approved, then edited. A red signal the user has
// not accepted for these exact bytes is the other. `new` on its own is not —
// SessionStart already establishes the baseline, and a card on the first use of
// a legitimately new skill is a nag. Orange on its own is not either:
// `skill.exec-payload` fires on almost every real skill, including the ones
// shipped by the app.
function invocationRisks(res) {
  return (res.rows || []).filter((r) => r.status === 'changed' || liveSignals(r).length);
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
          // Phrased for someone who does not have `rlegend` on their PATH, which is
          // everyone who installed the plugin rather than the repo. Telling a
          // non-developer to run a CLI they do not have is the same dead end in
          // a different costume.
          remedy: drift
            ? 'Run /rlegend-skills to review it, then accept the change.'
            : 'Run /rlegend-skills to see why, then accept it if you trust it.',
          cli: drift ? `rlegend skills pin ${r.id}` : `rlegend skills pin ${r.id} --accept-risk`,
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
        msg: `Runs code from the skill "${f.id.split(':').pop()}", which Rockfort Legend flagged because ${f.reason}.`,
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
  discover, list, inspect, hashSkill, signals, audit, worstLevel, liveSignals,
  resolveInvoked, checkInvocation, invocationRisks,
  readLock, writeLock, pin, writeState, readState, guardPaths, tilde,
  flatten, pathVariants, canonBytes,
  roots, desktopRoots, desktopBase, lockIndex,
  LOCKFILE, STATEFILE, LOCK_VERSION, NOT_INVENTORIED_NOTE,
};
