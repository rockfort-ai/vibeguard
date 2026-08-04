'use strict';

// Skill signal tests. Each fixture under test/fixtures/skills reproduces a
// technique that is known to work in the wild — four of them are the exact
// bypasses Trail of Bits used against ClawHub/VirusTotal, Cisco AI Defense,
// Socket and Snyk in June 2026.
//
// `want` lists codes that must fire. `deny` lists codes that must NOT, which is
// where the calibration lives: a clean skill that documents `sudo apt install`
// and links to github.com has to come back green, or the tool is noise.

const path = require('path');
const { load } = require('../lib/policy');
const { inspect, signals, hashSkill } = require('../lib/skills');

const FIXTURES = path.join(__dirname, 'fixtures', 'skills');

const CASES = [
  { skill: 'clean-formatter', want: [], deny: ['skill.instruction-override', 'skill.secret-reference', 'skill.sudo', 'skill.unknown-destination'] },
  { skill: 'padded', want: ['skill.whitespace-inflation', 'skill.secret-reference', 'skill.denied-destination'] },
  { skill: 'bytecode-helper', want: ['skill.compiled-payload'] },
  { skill: 'invisible', want: ['skill.description-hidden-text', 'skill.description-injection'] },
  { skill: 'log-shipper', want: ['skill.secret-reference', 'skill.denied-destination', 'skill.exec-payload'] },
  { skill: 'helpful-setup', want: ['skill.agent-config-write'] },
  { skill: 'peeker', want: ['skill.symlink-escape'] },
];

// The symlink-escape fixture is built here rather than committed. A repo that
// ships a symlink pointing at ~/.ssh is alarming to read, breaks on checkout
// for anyone whose home directory differs, and is the sort of thing a scanner
// should flag in someone else's package.
function ensureSymlinkFixture() {
  const fs = require('fs');
  const link = path.join(FIXTURES, 'peeker', 'notes');
  try {
    fs.lstatSync(link);
  } catch {
    try { fs.symlinkSync(path.join(require('os').homedir(), '.ssh'), link); } catch { /* best effort */ }
  }
}

function run() {
  const policy = load(process.cwd());
  ensureSymlinkFixture();
  let fail = 0;

  for (const c of CASES) {
    const s = inspect('test', c.skill, path.join(FIXTURES, c.skill));
    const codes = signals(s, policy).map((x) => x.code);
    const missing = c.want.filter((w) => !codes.includes(w));
    const wrong = (c.deny || []).filter((d) => codes.includes(d));
    const ok = !missing.length && !wrong.length;
    if (!ok) fail++;

    console.log(`${ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} ${c.skill.padEnd(18)} ${codes.join(', ') || '(clean)'}`);
    if (missing.length) console.log(`      \x1b[31mmissing:\x1b[0m ${missing.join(', ')}`);
    if (wrong.length) console.log(`      \x1b[31mfalse positive:\x1b[0m ${wrong.join(', ')}`);
  }

  // Drift: the property the whole design rests on. Any content change, and a
  // repointed symlink in particular, must move the hash.
  const before = inspect('test', 'clean-formatter', path.join(FIXTURES, 'clean-formatter'));
  const fs = require('fs');
  const target = path.join(FIXTURES, 'clean-formatter', 'SKILL.md');
  const original = fs.readFileSync(target, 'utf8');
  fs.writeFileSync(target, original + '\nOne extra line.\n');
  const after = inspect('test', 'clean-formatter', path.join(FIXTURES, 'clean-formatter'));
  fs.writeFileSync(target, original);
  const restored = inspect('test', 'clean-formatter', path.join(FIXTURES, 'clean-formatter'));

  const drifts = before.hash !== after.hash;
  const stable = before.hash === restored.hash;
  if (!drifts || !stable) fail++;
  console.log(`${drifts && stable ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} ${'drift detection'.padEnd(18)} ${before.hash} → ${after.hash} → ${restored.hash}`);

  // An empty skill must hash deterministically rather than throw.
  if (hashSkill([]) !== hashSkill([])) { fail++; console.log('\x1b[31m✗\x1b[0m empty-hash unstable'); }

  // A skill pinned in another project must not be reported as removed just
  // because you are standing somewhere else.
  {
    const { audit } = require('../lib/skills');
    const os = require('os');
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'rlegend-scope-'));
    const realDir = path.join(FIXTURES, 'clean-formatter');
    fs.mkdirSync(path.join(home, '.rlegend'), { recursive: true });
    fs.writeFileSync(path.join(home, '.rlegend', 'skills.lock.json'), JSON.stringify({
      version: 1,
      pinned: {
        'project:elsewhere': { hash: 'x', dir: realDir },            // installed, out of scope
        'project:actually-gone': { hash: 'x', dir: '/nope/gone' },   // really deleted
      },
    }));
    const prevHome = process.env.HOME;
    process.env.HOME = home;
    delete require.cache[require.resolve('../lib/skills')];
    const { audit: scoped } = require('../lib/skills');
    const res = scoped(home, policy);
    process.env.HOME = prevHome;
    delete require.cache[require.resolve('../lib/skills')];

    const quiet = !res.removed.includes('project:elsewhere');
    const loud = res.removed.includes('project:actually-gone');
    if (!quiet) fail++;
    if (!loud) fail++;
    console.log(`${quiet ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} out-of-scope skill is not "removed"`);
    console.log(`${loud ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} genuinely deleted skill still is`);
    fs.rmSync(home, { recursive: true, force: true });
  }

  const disc = discoveryTests(policy);
  fail += disc.fail;

  const plat = platformTests();
  fail += plat.fail;

  const total = CASES.length + 3 + disc.total + plat.total;
  console.log(`\n${total - fail}/${total} passed`);
  return fail;
}

// --- discovery and lockfile migration ----------------------------------------
//
// v1.2.0 taught discovery about the desktop app's plugin tree. Two things had
// to be true for that to be safe, and both are asserted here.
//
// One: descend only via a manifest. The same tree holds hundreds of SKILL.md
// files left behind by old chat sessions, none of which can load. Globbing it
// would bury the real inventory and pin the junk as a baseline.
//
// Two: a pin survives the ids changing shape. Discovery gained new sources, so
// `user:pdf` became `desktop-plugin:anthropic-skills:pdf` — and matching on id
// alone would have reported every already-approved skill as drift on upgrade.
// A wall of false alarms is how a security tool teaches people to click through.

function discoveryTests(policy) {
  const fs = require('fs');
  const os = require('os');
  let fail = 0;
  let total = 0;
  const check = (ok, label, detail) => {
    total++;
    if (!ok) fail++;
    console.log(`${ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} ${label}${!ok && detail ? `  — ${detail}` : ''}`);
  };

  // Load the module against a throwaway HOME. It resolves the lockfile path at
  // require time, so the cache has to go with it.
  const withHome = (home, fn) => {
    const prev = process.env.HOME;
    const prevProfile = process.env.USERPROFILE;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    delete require.cache[require.resolve('../lib/skills')];
    try {
      return fn(require('../lib/skills'));
    } finally {
      process.env.HOME = prev;
      process.env.USERPROFILE = prevProfile;
      delete require.cache[require.resolve('../lib/skills')];
    }
  };

  const put = (file, body) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, body);
  };
  const skill = (dir, name) => put(path.join(dir, 'SKILL.md'),
    `---\nname: ${name}\ndescription: a test skill\n---\n\nDoes nothing.\n`);

  // 1. The desktop tree: manifests decide, and nothing else does.
  {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'rlegend-desk-'));
    const ids = withHome(home, (S) => {
      const base = S.desktopBase();

      // Bundled form: one plugin available, one explicitly disabled.
      const rpm = path.join(base, 'sessA', 'sessB', 'rpm');
      put(path.join(rpm, 'manifest.json'), JSON.stringify({
        lastUpdated: 2000,
        plugins: [
          { id: 'plugin_ok', name: 'okplug', installationPreference: 'available' },
          { id: 'plugin_off', name: 'offplug', installationPreference: 'disabled' },
        ],
      }));
      skill(path.join(rpm, 'plugin_ok', 'skills', 'good'), 'good');
      skill(path.join(rpm, 'plugin_off', 'skills', 'bad'), 'bad');

      // An older session left on disk. Not loadable, must not be reported.
      const stale = path.join(base, 'sessOld', 'sessB', 'rpm');
      put(path.join(stale, 'manifest.json'), JSON.stringify({
        lastUpdated: 1000,
        plugins: [{ id: 'plugin_stale', name: 'staleplug', installationPreference: 'available' }],
      }));
      skill(path.join(stale, 'plugin_stale', 'skills', 'ghost'), 'ghost');

      // Per-skill form: enabled one by one, and nested one level deeper.
      const sp = path.join(base, 'skills-plugin', 'x', 'y');
      put(path.join(sp, 'manifest.json'), JSON.stringify({
        lastUpdated: 2000,
        skills: [{ skillId: 'on', enabled: true }, { skillId: 'off', enabled: false }],
      }));
      put(path.join(sp, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'desk' }));
      skill(path.join(sp, 'skills', 'on'), 'on');
      skill(path.join(sp, 'skills', 'off'), 'off');

      // The decoy: a real SKILL.md no manifest points at.
      skill(path.join(base, 'local_junk', 'uploads', 'decoy'), 'decoy');

      return S.discover(null).map((s) => s.id);
    });

    check(ids.includes('desktop-plugin:okplug:good'), 'finds skills in an installed desktop plugin', ids.join(','));
    check(ids.includes('desktop-plugin:desk:on'), 'finds an individually enabled desktop skill', ids.join(','));
    check(!ids.some((i) => i.endsWith(':bad')), 'skips a disabled desktop plugin', ids.join(','));
    check(!ids.some((i) => i.endsWith(':off')), 'skips a skill the manifest disables', ids.join(','));
    check(!ids.some((i) => i.endsWith(':ghost')), 'ignores an older rotated session', ids.join(','));
    check(!ids.some((i) => i.endsWith(':decoy')), 'never descends without a manifest', ids.join(','));
    fs.rmSync(home, { recursive: true, force: true });
  }

  // 2. A plugin the user switched off is not loadable, so it is not reported.
  {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'rlegend-off-'));
    const install = path.join(home, 'installed', 'offplug');
    skill(path.join(install, 'skills', 'thing'), 'thing');
    put(path.join(home, '.claude', 'plugins', 'installed_plugins.json'),
      JSON.stringify({ plugins: { 'offplug@mkt': [{ installPath: install }] } }));

    const on = withHome(home, (S) => S.discover(null).map((s) => s.id));
    put(path.join(home, '.claude', 'settings.json'),
      JSON.stringify({ enabledPlugins: { 'offplug@mkt': false } }));
    const off = withHome(home, (S) => S.discover(null).map((s) => s.id));

    check(on.includes('plugin:offplug@mkt:thing'), 'an installed plugin\'s skills are found', on.join(','));
    check(!off.length, 'and disappear once the plugin is disabled', off.join(','));
    fs.rmSync(home, { recursive: true, force: true });
  }

  // 3. Migration by directory: same skill, new id shape, still pinned.
  {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'rlegend-mig-'));
    const dir = path.join(home, '.claude', 'skills', 'thing');
    skill(dir, 'thing');
    const hash = withHome(home, (S) => S.inspect('user', 'thing', dir).hash);
    put(path.join(home, '.rlegend', 'skills.lock.json'), JSON.stringify({
      version: 1,
      pinned: { 'legacy:thing': { hash, dir, accepted: ['skill.exec-payload'], files: 1 } },
    }));
    const res = withHome(home, (S) => S.audit(home, policy));
    const row = res.rows.find((r) => r.name === 'thing');
    check(row && row.status === 'pinned', 'a pin survives its id changing shape', row && row.status);
    check(row && row.accepted.includes('skill.exec-payload'), 'and carries accepted risk with it');
    check(!res.removed.includes('legacy:thing'), 'the old id is not reported as removed', res.removed.join(','));
    fs.rmSync(home, { recursive: true, force: true });
  }

  // 4. Migration by name + hash: the directory itself moved, which is what the
  //    desktop app does when it rotates a session. The hash is the proof.
  {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'rlegend-mig2-'));
    const dir = path.join(home, '.claude', 'skills', 'thing');
    skill(dir, 'thing');
    const hash = withHome(home, (S) => S.inspect('user', 'thing', dir).hash);
    put(path.join(home, '.rlegend', 'skills.lock.json'), JSON.stringify({
      version: 1,
      pinned: { 'desktop-plugin:old-session:thing': { hash, dir: path.join(home, 'gone', 'thing'), files: 1 } },
    }));
    const res = withHome(home, (S) => S.audit(home, policy));
    const row = res.rows.find((r) => r.name === 'thing');
    check(row && row.status === 'pinned', 'identical bytes under a moved path stay pinned', row && row.status);
    check(!res.removed.length, 'and the old path is not reported as removed', res.removed.join(','));
    fs.rmSync(home, { recursive: true, force: true });
  }

  // 5. The fallbacks must not promote anything. Same name, different bytes, and
  //    no directory in common: that is a new skill, and it says so.
  {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'rlegend-mig3-'));
    const dir = path.join(home, '.claude', 'skills', 'thing');
    skill(dir, 'thing');
    put(path.join(home, '.rlegend', 'skills.lock.json'), JSON.stringify({
      version: 1,
      pinned: { 'legacy:thing': { hash: 'deadbeefdeadbeef', dir: path.join(home, 'gone', 'thing'), files: 1 } },
    }));
    const res = withHome(home, (S) => S.audit(home, policy));
    const row = res.rows.find((r) => r.name === 'thing');
    check(row && row.status === 'new', 'a same-named skill with different bytes is new, not pinned', row && row.status);
    fs.rmSync(home, { recursive: true, force: true });
  }

  return { fail, total };
}

// --- cross-platform path matching --------------------------------------------
//
// These run identically on macOS, Linux and Windows, because the Windows
// behaviour is driven by an explicit flag rather than the host. The guard used
// to compare a `path.join`-shaped string against raw command text, which meant
// every Git Bash, WSL, Cygwin and mixed-case spelling on Windows failed open —
// no match, no deny, no warning that the control had not fired.

function platformTests() {
  const { flatten, pathVariants, canonBytes } = require('../lib/skills');
  const stored = 'C:\\Users\\p\\.claude\\skills\\evil';
  const commands = [
    ['native backslash', 'python C:\\Users\\p\\.claude\\skills\\evil\\x.py'],
    ['forward slash', 'python C:/Users/p/.claude/skills/evil/x.py'],
    ['git bash', 'bash /c/Users/p/.claude/skills/evil/run.sh'],
    ['wsl', 'python /mnt/c/Users/p/.claude/skills/evil/x.py'],
    ['cygwin', 'bash /cygdrive/c/Users/p/.claude/skills/evil/run.sh'],
    ['mixed case', 'python C:\\Users\\P\\.CLAUDE\\Skills\\Evil\\x.py'],
  ];

  let fail = 0;
  let total = commands.length + 4;
  const variants = pathVariants(stored, true).map((v) => flatten(v, true));
  for (const [label, cmd] of commands) {
    const hit = variants.some((v) => flatten(cmd, true).includes(v));
    if (!hit) fail++;
    console.log(`${hit ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} win path ${label.padEnd(17)} ${hit ? 'blocked' : 'FAILS OPEN'}`);
  }

  // POSIX must not gain Windows' case-insensitivity: two skills differing only
  // by case are two different skills on a case-sensitive filesystem.
  const caseSensitive = !flatten('/home/p/skills/Evil', false).includes(flatten('/home/p/skills/evil', false));
  if (!caseSensitive) fail++;
  console.log(`${caseSensitive ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} posix stays case-sensitive`);

  // A lockfile has to survive git's autocrlf, or Windows sees phantom drift.
  const crlfStable = canonBytes('SKILL.md', Buffer.from('a\r\nb\r\n')).equals(
    canonBytes('SKILL.md', Buffer.from('a\nb\n')));
  const binaryRaw = !canonBytes('x.pyc', Buffer.from('a\r\n\0b')).equals(
    canonBytes('x.pyc', Buffer.from('a\n\0b')));
  if (!crlfStable) fail++;
  if (!binaryRaw) fail++;
  console.log(`${crlfStable ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} crlf/lf hash identical`);
  console.log(`${binaryRaw ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} binary hashed byte-exact`);

  return { fail, total };
}

if (require.main === module) process.exit(run() ? 1 : 0);
module.exports = { run };
