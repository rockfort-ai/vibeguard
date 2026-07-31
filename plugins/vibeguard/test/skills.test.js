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
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-scope-'));
    const realDir = path.join(FIXTURES, 'clean-formatter');
    fs.mkdirSync(path.join(home, '.vibeguard'), { recursive: true });
    fs.writeFileSync(path.join(home, '.vibeguard', 'skills.lock.json'), JSON.stringify({
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

  const plat = platformTests();
  fail += plat.fail;

  const total = CASES.length + 3 + plat.total;
  console.log(`\n${total - fail}/${total} passed`);
  return fail;
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
