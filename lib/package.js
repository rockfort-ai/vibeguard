'use strict';

// Build the distributable plugin payload from this repo.
//
// Why this exists instead of a hand-maintained second copy: the plugin has to
// ship the same decision engine the test suite runs against. Two copies of
// decide.js drift silently, and "the shipped build differs from the tested
// build" is a sentence you cannot afford to say about a security tool. So the
// payload is generated, `rlegend package` refuses to build unless the tests pass,
// and every file lands with a recorded SHA-256 in MANIFEST.json.
//
// Output is a complete marketplace repo, not just a plugin directory, so it can
// be committed straight to rockfort-ai/rlegend:
//
//   <out>/.claude-plugin/marketplace.json
//   <out>/plugins/rlegend/{.claude-plugin,hooks,commands,bin,lib,adapters,policy}

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const VERSION = '1.3.0';

// Everything the runtime needs, and nothing else. `lib/policy.js` resolves the
// bundled policy as `../policy/policy.json`, so the tree shape has to survive
// the copy.
const PAYLOAD = [
  'bin/rlegend.js',
  'lib/audit.js', 'lib/bridge.js', 'lib/decide.js', 'lib/extract.js',
  'lib/paths.js', 'lib/policy.js', 'lib/remember.js', 'lib/render.js', 'lib/safelist.js',
  'lib/session.js', 'lib/skills.js',
  'adapters/claude-code.js', 'adapters/claude-code-session.js', 'adapters/claude-code-post.js',
  'adapters/claude-code-stop.js', 'adapters/cursor.js',
  'policy/policy.json', 'policy/strict.json',
  'test/skills.test.js', 'test/bridge.test.js', 'test/adapter.test.js',
  'test/demo.sh', 'test/demo-cards.sh',
  'test/fixtures/skills/clean-formatter/SKILL.md',
  'test/fixtures/skills/padded/SKILL.md',
  'test/fixtures/skills/bytecode-helper/SKILL.md',
  'test/fixtures/skills/bytecode-helper/scripts/opt.pyc',
  'test/fixtures/skills/invisible/SKILL.md',
  'test/fixtures/skills/log-shipper/SKILL.md',
  'test/fixtures/skills/log-shipper/scripts/ship.sh',
  'test/fixtures/skills/helpful-setup/SKILL.md',
  'test/fixtures/skills/peeker/SKILL.md',
  // Calibration fixtures. These carry no attack; they are the cases that must
  // come back quiet, plus the two that isolate one suppression each.
  'test/fixtures/skills/office-namespaces/SKILL.md',
  'test/fixtures/skills/office-namespaces/scripts/convert.py',
  'test/fixtures/skills/office-with-api/SKILL.md',
  'test/fixtures/skills/office-with-api/scripts/summarise.py',
  'test/fixtures/skills/inert-url-constant/SKILL.md',
  'test/fixtures/skills/inert-url-constant/scripts/footer.py',
  'test/fixtures/skills/api-caller/SKILL.md',
  'test/fixtures/skills/api-caller/scripts/eval.py',
  'test/fixtures/skills/beacon/SKILL.md',
  'test/fixtures/skills/beacon/scripts/collect.py',
  'COVERAGE.md', 'README.md',
];

const OPTIONAL = new Set(['LICENSE', 'COVERAGE.md', 'README.md']);

const DESCRIPTION =
  'Know what Claude Code is about to do, before you approve it. Plain-English ' +
  'red / orange / green cards on every permission prompt, network egress policy ' +
  'you can enforce instead of guessing, and content pinning for installed skills ' +
  'so a skill that changes after you approved it cannot quietly run.';

function marketplaceJson() {
  return {
    $schema: 'https://anthropic.com/claude-code/marketplace.schema.json',
    name: 'rlegend',
    description: 'Rockfort Legend by Rockfort AI — permission cards, egress control, and skill pinning for Claude Code',
    owner: { name: 'Rockfort AI', url: 'https://rockfort.ai' },
    plugins: [{
      name: 'rlegend',
      displayName: 'Rockfort Legend',
      description: DESCRIPTION,
      author: { name: 'Rockfort AI', url: 'https://rockfort.ai' },
      category: 'security',
      source: './plugins/rlegend',
      homepage: 'https://github.com/rockfort-ai/rlegend',
    }],
  };
}

function pluginJson(version) {
  return {
    name: 'rlegend',
    displayName: 'Rockfort Legend',
    version,
    description: DESCRIPTION,
    author: { name: 'Rockfort AI', url: 'https://rockfort.ai' },
    homepage: 'https://github.com/rockfort-ai/rlegend',
    repository: 'https://github.com/rockfort-ai/rlegend',
    license: 'MIT',
    keywords: ['security', 'permissions', 'hooks', 'safety', 'egress', 'skills', 'supply-chain'],
  };
}

// ${CLAUDE_PLUGIN_ROOT} is the whole reason to ship as a plugin rather than a
// settings.json snippet: Claude Code expands it per platform, so the same
// manifest works on macOS, Linux and Windows with no $HOME / %USERPROFILE%
// divergence.
function hooksJson() {
  return {
    description: 'Rockfort Legend — permission cards, egress enforcement, and skill drift detection',
    hooks: {
      PreToolUse: [{
        matcher: '*',
        hooks: [{
          type: 'command',
          command: 'node "${CLAUDE_PLUGIN_ROOT}/adapters/claude-code.js"',
          timeout: 20,
        }],
      }],
      // A hook-driven `ask` shows a reduced dialog — Deny / Allow once, with no
      // "don't ask again". So the only way a question can stop repeating is to
      // notice that it was answered yes. PostToolUse only fires after a tool
      // actually ran, which is exactly that signal.
      PostToolUse: [{
        matcher: '*',
        hooks: [{
          type: 'command',
          command: 'node "${CLAUDE_PLUGIN_ROOT}/adapters/claude-code-post.js"',
          timeout: 10,
        }],
      }],
      // Not `compact`: compaction does not reload skills, and re-reporting the
      // inventory into a context that was just trimmed spends the tokens
      // compaction reclaimed.
      SessionStart: [{
        matcher: 'startup|resume|clear',
        hooks: [{
          type: 'command',
          command: 'node "${CLAUDE_PLUGIN_ROOT}/adapters/claude-code-session.js"',
          timeout: 15,
        }],
      }],
      // No `matcher`: Stop is not tool-scoped, and a matcher it does not expect
      // is the kind of thing that makes a hook silently never fire.
      Stop: [{
        hooks: [{
          type: 'command',
          command: 'node "${CLAUDE_PLUGIN_ROOT}/adapters/claude-code-stop.js"',
          timeout: 10,
        }],
      }],
    },
  };
}

const SKILLS_COMMAND = `---
description: Inventory every Claude skill that can load in this session, flag content drift and risk signals.
allowed-tools: Bash(node:*)
---

Run the skill audit and show the user its output verbatim in a code block:

\`\`\`bash
node "\${CLAUDE_PLUGIN_ROOT}/bin/rlegend.js" skills
\`\`\`

Then, briefly:

- If any skill is marked **CHANGED**, say so first. It means the skill's files
  differ from what was pinned — the case an install-time scan cannot catch.
- Report the signal lines as written. Do not summarise them away, and do not
  translate them into a safety verdict: Rockfort Legend reports signals and hashes, it
  never certifies a skill as safe.
- If nothing is flagged, one line is enough.

To accept a skill's current contents: \`rlegend skills pin <id>\`. To also accept the
signals it trips: \`rlegend skills pin <id> --accept-risk\`.
`;

const SESSION_COMMAND = `---
description: Show every tool call Rockfort Legend judged this session, and which ones it stayed quiet about and why.
allowed-tools: Bash(node:*)
---

Show the user this output verbatim in a code block:

\`\`\`bash
node "\${CLAUDE_PLUGIN_ROOT}/bin/rlegend.js" session
\`\`\`

Then, briefly:

- Lead with the "elevated action(s) ran without a prompt" block if there is one.
  Those are calls the user was never asked about — in an auto-accept mode
  Rockfort Legend is told to stay quiet, so it records instead of interrupting.
- The \`quiet(...)\` column is the reason nothing was shown. \`mode:*\` means a
  permission mode silenced it, \`allow-rule:*\` means a rule in settings.json did,
  \`safe-list:*\` means Rockfort Legend answered it, \`remembered:*\` means the user
  already said yes once.
- If skills were invoked, repeat the attribution caveat as written. Rockfort Legend
  sees tool calls and not their origin; do not tell the user a skill "ran" a
  command.
- Do not translate any of this into a safety verdict.
`;

function build({ out, version = VERSION }) {
  const pluginDir = path.join(out, 'plugins', 'rlegend');
  fs.rmSync(out, { recursive: true, force: true });

  // Anything with a shebang has to land executable, or `./bin/rlegend.js` is a
  // "permission denied" for whoever unpacks this. Everything internal invokes
  // it as `node bin/rlegend.js`, so the missing bit went unnoticed until
  // someone typed the path directly, which is exactly what the docs tell you
  // to do. Derived from the file's own first two bytes rather than a list, so
  // a new script cannot be forgotten.
  const written = [];
  const put = (rel, body) => {
    const dest = path.join(pluginDir, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, body);
    const buf = Buffer.from(body);
    if (buf.slice(0, 2).toString() === '#!') fs.chmodSync(dest, 0o755);
    written.push({ file: rel, sha256: sha(buf) });
  };

  const missing = [];
  for (const rel of PAYLOAD) {
    const src = path.join(ROOT, rel);
    if (!fs.existsSync(src)) {
      if (!OPTIONAL.has(rel)) missing.push(rel);
      continue;
    }
    put(rel, fs.readFileSync(src));
  }
  if (missing.length) throw new Error(`payload missing required files: ${missing.join(', ')}`);

  put(path.join('.claude-plugin', 'plugin.json'), JSON.stringify(pluginJson(version), null, 2) + '\n');
  put(path.join('hooks', 'hooks.json'), JSON.stringify(hooksJson(), null, 2) + '\n');
  put(path.join('commands', 'rlegend-skills.md'), SKILLS_COMMAND);
  put(path.join('commands', 'rlegend-session.md'), SESSION_COMMAND);

  // Root of the marketplace repo.
  fs.mkdirSync(path.join(out, '.claude-plugin'), { recursive: true });
  fs.writeFileSync(
    path.join(out, '.claude-plugin', 'marketplace.json'),
    JSON.stringify(marketplaceJson(), null, 2) + '\n');

  const manifest = {
    name: 'rlegend',
    version,
    builtAt: new Date().toISOString(),
    builtBy: 'rlegend package',
    // Lets anyone verify the shipped tree against this build without trusting
    // the packager.
    files: written.sort((a, b) => a.file.localeCompare(b.file)),
  };
  fs.writeFileSync(path.join(pluginDir, 'MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n');

  return { out, pluginDir, version, files: written.length };
}

function sha(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16);
}

module.exports = { build, VERSION, PAYLOAD };
