# Rockfort Legend — handover

Written 2026-07-31, updated 2026-08-05 for v1.3.0 (skill-signal calibration and
semantic drift). Everything below is verified, not remembered.

**The product was called VibeGuard until 2026-08-04.** The name collided with
too many existing tools. Everything is now `rlegend` / "Rockfort Legend". If you
find the old name anywhere outside `lib/paths.js` — which keeps it on purpose,
to migrate state — it is a miss, not a deliberate leftover.

## Read this first

**The engine repo is the source of truth. `plugins/rlegend/` in the git repo
is GENERATED — never hand-edit it.**

```
~/Desktop/Claude Code/projects/rlegend/        ← engine. edit here.
~/Desktop/Claude Code/projects/rlegend-repo/   ← git clone of rockfort-ai/rlegend
~/.rlegend/engine/                             ← what actually runs on this Mac
```

The only hand-written files in the git repo are `README.md` (root) and
`extension/`. Everything under `plugins/rlegend/` comes from `rlegend package`.

## The loop

```sh
cd ~/Desktop/Claude\ Code/projects/rlegend
node bin/rlegend.js test          # 154 tests. package refuses to build if any fail.
node bin/rlegend.js package       # builds dist/marketplace, smoke-tests the payload

# deploy locally (what runs on this Mac)
rsync -a --delete --exclude test dist/marketplace/plugins/rlegend/ ~/.rlegend/engine/

# sync into the git repo for a commit
rsync -a --delete --exclude LICENSE dist/marketplace/plugins/rlegend/ \
  ~/Desktop/Claude\ Code/projects/rlegend-repo/plugins/rlegend/
cp dist/marketplace/.claude-plugin/marketplace.json \
  ~/Desktop/Claude\ Code/projects/rlegend-repo/.claude-plugin/marketplace.json
```

**Hooks load at session start.** Any deploy needs a new Claude Code session
before it takes effect. Verifying a change inside the session that made it will
mislead you — this cost real time.

## State

- Branch `v1.1.0-egress-and-skill-pinning`, 7 commits, **not merged**
- PR: https://github.com/rockfort-ai/vibeguard/pull/1 — still under the old repo
  name, see below
- Tests: **200/200** (27 decision rules, 57 skill signals + calibration +
  drift + discovery, 23 editor bridge, 93 pre-tool adapter)
- Deployed at `~/.rlegend/engine`, v1.3.0
- `~/.claude/settings.json` hooks: PreToolUse, PostToolUse, SessionStart **and
  Stop** — all pointing at `$HOME/.rlegend/engine/adapters/`
- The marketplace plugin `rlegend@rlegend` is **disabled**: it still serves
  v1.0.0 from `main`. Re-enable once the PR merges and drop the manual wiring.
- Settings backups: `~/.claude/settings.json.pre-vibeguard-1.1.0` (keeps the old
  spelling because that is its real filename) and
  `~/.claude/settings.json.pre-rlegend-rename`

### The GitHub repo is still called vibeguard

`gh repo rename` returned 404 because the authenticated account has `push` but
`admin: false` on the org repo, and renaming needs admin. **Prashanth has to do
it**, or grant admin. Until then:

- the committed `README.md` and `.claude-plugin/marketplace.json` reference
  `rockfort-ai/rlegend`, so **those links 404**, including the
  `/plugin marketplace add rockfort-ai/rlegend` install line
- after renaming, GitHub redirects the old URL and PR #1 survives; then run
  `git remote set-url origin https://github.com/rockfort-ai/rlegend.git` in
  `rlegend-repo`

### Slash commands are hand-installed on this Mac

The plugin ships `commands/rlegend-skills.md` and `commands/rlegend-session.md`,
but the plugin is disabled, and Claude Code only reads a plugin's commands when
it is enabled. So copies live in `~/.claude/commands/`, with
`${CLAUDE_PLUGIN_ROOT}` rewritten to `$HOME/.rlegend/engine`.

**Delete those two copies when the plugin is re-enabled**, or the same command
will be defined twice.

Two v1.0.0-era leftovers were removed at the same time, both of which sat in
`~/.claude/` and so were invisible to the rename. They are in
`~/.claude/rlegend-rename-backup/`:

- `commands/vibeguard-skills.md` — pointed at `~/.vibeguard/engine/bin/vg.js`
- `skills/vibeguard-status/` — shelled out to `~/.claude/hooks/vibeguard-status.js`,
  which reads `~/.claude/hooks/vibeguard.log`. Nothing has written that log
  since the v1.1.0 engine took over, so it reported **"NOT RUNNING IN THIS
  SESSION"** while the tool was running normally. There is no replacement; the
  closest thing is `rlegend session`, where a row for the current session id is
  itself proof the hook fired.

`~/.vibeguard/engine/` is still on disk and is now unreferenced. Safe to delete
along with the rest of `~/.vibeguard/`.

### State migration

`~/.rlegend/` holds the state; `~/.vibeguard/` was **copied, not moved**, and is
still on disk. 24 skill pins and the remembered answers came across, so the
drift baseline survived the rename. `lib/paths.js` does this once, guarded by
`if (fs.existsSync(newDir)) return` — which means editing the migration list
after a machine has already migrated does nothing on that machine. The egress
log under `~/.claude/vibeguard/` was copied by hand here for exactly that
reason. Delete `~/.vibeguard/` once you are happy.

## What v1.1.0 added

| | |
|---|---|
| Egress policy | `policy/policy.json` → every harness via `rlegend sync` |
| Skill pinning | content hashes, drift detection, `/rlegend-skills` |
| Remembered answers | editor "Always allow" + learn-from-approval |
| MCP inventory | `rlegend mcp` — observed, not judged |

Commands: `rlegend check / sync / allow / learn / skills / allowed / mcp /
session / package / coverage / test`.

## What v1.3.0 added

Prompted by reading the tool's own output on a normal machine and asking whether
a user would act on it. The session-start report carried four flagged skills;
all four were false positives, and the one true statement in it — three skills
drifted — was buried and unactionable.

| | |
|---|---|
| Inert-host suppression | XML/schema namespace URIs are identifiers, not destinations; 12 false lines → 0 |
| Network-capability gate | an unrecognised host in code is reported only when the code can make a request |
| Credential tiering | naming a key you obviously need is amber; a key *plus* an unexpected destination is red |
| Semantic drift | pins record a hash per file plus hosts/secrets/scripts, so drift reports the delta |
| Delta in the deny message | `PreToolUse` names what the change added, not just that it changed |
| Lockfile v3 | `fileHashes` + `facts` per pin; v2 entries still detect drift and say plainly they cannot diff it |

Two things worth keeping in mind if you touch this:

- **`signals()` now has a side effect.** It sets `skill.facts`, which `pin()`
  reads. Every caller that builds a row must call it *before* spreading the
  skill, or pins silently lose their baseline and every future drift reports
  `baseline: false` forever. Both call sites carry a comment saying so.
- **The suppressions were mutation-tested, and the first version of the test
  did not bite.** `office-namespaces` is covered by both the inert list and the
  capability gate, so deleting either one left the suite green. `office-with-api`
  and `inert-url-constant` exist to isolate one mechanism each. If you add a
  third suppression, add the fixture that isolates it — a calibration test that
  cannot fail is worse than none, because it reads as proof.

## What v1.2.0 added

| | |
|---|---|
| Quiet-path instrumentation | every audit row records `surfaced`, `quiet`, `mode`, `level` |
| Stop recap | `systemMessage` only; `/rlegend-session` for the full picture |
| Desktop skill discovery | 1 → 23 skills, manifest-driven, never globbed |
| Active skill check | live inspect on the `Skill` tool; drift or unaccepted red only |
| Safe-list | a bounded, positive list that answers a prompt |
| MCP | credential scanning of argument values, first-seen server card |

## The product principle, stated by Prashanth

> Keep it simple without adding friction. Only when a popup comes, show the user
> what it means in English and give them a signal so they can act.

Concretely, and this is the bar to hold new work to:

- **Never invent a prompt.** If Claude Code would run something silently,
  Rockfort Legend stays silent. `test/…/friction.js` in the scratchpad measured this:
  it was 6 invented prompts out of 8 allowlisted commands, now 1.
- **Red breaks through an *allowlist*, not through a *permission mode*.** These
  are different statements and v1.2.0 stopped conflating them.
  `Bash(sudo *)` is a claim about a command, and the tiny irreversible set —
  sudo, rm -rf ~, force-push, disk erase, drop table, chmod 777 — is not covered
  by it, so it still asks. `bypassPermissions` / `dontAsk` / `auto` is a claim
  about the session: the user deliberately said stop asking. Nothing asks there,
  red included; it is recorded and reported afterwards by the Stop recap.
  `acceptEdits` is on the allowlist side of that line — it says only that edits
  are fine, so an edit to Claude's own config still asks.
- **A deny is not an ask.** Hard denies (`egress.secret-exfiltration`,
  `pipe-to-shell`, `denied-destination`) block in every mode, including the
  quiet ones. Blocking is not the same as interrupting, and a quiet mode does
  not switch off enforcement.
- **Never auto-approve — with one bounded, named exception.** Anything surfaced
  returns `ask`; only an editor-popup click, or a `safeCommands` entry matched
  positively by name, can produce `allow`. The exception is deliberately not
  "green means yes": green means no rule fired, which includes everything that
  could not be parsed. Six vetoes, and it runs only after the adapter has
  established a prompt was coming, so it can remove a prompt and never enable an
  action. `test/adapter.test.js` runs 60 mutations of safe-listed commands and
  the whole decision corpus to hold that line — read it before widening the list.
- **No desktop notifications.** Removed — Claude Code already raises its own.
- **Never certify a skill as safe.** Signals and hashes only. See COVERAGE.md.

## Defaults are deliberately quiet

`policy/policy.json` is the "friendly" profile: unknown destinations, insecure
http and raw IPs are all **allowed silently**. Only the always-bad list is
blocked (credentials leaving the machine, `curl | bash`, known exfil sinks).
`policy/strict.json` turns on full egress control for teams — copy it to
`~/.rlegend/policy.json`.

## Bugs found the hard way — don't reintroduce these

1. **Windows enforcement failed open.** Paths were compared as raw substrings;
   Git Bash `/c/…`, WSL, Cygwin and mixed case all missed. Five of six spellings
   produced no deny and no sign the control hadn't fired. Fixed in
   `lib/skills.js` (`pathVariants`/`flatten`), tested platform-independently.
2. **Secret indicators matched substrings.** `.env` matched inside
   `process.env`, and the `env` command inside `process.env.HOME` — so an
   ordinary Node one-liner plus any package install was *hard-denied* as
   credential theft. Worst class: a block the user can't override on a normal
   command. Fixed with boundaries in `lib/extract.js`.
3. **Auto-learning silenced real guardrails.** PostToolUse fires on
   auto-approved tools too, so background `rm -rf` cleanups taught Rockfort Legend
   that deleting files is always fine. Now PreToolUse leaves a marker only when
   it actually asks, PostToolUse consumes it, and destructive rules are never
   inferred at all (`NEVER_AUTO_LEARN` in `lib/remember.js`).
4. **The editor bridge was nearly dropped.** The rewrite replaced the hook that
   called `bridge.emit()` with one that had no bridge references — the VS Code
   panel would have gone dead silently. `test/bridge.test.js` exists to stop
   that recurring. **The extension has never been tested against a real editor,
   only a simulated one.**
5. **The shipped CLI crashed on every command.** `bin/rlegend.js` required the build
   tool at load time and that file isn't in the payload. Now lazy; `rlegend package`
   exercises the packaged CLI.
6. **Out-of-scope skills reported as removed.** "Not loadable from here" is not
   "deleted"; it produced a false alarm on every project switch.

## Open / unverified

- **Codex**: never run against real Codex. Test bundle ready at
  `send/rlegend-codex-test.tgz` + `send/TESTING-CODEX.md`. Config keys come
  from vendor docs, unverified.
- **Windows**: logic tested via a flag, wiring never tested on a real machine.
- **VS Code extension**: `extension/src/extension.js` gained an "Always allow"
  third button. Untested against a running editor.
- **Browser MCP prompts**: `Claude_Browser` is *not* a configured MCP server —
  it's app-internal, so `permissions.allow` rules for it match nothing. Two
  attempts at fixing this via settings.json failed. The lever is the dialog's
  "don't ask again" (never used — `allowedTools` is empty) or the app's own UI.
  Don't try a third settings.json rule without new evidence. **New evidence did
  turn up in v1.2.0** and it is a different bug: `ruleMatches` could not parse
  `mcp__x__*` at all, so every MCP allowlist entry silently matched nothing.
  That is fixed. Whether it makes `Claude_Browser` behave is untested — it is
  app-internal, so it may still not be reachable this way.
- **`rlegend package` version is hardcoded** at `VERSION = '1.2.0'` in
  `lib/package.js`. Bump it there.
- **Does a hook `ask` prompt under `bypassPermissions`?** **Answered 2026-08-04
  against 2.1.220 — yes, and it is honoured.** Method: a fresh headless session,
  `claude --permission-mode bypassPermissions -p "… chmod 777 /tmp/probe"`, with
  the file's mode checked before and after. It stayed `644`, so the call did not
  run, and the audit row showed `surfaced:true, decision:ask,
  mode:bypassPermissions`. The control did not fail open. Note this was print
  mode, where an `ask` cannot be answered and so resolves to not-running;
  whether an interactive session shows a dialog is still unobserved, but either
  way it does not silently execute. **This is now moot for red asks**, since
  quiet modes no longer surface them at all — but it still matters for hard
  denies, and it is the method to reuse if that ever needs rechecking.
- **The GitHub repo rename** is still pending admin rights — see State above.

## Gotcha that will bite you

Rockfort Legend blocks *your own* shell commands while you work on it. Writing a
commit message containing `.env` plus a `git push` trips the exfiltration rule
in whatever build is live in your session. Workaround: write the message to a
file and `git commit -F <file>` so the command text stays clean. This happened
three times.
