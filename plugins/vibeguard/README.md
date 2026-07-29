# VibeGuard (Claude Code plugin)

Plain-English explanations + severity ratings for Claude Code permission prompts,
so non-technical users understand what they're approving.

## Install

```sh
/plugin marketplace add prashanthnanand/vibeguard
/plugin install vibeguard@vibeguard
```

## How it works

`hooks/vibeguard.js` runs as a **PreToolUse hook**, wired up by
`hooks/hooks.json`. Before Claude runs a command, edits a file, or fetches a
URL, the script inspects the action and classifies it:

Actions Claude auto-runs stay silent. When Claude asks for permission, the
prompt carries a one-line card:

```
🟢 SAFE · Only reads or lists files. Changes nothing. → OK to approve.
🟠 CHECK FIRST · Deletes files for good. There is no Trash here. → Check the file names above first.
🔴 HIGH RISK · Gives full administrator power over your Mac. → If you did not ask for this, click Deny.
```

| Level | Meaning |
|-------|---------|
| 🟢 Safe to approve | Reading files, running tests, `git status`, normal project edits |
| 🟠 Check this first | Deleting files, installing packages, `git push`, changing permissions, sending data to the internet, unrecognised tools |
| 🔴 High risk | sudo, `curl \| sh`, force-push, editing `.env` or `~/.ssh`, disk-level commands, DROP TABLE. Always prompts even if allowlisted, and fires a desktop notification banner with sound |

## Two implementation details that matter

**Only `PreToolUse` can write into the permission dialog.** It does so via
`hookSpecificOutput.permissionDecisionReason`. `PermissionRequest` hooks
cannot, and `systemMessage` renders outside the dialog, so both are unused
here. One hook, matcher `"*"`, handles everything.

**The dialog strips all line breaks.** Neither `\n` nor `\n\n` survives, so
multi-line layouts are impossible. The card is therefore designed as one
line, using `·` and `→` as separators and keeping each message to roughly
one short sentence. Adding a long message here does not wrap nicely, so
keep new rules terse.

(The [editor extension](../../extension) exists mostly to escape that second
constraint. It renders the same verdict with room to breathe.)

## Staying quiet on auto-run

A `PreToolUse` hook fires before Claude Code decides whether to prompt, so
the script has to work out for itself whether a prompt was coming. It must
never invent one, because that turns a silent auto-run into a nag.

The rule is: **only speak up for tools Claude Code documents as always
needing approval.** Anything else stays silent rather than guessing.

`PROMPTING_TOOLS` is that list, and it is documentation-backed, not
guesswork:

| Source | What it establishes |
|--------|--------------------|
| [permissions](https://code.claude.com/docs/en/permissions) | File modification always prompts. Bash prompts except a built-in read-only set (`ls`, `cat`, `echo`, `pwd`, `head`, `tail`, `grep`, `find`, `wc`, `which`, `diff`, `stat`, `du`, `cd`, read-only `git`). Read-only file access does not prompt inside the working directory. |
| [security](https://code.claude.com/docs/en/security) | Tools making network requests (`WebFetch`, `WebSearch`) require approval by default. |

MCP tools (`mcp__*`) are included too, since they are not auto-approved
without an explicit rule.

On top of that, the script skips anything matching `permissions.allow` in
your user or project settings, honours `permission_mode` (`acceptEdits`,
`bypassPermissions`, and similar), and treats the documented read-only Bash
commands as silent.

Red ignores every one of these checks and always prompts.

**Do not add a tool to `PROMPTING_TOOLS` on a hunch.** If it turns out not to
prompt by default, VibeGuard starts manufacturing permission prompts that
would never otherwise have appeared. Confirm in the docs first.

## Files

- `lib/classify.js` — the classifier. Pure, no I/O, no dependencies. Rules live here.
- `lib/bridge.js` — writes verdicts to `~/.vibeguard/` for the editor extension.
- `hooks/vibeguard.js` — the hook entry point: allowlist checks, notifications, output.
- `hooks/hooks.json` — the `PreToolUse` registration.
- `test/run.js` — classifier tests.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `VIBEGUARD_NOTIFY` | on | Set to `0` to suppress desktop notifications for red items. |
| `VIBEGUARD_INTERACTIVE` | off | Set to `1` to let the editor extension's popup answer prompts directly. |
| `VIBEGUARD_TIMEOUT_MS` | `12000` | How long to wait for that answer before falling back to a normal prompt. |

## Testing / tweaking

```sh
node test/run.js
```

Or pipe a sample payload in:

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"}}' | node hooks/vibeguard.js
```

Empty output = the action would have auto-run, so VibeGuard said nothing. Add
or edit rules in `BASH_RULES` / `classifyFileChange` in `lib/classify.js` —
each rule is a regex plus a plain-English message.

To disable: `/plugin uninstall vibeguard@vibeguard`.

## Roadmap ideas

1. ~~Package as a shareable Claude Code **plugin** (marketplace-installable)~~ ✅
2. Fallback AI explanation (fast Haiku call) for commands no rule recognizes
3. ~~VS Code / Cursor extension with a real popup UI~~ ✅
4. ~~Native macOS notification for red items when the terminal isn't focused~~ ✅
5. Windows notification support (`notify.ps1` / BurntToast)
