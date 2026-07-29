# VibeGuard

Plain-English explanations and severity ratings for Claude Code permission
prompts, so non-technical users understand what they're approving.

```
🟢 SAFE · Only reads or lists files. Changes nothing. → OK to approve.
🟠 CHECK FIRST · Deletes files for good. There is no Trash here. → Check the file names above first.
🔴 HIGH RISK · Gives full administrator power over your Mac. → If you did not ask for this, click Deny.
```

Two pieces, usable together or apart:

| | What it is | Install |
|---|---|---|
| [`plugins/vibeguard`](plugins/vibeguard) | Claude Code plugin. A `PreToolUse` hook that writes the card into the permission dialog. | `/plugin marketplace add prashanthnanand/vibeguard` |
| [`extension`](extension) | VS Code / Cursor extension. Shows the same verdict as a real popup, with the command in full and optional Approve/Deny buttons. | `code --install-extension vibeguard-1.0.0.vsix` |

The plugin works on its own. The extension needs the plugin, because the plugin
is what does the classifying.

## Install the plugin

```sh
/plugin marketplace add prashanthnanand/vibeguard
/plugin install vibeguard@vibeguard
```

That is all. No dependencies, no build step — it is plain Node, which you
already have if you're running Claude Code.

> **Migrating from the hand-installed version?** Remove the `hooks` block from
> `~/.claude/settings.json` first, and delete `~/.claude/hooks/vibeguard.js`.
> Leaving both in place runs the classifier twice and shows the card twice.

To confirm it works:

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"}}' \
  | node plugins/vibeguard/hooks/vibeguard.js
```

Empty output means green (nothing worth saying). See
[plugins/vibeguard/README.md](plugins/vibeguard/README.md) for how the
classifier decides, and why it stays quiet most of the time.

## Install the extension

No published Marketplace listing yet, so build the `.vsix` locally:

```sh
cd extension
npm run package
code --install-extension vibeguard-1.0.0.vsix     # VS Code
cursor --install-extension vibeguard-1.0.0.vsix   # Cursor
```

Cursor is a VS Code fork, so the same `.vsix` serves both.

## How the two halves talk

The hook classifies, then appends the verdict to `~/.vibeguard/events.jsonl`
(mode 0600, in a 0700 directory — the log contains command lines and file
paths). The extension tails that file.

It is deliberately a file and not a socket: nothing to negotiate, nothing to
clean up, and it does not matter which of the two starts first.

```
Claude Code ──PreToolUse──▶ vibeguard.js ──▶ permission dialog (one line)
                                 │
                                 └──▶ ~/.vibeguard/events.jsonl
                                                │
                                       extension tails it ──▶ popup + panel
```

### Letting the editor answer the prompt

By default the extension only explains; you still answer in Claude Code. Set
`VIBEGUARD_INTERACTIVE=1` and the popup gets working Approve and Deny buttons,
answering the prompt directly.

The hook only ever waits when the extension has written a heartbeat in the last
30 seconds, and never for longer than 12 seconds. If you dismiss the popup,
close the editor, or nothing answers, it falls back to the ordinary Claude Code
prompt. **No answer is never treated as approval.**

## Development

```sh
node plugins/vibeguard/test/run.js   # classifier tests, no dependencies
```

To work on the extension, open `extension/` in VS Code and press F5.

Adding a rule means adding one regex and one plain-English sentence to
`BASH_RULES` or `classifyFileChange` in
[plugins/vibeguard/lib/classify.js](plugins/vibeguard/lib/classify.js). Both the
dialog card and the editor popup are rendered from the same rule, so you only
write it once.

## Licence

MIT
