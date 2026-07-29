# VibeGuard for VS Code and Cursor

Shows what Claude Code is about to do, in plain English, in a real popup —
before you approve it.

A [Rockfort AI](https://rockfort.ai) product · [← Back to the main README](../README.md)

Requires the [VibeGuard Claude Code plugin](../plugins/vibeguard), which does
the classifying. This extension displays the result. Install that first —
two lines, [here](../README.md#install-in-30-seconds).

## Why it exists

The Claude Code permission dialog is a single line with no formatting. That is
the wrong place to explain risk to someone who isn't a developer. Here the same
verdict gets:

- a real popup, coloured by severity
- two lines instead of one — what the action does, and what you should do
- the full command or file path, in a monospace block
- a running panel of everything Claude has asked for this session
- optionally, working **Approve** and **Deny** buttons

## Install

```sh
cd extension
npm run package
code --install-extension vibeguard-1.0.0.vsix     # VS Code
cursor --install-extension vibeguard-1.0.0.vsix   # Cursor
```

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `vibeguard.popupOn` | `orangeAndRed` | Which levels raise a popup. `all`, `orangeAndRed`, `red`, `off`. |
| `vibeguard.revealPanelOn` | `red` | Which levels auto-open the panel. |
| `vibeguard.statusBar` | `true` | Show the status bar indicator. |

## Commands

- **VibeGuard: Show recent activity** — open the panel
- **VibeGuard: Clear history**
- **VibeGuard: Check connection to Claude Code** — confirms verdicts are arriving

## Approving and denying from the editor

By default the extension explains and you still answer in Claude Code.

To answer from the popup instead, run Claude Code with
`VIBEGUARD_INTERACTIVE=1`. The hook then waits for your click and applies it.

The safety properties matter here, so to be explicit:

- The hook only waits if this extension wrote a heartbeat in the last 30s.
- It never waits longer than 12s.
- Dismissing the popup, or quitting the editor mid-prompt, writes nothing — the
  ordinary Claude Code prompt comes back.
- **Silence is never approval.** Only an explicit click on Approve approves.

## How it receives verdicts

It tails `~/.vibeguard/events.jsonl`, written by the hook. It never runs
commands, never reads your project, and makes no network requests — it only
reads that one file and writes small decision files next to it.

Restarting the editor loads past events into the panel without re-popping them.
