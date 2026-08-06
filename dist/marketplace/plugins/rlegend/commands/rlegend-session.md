---
description: Show every tool call Rockfort Legend judged this session, and which ones it stayed quiet about and why.
allowed-tools: Bash(node:*)
---

Show the user this output verbatim in a code block:

```bash
node "${CLAUDE_PLUGIN_ROOT}/bin/rlegend.js" session
```

Then, briefly:

- Lead with the "elevated action(s) ran without a prompt" block if there is one.
  Those are calls the user was never asked about — in an auto-accept mode
  Rockfort Legend is told to stay quiet, so it records instead of interrupting.
- The `quiet(...)` column is the reason nothing was shown. `mode:*` means a
  permission mode silenced it, `allow-rule:*` means a rule in settings.json did,
  `safe-list:*` means Rockfort Legend answered it, `remembered:*` means the user
  already said yes once.
- If skills were invoked, repeat the attribution caveat as written. Rockfort Legend
  sees tool calls and not their origin; do not tell the user a skill "ran" a
  command.
- Do not translate any of this into a safety verdict.
