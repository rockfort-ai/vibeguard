---
description: Inventory every Claude skill that can load in this session, flag content drift and risk signals.
allowed-tools: Bash(node:*)
---

Run the skill audit and show the user its output verbatim in a code block:

```bash
node "${CLAUDE_PLUGIN_ROOT}/bin/vg.js" skills
```

Then, briefly:

- If any skill is marked **CHANGED**, say so first. It means the skill's files
  differ from what was pinned — the case an install-time scan cannot catch.
- Report the signal lines as written. Do not summarise them away, and do not
  translate them into a safety verdict: VibeGuard reports signals and hashes, it
  never certifies a skill as safe.
- If nothing is flagged, one line is enough.

To accept a skill's current contents: `vg skills pin <id>`. To also accept the
signals it trips: `vg skills pin <id> --accept-risk`.
