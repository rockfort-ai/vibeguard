# Coverage: what is actually enforceable, per harness

Written to be shown to a security buyer without embarrassment. "Enforce" means
the agent physically cannot make the request. "Detect" means we see it and can
alert, but something else has to stop it. "None" means neither.

| Harness | Desktop | Cloud / hosted | Enforcement point | Strength |
|---|---|---|---|---|
| **Claude Code** | ✅ enforce | ✅ enforce | `PreToolUse` hook returning `deny`, plus OS sandbox `network.allowedDomains` | **Strong.** Hook blocks the call before it runs; the sandbox proxy enforces domains at the OS level for Bash and every child process. `managed-settings.json` + `allowManagedDomainsOnly` stops developers widening it. |
| **Cursor (local agent)** | ✅ enforce | — | `.cursor/hooks.json` → `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` | **Medium.** `deny` works. Do not rely on hook `allow`/`ask` — Cursor's own command allow-list has been reported to take precedence. Blocker only. |
| **Cursor Cloud Agents** | — | ⚠️ partial | Team **Network Access Policy** (domain allowlist, admin-lockable) + repo-committed `.cursor/hooks.json` | **Medium.** The allowlist is enforced by Cursor's infrastructure, not by us — we generate the domain list. Whether repo hooks execute in the hosted runner is version-dependent; verify per release before claiming it. |
| **Codex CLI** | ✅ enforce | ✅ enforce | `[features.network_proxy] domains` + `sandbox_workspace_write.network_access` | **Strong but static.** Unlisted domains are denied, deny beats allow. No pre-tool hook exists, so policy must be compiled ahead of time — no runtime judgement, no plain-English card. Precedence: MDM > `managed_config.toml` > `~/.codex/config.toml` > project `.codex/config.toml`. |
| **Devin** | — | ❌ none in-band | Vendor console allowlist; otherwise egress proxy in front of a self-hosted runner | **Weak.** No hook API. On managed hosting you are limited to whatever the vendor's console exposes. Self-hosted runner + your own proxy is the only real control, and that is exactly the "partial solution" the ask names. |
| **Anything else** | ⚠️ | ⚠️ | `rlegend sync --target proxy` → Squid/mitm config | Enforcement moves to the network. Works everywhere, sees nothing above L4/L7 unless you terminate TLS. |

## The honest summary

For third-party hosted cloud agents there is no hook to hang policy on. What
exists instead is three weaker levers, and a product should say so plainly:

1. **Repo-committed config.** `.claude/settings.json`, `.cursor/hooks.json`,
   `.codex/config.toml` travel with the checkout, so a hosted runner picks them
   up when it clones. This is the closest thing to a hook on a machine you do
   not own. It is also trivially editable by the agent itself, which is why the
   `local.edit-agent-config` rule exists.
2. **Vendor allowlist APIs/consoles.** Real enforcement, coarse granularity,
   different shape per vendor. `rlegend sync --target vendor` emits the flat domain
   list these boxes want.
3. **Credential scope.** The control that survives everything else: if the
   token in the runner cannot reach production, the egress question matters
   less. Not a network control, but the one that actually holds.

## Known bypasses — do not oversell this

- **Domain fronting / SNI mismatch.** Any allowlist that decides on the
  client-supplied hostname without terminating TLS can be walked around.
  Claude Code's built-in proxy says this in its own docs. TLS termination is
  required for a real guarantee.
- **Broad allowlist entries are exfil paths.** `github.com` on the allowlist
  means gists, issues, and repo pushes are all valid data-drop destinations.
  Class-level allowlisting trades precision for usability; be explicit about it.
- **Path-scoped deny rules flatten on compile.** The hooks can deny
  `discord.com/api/webhooks` and leave the rest of Discord alone. Proxy and
  vendor allowlists are host-only, so `rlegend sync` widens that rule to the whole
  host. The runtime layer is more precise than the compiled layer; check the
  generated file before shipping it.
- **Shell obfuscation.** `$(echo aHR0cHM6...| base64 -d)` defeats static
  destination extraction. Runtime proxy enforcement does not care; hook-level
  parsing does. Layer both.
- **MCP servers.** An MCP server is its own egress path with its own network
  stack. `beforeMCPExecution` sees the arguments, not the server's outbound
  traffic. Two things are checked, and neither is enforcement of egress: a URL
  in the arguments is classified like any other destination, and a credential
  indicator in an argument *value* raises `mcp.secret-argument` — an ask, not a
  block, because the destination is the server itself and there is nothing to
  name. First use of a server on a machine is reported once. What the server
  does after that is invisible, and no amount of argument inspection changes
  that. Do not sell this as MCP egress control.
- **Sub-agents and background tasks.** Verify per harness that hooks fire for
  nested agent turns, not just top-level ones.

## Skills: what `rlegend skills` does and does not claim

We do not tell you a skill is safe, and you should distrust any vendor who
does. In June 2026 Trail of Bits bypassed the skill scanners behind ClawHub
(VirusTotal Code Insight), Cisco AI Defense, and Vercel's skills.sh (Socket,
Snyk). Three of the four malicious skills took under an hour to build. Socket
raised nothing above Medium under any tested condition; Snyk downgraded its
findings once obfuscation was applied. The techniques that worked were
whitespace inflation past the scanner's context window, payloads in precompiled
`.pyc`, instructions buried in DOCX structure, and prompt injection aimed at
the scanner's own LLM judge.

An install-time verdict, computed once, over text the author controls, is not a
security boundary. So the split here is deliberate:

| Capability | Strength | Mechanism |
|---|---|---|
| **Inventory** — which skills are loadable right now | ✅ reliable | Reads `~/.claude/skills`, the project's `.claude/skills`, and `installPath` from `installed_plugins.json`. Not the marketplace clones, which are catalogue, not code in your context. |
| **Drift** — a pinned skill's bytes changed | ✅ **enforce** | SHA-256 over sorted (path, content) pairs including symlink targets, held in `~/.rlegend/skills.lock.json`. This is the case install-time scanning structurally cannot catch: ship clean, get approved, mutate at v1.4. Nothing rescans on update. |
| **Execution out of a drifted skill** | ✅ **enforce** | `PreToolUse` deny, checked before the allowlist — an approved `Bash(python:*)` does not waive it, and it holds under `bypassPermissions`. |
| **Risk signals** — `.pyc`, symlink escape, hidden Unicode, whitespace inflation, credential references, blocked destinations, self-granting config writes | ⚠️ **detect only** | Reported at session start, with the matched text quoted so you can judge it yourself. Best-effort pattern matching. Assume a competent author can evade every one of them. |
| **"Is this skill safe?"** | ❌ **not offered** | No such verdict exists. `rlegend skills` prints signals and a hash, never a grade. |

Honest limits on top of that:

- **`SessionStart` cannot block.** The docs are explicit that it is
  context-only — no `permissionDecision`, no deny. It reports; `claude-code.js`
  enforces off the state file it writes. Detection and enforcement are separate
  events, and a report is not a control.
- **Trust-on-first-use.** The first run pins whatever is already on disk rather
  than flagging all of it. If a skill was already malicious before Rockfort Legend
  was installed, it gets pinned as the baseline. Drift tells you something
  *changed*, never that what you started with was clean.
- **Windows was failing open until 2026-07-30.** The guard compared a
  `path.join`-shaped directory against raw command text. On macOS and Linux
  there is one spelling of a path, so it worked. On Windows there are at least
  six — native backslash, forward slash, Git Bash `/c/…`, WSL `/mnt/c/…`,
  Cygwin `/cygdrive/c/…`, and any casing — and five of them silently missed,
  producing no deny and no indication the control had not fired. All six are
  now generated and compared, with a test that runs on every platform because
  the Windows behaviour is driven by a flag rather than by the host. Worth
  stating plainly to a buyer: a control that fails open on one OS is worse than
  no control, because it is trusted.
- **Hashes are normalised for portability, not byte-exactness.** Path
  separators and CRLF/LF in text files are canonicalised, so the same skill
  hashes identically on every platform and a lockfile can be committed and
  compared across a team. The cost is that a pure line-ending change is
  invisible to drift. Binary files are hashed byte-exact.
- **There are no desktop notifications.** There were, on macOS only, and they
  were removed: Claude Code already raises its own OS notification when it needs
  permission, so a second banner was two alerts for one decision on a dialog the
  user was already looking at. The plain-English card inside the permission
  dialog is the control, and it is the same on every platform.
- **Signals on prose are ambiguous and always will be.** The first version of
  the injection rules flagged Rockfort Legend's own status skill, for telling the
  agent "do not tell the user their actions were safe just because no cards
  appeared" — a safety instruction that pattern-matches as concealment.
  Concealment phrasing is therefore amber, not red, everywhere except the
  always-loaded `description` field. Anyone claiming a clean false-positive
  rate on natural language is selling you something.
