<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/bastion-paper.svg">
    <img src="assets/bastion-ink.svg" alt="Rockfort AI" width="60">
  </picture>
</p>

<h1 align="center">VibeGuard</h1>

<p align="center">
  <b>Know what Claude Code is about to do — before you approve it.</b>
</p>

<p align="center">
  <a href="https://rockfort.ai">A Rockfort AI product</a>
  &nbsp;·&nbsp;
  <a href="#install-in-30-seconds">Install</a>
  &nbsp;·&nbsp;
  <a href="#what-the-colours-mean">The colours</a>
  &nbsp;·&nbsp;
  <a href="#it-also-watches-the-skills-you-install">Skills</a>
  &nbsp;·&nbsp;
  <a href="plugins/vibeguard/README.md">How it works</a>
</p>

---

## The problem

Claude Code asks before it does anything to your computer. Good. But the question looks like this:

```
Bash(rm -rf ./src)
```

If you're not a developer, that isn't a question you can answer. So most people click **Approve** and hope for the best.

## What VibeGuard does

It adds one line of plain English, and a colour, to every prompt:

```
🟢 SAFE · Only reads or lists files. Changes nothing. → OK to approve.

🟠 CHECK FIRST · Deletes files for good. There is no Trash here. → Check the file names above first.

🔴 HIGH RISK · Gives full administrator power over your Mac. → If you did not ask for this, click Deny.
```

Now it's a question you can answer.

And for the small number of things that are **never** okay — your passwords being sent to a stranger's website, a script downloaded off the internet and run without being read — it doesn't ask. It just says no.

```
🔴 HIGH RISK · Reads your credentials file (.env) and sends it to webhook.site.
               This is how credentials leak. → Blocked.
```

That's the whole product. It stays quiet the rest of the time.

---

## Install in 30 seconds

You don't need a terminal, and you don't need to know what any of this does.

### Step 1 — Copy this line

```
/plugin marketplace add rockfort-ai/vibeguard
```

Paste it into Claude Code, press **Enter**.

### Step 2 — Copy this line

```
/plugin install vibeguard@vibeguard
```

Paste it in, press **Enter**. Claude Code will ask you to confirm — say yes.

### That's it. You're done.

From now on, every time Claude Code asks permission for something, you'll see a colour and a plain-English explanation with it. Nothing else changes.

> **Want to check it's working?** Ask Claude to do something ordinary, like installing a package. You should see an 🟠 orange line in the prompt.

<details>
<summary><b>Requirements</b></summary>

Claude Code, and Node.js — which you already have if you installed Claude Code with npm. Nothing else to install; VibeGuard has zero dependencies.

macOS, Linux and Windows all behave identically — there is no platform-specific behaviour left in it.
</details>

<details>
<summary><b>Uninstalling</b></summary>

```
/plugin uninstall vibeguard@vibeguard
```
</details>

---

## What the colours mean

| | Meaning | Examples |
|---|---|---|
| 🟢 | **Safe.** Nothing is lost, nothing leaves your computer. | Reading files, running tests, checking project status, ordinary edits |
| 🟠 | **Check this first.** Real, but usually fine — read the command before you approve. | Deleting files, installing packages, publishing code, sending data to a website |
| 🔴 | **High risk.** Stop and read. If you didn't ask for this, deny it. | Administrator access, running scripts straight off the internet, erasing a disk, touching your passwords or keys |

Red items always ask, even if you've told Claude Code to stop asking about that kind of command. That list is short and hard to undo — administrator access, force-pushing over your history, erasing a disk — and "I allowlisted terminal commands" shouldn't quietly include them.

**Everything else defers to you.** If you've already told Claude Code something is fine, VibeGuard doesn't second-guess it. It explains the prompts you were going to see anyway, and adds no new ones. There is no desktop notification: Claude Code already raises one when it needs an answer, and a second banner for the same decision is just noise.

---

## The things it stops without asking

There is a short list where "are you sure?" is the wrong question, because the answer is always no. VibeGuard blocks these outright:

| | |
|---|---|
| **Your secrets leaving the machine** | Anything that reads a password file, key, or token *and* sends it somewhere in the same breath |
| **Scripts run straight off the internet** | The `curl … \| bash` pattern — code that runs before anyone, including you, has read it |
| **Known drop-off points** | The specific sites used to collect stolen data — paste bins, webhook catchers, anonymous file drops |

This list is deliberately tiny. Everything else it explains and lets you decide.

---

## It also watches the skills you install

Claude Code can install **skills** — small bundles of instructions written by other people. They're useful, and they're also unreviewed code running with your agent's permissions.

VibeGuard takes a fingerprint of every skill on your machine the first time it sees it. If one of them **changes later**, you get told, and you're asked before anything from it runs.

That matters because of a specific trick: publish something helpful, wait for people to install it, then quietly change it. Nothing re-checks a skill after you've said yes to it once. This does.

Run **`/vibeguard-skills`** in Claude Code any time to see what's installed and whether anything has changed.

> VibeGuard reports what it finds. It never tells you a skill is "safe" — nobody can honestly promise that, and the scanners that do have been [publicly bypassed](plugins/vibeguard/COVERAGE.md).

---

## Optional: see it in your editor

If you use **VS Code** or **Cursor**, there's a companion extension. The prompt inside Claude Code is limited to a single line — the extension isn't, so you get the full explanation, the command in full, and a running list of everything Claude has asked for.

You can also turn on **Approve / Deny buttons** and answer the prompt from the popup.

→ [Set up the editor extension](extension/README.md)

---

## What VibeGuard doesn't do

Worth being explicit, since it's a security tool:

- It **never sends anything anywhere.** No servers, no analytics, no network requests at all. The one file it writes is a local log you can delete.
- It **never runs commands.** It reads what Claude Code is proposing, describes it, and sometimes says no.
- It has **zero dependencies** — nothing gets pulled in from the internet.
- It **can't make Claude Code less safe.** It only ever adds explanation, asks about something that would otherwise have been silent, or blocks something outright. It cannot approve anything on your behalf.
- It **doesn't judge your skills for you.** It reports what it sees and tells you when something changed. It never claims a skill is safe.

It's plain JavaScript with no build step, and you're welcome to read it — [`lib/decide.js`](plugins/vibeguard/lib/decide.js) holds every rule, in order.

---

## For developers

- [**How it works**](plugins/vibeguard/README.md) — the decision engine, why it stays quiet on auto-run, and how to add a rule
- [**What is actually enforceable**](plugins/vibeguard/COVERAGE.md) — the honest per-tool matrix, including what VibeGuard *cannot* do and where published scanners have been bypassed
- [**Editor extension**](extension/README.md) — the popup, the panel, and the approve/deny protocol

```sh
git clone https://github.com/rockfort-ai/vibeguard.git
cd vibeguard/plugins/vibeguard
node bin/vg.js test        # decision rules, skill signals, editor bridge
```

Adding a rule is one regex and one plain-English sentence in [`lib/decide.js`](plugins/vibeguard/lib/decide.js). The Claude Code prompt and the editor popup render from the same rule, so you write it once.

Contributions welcome — especially new rules. The bar for the wording is: **would this make sense to someone who has never opened a terminal?**

<details>
<summary><b>Turning on strict mode</b> — for teams and the security-minded</summary>

By default VibeGuard is quiet: it blocks the always-bad list and explains the rest. If you want it to also question every network destination it doesn't recognise, and to hard-block skills that changed rather than asking:

```sh
mkdir -p ~/.vibeguard
cp plugins/vibeguard/policy/strict.json ~/.vibeguard/policy.json
```

This is the profile intended for managed deployments, where an administrator pushes the policy and developers can't widen it. The same policy file compiles into Cursor, Codex, and a plain HTTP proxy:

```sh
node bin/vg.js sync --target all
```

Details and the honest limits are in [COVERAGE.md](plugins/vibeguard/COVERAGE.md).
</details>

---

## About Rockfort AI

[Rockfort AI](https://rockfort.ai) builds security tooling for a world where AI writes the code.

VibeGuard is our smallest product and our most opinionated one. AI coding assistants gave millions of people the ability to build software without learning what `sudo` means — and then kept asking them to approve `sudo`. This closes that gap.

---

<p align="center">
  <sub>MIT licensed · Built by <a href="https://rockfort.ai">Rockfort AI</a></sub>
</p>
