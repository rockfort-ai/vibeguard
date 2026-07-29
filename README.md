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

macOS and Linux are fully supported. On Windows everything works except the desktop notification for high-risk items.
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

Red items always ask, even if you've told Claude Code to stop asking about that kind of command — and they also raise a desktop notification, so you'll catch them when you're looking somewhere else.

Everything Claude Code would run silently on its own stays silent. VibeGuard adds explanations to prompts you were already going to see; it never creates new ones.

---

## Optional: see it in your editor

If you use **VS Code** or **Cursor**, there's a companion extension. The prompt inside Claude Code is limited to a single line — the extension isn't, so you get the full explanation, the command in full, and a running list of everything Claude has asked for.

You can also turn on **Approve / Deny buttons** and answer the prompt from the popup.

→ [Set up the editor extension](extension/README.md)

---

## What VibeGuard doesn't do

Worth being explicit, since it's a security tool:

- It **never sends anything anywhere.** No servers, no analytics, no network requests at all.
- It **never runs commands.** It only reads what Claude Code is proposing and describes it.
- It has **zero dependencies** — nothing gets pulled in from the internet.
- It **can't make Claude Code less safe.** It only ever adds explanation to a prompt, or asks you about something that would otherwise have been silent.

The whole thing is about 400 lines of plain JavaScript, and you're welcome to read it: [`lib/classify.js`](plugins/vibeguard/lib/classify.js) holds every rule.

---

## For developers

- [**How the classifier works**](plugins/vibeguard/README.md) — why it stays quiet on auto-run, how the rules are structured, and how to add your own
- [**Editor extension**](extension/README.md) — the popup, the panel, and the interactive approve/deny protocol

```sh
git clone https://github.com/rockfort-ai/vibeguard.git
cd vibeguard
node plugins/vibeguard/test/run.js
```

Adding a rule is one regex and one plain-English sentence in [`plugins/vibeguard/lib/classify.js`](plugins/vibeguard/lib/classify.js). Both the Claude Code prompt and the editor popup render from the same rule, so you only write it once.

Contributions welcome — especially new rules. The bar for the wording is: **would this make sense to someone who has never opened a terminal?**

---

## About Rockfort AI

[Rockfort AI](https://rockfort.ai) builds security tooling for a world where AI writes the code.

VibeGuard is our smallest product and our most opinionated one. AI coding assistants gave millions of people the ability to build software without learning what `sudo` means — and then kept asking them to approve `sudo`. This closes that gap.

---

<p align="center">
  <sub>MIT licensed · Built by <a href="https://rockfort.ai">Rockfort AI</a></sub>
</p>
