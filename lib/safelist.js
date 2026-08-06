'use strict';

// The one place Rockfort Legend answers a prompt on your behalf.
//
// Everything else in this codebase is built on "never auto-approve", and that
// stays true in the shape that matters: this does not approve because a verdict
// came back green. Green means *no rule fired*, which includes every command
// Rockfort Legend failed to parse — a base64 blob, an obfuscated one-liner, a syntax
// nobody anticipated. Auto-approving that is the direction that fails open, and
// a control that fails open is worse than no control because it is trusted.
//
// So this is a positive list. A command is answered only if it matches a named
// entry exactly, and any one of six independent vetoes stops it. The policy
// file supplies data in a fixed grammar and never a regex, because a regex from
// a repo's own .rlegend/policy.json would let that repo widen its own
// auto-approval.
//
// One more property, from where it sits in the adapter rather than from
// anything here: it runs only after Claude Code was already going to raise a
// prompt. It can remove a prompt. It can never enable an action that was not
// going to run.

const { secretReads } = require('./extract');

const MAX_LEN = 300;

// Anything that chains, redirects, substitutes or escapes. Deliberately not
// "split on separators and check each part" — that is how `git status; rm -rf ~`
// gets through a sloppy implementation. One command, no composition, or nothing.
//
// `\ ` is the one exception, and it is not a nicety: on macOS the directories
// people actually work in are called "Claude Code" and "Application Support",
// so a blanket backslash veto meant no path with a space in it could ever be
// answered. Every other use of a backslash is still refused — the escaped
// space is swapped out first, then this runs on what is left.
const ESCAPED_SPACE = /\\ /g;
const SPACE_HOLDER = '\u0000'; // cannot appear in a command line
const COMPOSITION = /[;|&><`$(){}\\\n\r]/;

// Flags that turn a reader into a writer or an evaluator, whatever the binary.
const DANGEROUS = new Set([
  '-o', '--output', '-T', '--upload-file', '-e', '--eval', '--exec', '--output-file',
]);

const FLAG = /^-{1,2}[A-Za-z][\w-]*$/;

// A relative path inside the project. No absolute paths, no home, no traversal.
function isRelPath(t) {
  if (!/^[\w.@/+ -]+$/.test(t)) return false;
  if (t.startsWith('/') || t.startsWith('~') || t.startsWith('-')) return false;
  return !t.split('/').includes('..');
}

// Returns { id } when the command is answerable, null otherwise.
//
// `v` and `ext` are the real verdict and extraction, not a re-derivation: the
// safe-list runs after decide(), never instead of it.
function match(tool, ti, ext, v, policy) {
  const cfg = (policy && policy.safeCommands) || {};
  if (cfg.enabled === false) return null;
  if (!Array.isArray(cfg.entries) || !cfg.entries.length) return null;

  // Veto 1: Bash only. No file-writing tool, no MCP call, no WebFetch.
  if (tool !== 'Bash') return null;

  // Veto 2: the engine must have had nothing to say. This is a filter on top of
  // the verdict, never a substitute for it.
  if (!v || v.level !== 'green' || v.decision !== 'allow') return null;

  // Veto 3: any destination at all, including allowlisted ones. "Safe" here
  // means local and boring; the moment a socket is involved it is neither.
  if (ext && Array.isArray(ext.destinations) && ext.destinations.length) return null;

  // Veto 4: the command-level flags extraction already computed.
  const flags = (ext && ext.flags) || {};
  if (flags.pipeToShell || flags.listener || flags.execFromDownload) return null;

  const cmd = String((ti && ti.command) || '');
  if (!cmd.trim() || cmd.length > MAX_LEN) return null;

  // Veto 5: composition. Escaped spaces are folded into a placeholder first so
  // "Claude\ Code" survives, then restored when the tokens are read back.
  const held = cmd.replace(ESCAPED_SPACE, SPACE_HOLDER);
  if (COMPOSITION.test(held)) return null;

  // Veto 6: credentials. Load-bearing rather than belt-and-braces — `cat .env`
  // is a green verdict, because readPath is only set for the Read tool and
  // never for Bash. Without this, a safe-listed `cat` would answer yes to
  // reading your credentials.
  if (secretReads(cmd, policy).length) return null;

  const tokens = held.trim().split(/\s+/).filter(Boolean)
    .map((t) => t.split(SPACE_HOLDER).join(' '));
  if (tokens.some((t) => DANGEROUS.has(t.split('=')[0]))) return null;

  for (const e of cfg.entries) {
    if (!e || typeof e.bin !== 'string') continue;
    // Exact first word. Not a path, not `env X=1 git`, not `\git`.
    if (tokens[0] !== e.bin) continue;

    let rest = tokens.slice(1);
    if (Array.isArray(e.sub) && e.sub.length) {
      if (!rest.length || !e.sub.includes(rest[0])) continue;
      rest = rest.slice(1);
    }

    const named = new Set([...(e.arg || []), ...(e.flagsOnly || [])]);
    // `flagsOnly` means exactly that: the entry opts out of accepting arbitrary
    // flags, so only the ones it names are allowed through.
    const genericFlags = !Array.isArray(e.flagsOnly);

    const ok = rest.every((t) => named.has(t)
      || (genericFlags && FLAG.test(t))
      || isRelPath(t));
    if (ok) return { id: e.id || e.bin };
  }
  return null;
}

// Layer merging, with deliberately asymmetric rules. Any layer may narrow the
// safe-list — remove entries, or switch it off entirely. Only the bundled
// policy and the user's own ~/.rlegend/policy.json may add to it, so a
// checked-out repo cannot hand itself new auto-approvals through the project
// layer or $RLEGEND_POLICY.
function mergeConfig(base, layer, trusted) {
  if (!layer) return base;
  const out = {
    enabled: base ? base.enabled !== false : true,
    entries: [...((base && base.entries) || [])],
  };

  if (layer.enabled === false) out.enabled = false;
  else if (layer.enabled === true && trusted) out.enabled = true;

  if (Array.isArray(layer.remove)) {
    const drop = new Set(layer.remove.map(String));
    out.entries = out.entries.filter((e) => !drop.has(e.id) && !drop.has(e.bin));
  }

  if (trusted && Array.isArray(layer.entries)) {
    const byId = new Map(out.entries.map((e) => [e.id || e.bin, e]));
    for (const e of layer.entries) {
      if (e && typeof e.bin === 'string') byId.set(e.id || e.bin, e);
    }
    out.entries = [...byId.values()];
  }

  return out;
}

module.exports = { match, mergeConfig, COMPOSITION, MAX_LEN };
