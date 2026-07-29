'use strict';

// Pure classification. No I/O, no side effects, no dependencies.
//
// Every rule is a regex plus a plain-English message written for someone who
// is not a developer. Two fields carry the whole card:
//
//   msg    — what this action actually does
//   action — what the person should do about it
//
// The Claude Code permission dialog renders these joined on one line. The
// editor extension renders them as two lines. Same data, both places, so a
// new rule only has to be written once.

const LEVELS = { green: 0, orange: 1, red: 2 };

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

// Tools Claude Code documents as always needing approval. We only speak up for
// these, so VibeGuard can never invent a prompt that would not have happened on
// its own. Anything not listed here stays silent rather than guessing. MCP
// tools (mcp__*) are handled separately by the caller.
//
// Sources: code.claude.com/docs/en/permissions ("file modification: Yes",
// "Bash commands: Yes, except a built-in set of read-only commands") and
// /docs/en/security ("Tools that make network requests require user approval
// by default").
const PROMPTING_TOOLS = new Set([
  'Bash', 'PowerShell',
  'Edit', 'Write', 'MultiEdit', 'NotebookEdit',
  'WebFetch', 'WebSearch',
]);

const EDIT_TOOLS = /^(Write|Edit|MultiEdit|NotebookEdit)$/;

// Claude Code runs a built-in set of read-only commands without prompting, in
// every mode. Listed at /docs/en/permissions#read-only-commands.
const READ_ONLY_CMDS = new Set([
  'ls', 'cat', 'echo', 'pwd', 'head', 'tail', 'grep', 'find',
  'wc', 'which', 'diff', 'stat', 'du', 'cd',
]);
const READ_ONLY_GIT = new Set([
  'status', 'log', 'diff', 'show', 'branch', 'remote', 'blame', 'describe',
]);

function isPromptingTool(tool) {
  return PROMPTING_TOOLS.has(tool) || tool.startsWith('mcp__');
}

function isReadOnlyBash(cmd) {
  if (!cmd.trim()) return false;
  // A redirect writes somewhere, so it is not read-only.
  if (/>|>>/.test(cmd)) return false;
  const parts = cmd.split(/&&|\|\||;|\|/);
  return parts.every((part) => {
    const words = part.trim().split(/\s+/).filter(Boolean);
    if (!words.length) return false;
    const [name, sub] = words;
    if (name === 'git') return READ_ONLY_GIT.has(sub);
    return READ_ONLY_CMDS.has(name);
  });
}

// ---------------------------------------------------------------------------
// Bash commands
// ---------------------------------------------------------------------------

const ROUTINE_DELETE = /(node_modules|dist\b|build\b|\.next|\.cache|\.turbo|coverage|__pycache__|\.pytest_cache|\btmp\b|\btemp\b|\.DS_Store)/;

const BASH_RULES = [
  // ---- RED ----
  {
    level: 'red',
    code: 'curl-pipe-sh',
    re: /\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/,
    msg: 'Downloads a script from the internet and runs it immediately, unchecked. It could do anything to your Mac.',
  },
  {
    level: 'red',
    code: 'sudo',
    re: /\bsudo\b/,
    msg: 'Gives full administrator power over your Mac. Could change or delete anything, including system files.',
  },
  {
    level: 'red',
    code: 'rm-rf-home',
    re: /\brm\s+(-\w*[rR]\w*f|-\w*f\w*[rR])\b.*(\s(\/|~\/?|\$HOME|\*)(\s|$))/,
    msg: 'Permanently deletes files from your home folder or whole disk. No undo, no Trash.',
  },
  {
    level: 'red',
    code: 'force-push',
    re: /\bgit\s+push\b.*(--force\b|-f\b)/,
    msg: 'Overwrites the history of your online backup. Can permanently erase saved work, including your teammates work.',
  },
  {
    level: 'red',
    code: 'disk-write',
    re: /\b(mkfs|diskutil\s+erase|dd\s+[^|]*of=\/dev)/i,
    msg: 'Writes directly to a disk or erases it. Can destroy everything on the drive.',
  },
  {
    level: 'red',
    code: 'drop-table',
    re: /\bdrop\s+(table|database)\b/i,
    msg: 'Deletes an entire database or table. All the data in it is gone permanently.',
  },
  {
    level: 'red',
    code: 'secret-exfil',
    re: /\.env[^\s]*\b.*\b(curl|wget|nc)\b|\b(curl|wget|nc)\b.*\.env\b/,
    msg: 'Looks like it sends your passwords and API keys over the internet.',
  },
  {
    level: 'red',
    code: 'chmod-777',
    re: /\bchmod\s+(-\w+\s+)?777\b/,
    msg: 'Lets every program and user on this computer read and change these files. A known security hole.',
  },

  // ---- ORANGE ----
  {
    level: 'orange',
    code: 'git-discard',
    re: /\bgit\s+reset\s+--hard\b|\bgit\s+checkout\s+--\s|\bgit\s+clean\b/,
    msg: 'Throws away recent edits that were never saved as a snapshot.',
  },
  {
    level: 'orange',
    code: 'rm',
    re: /\brm\s/,
    msg: (cmd) =>
      ROUTINE_DELETE.test(cmd)
        ? 'Deletes files, but these look like rebuildable cache or build folders.'
        : 'Deletes files for good. There is no Trash here.',
    action: (cmd) =>
      ROUTINE_DELETE.test(cmd)
        ? 'Usually fine to approve.'
        : 'Check the file names above first.',
  },
  {
    level: 'orange',
    code: 'git-push',
    re: /\bgit\s+push\b/,
    msg: 'Publishes your code to your online backup, where other people may see it.',
  },
  {
    level: 'orange',
    code: 'install',
    re: /\b(npm|pnpm|yarn|bun)\s+(i|install|add)\b|\bpip3?\s+install\b|\bbrew\s+install\b|\bgem\s+install\b|\bcargo\s+install\b/,
    msg: 'Downloads and installs software from the internet.',
    action: 'Check the package name is the one you expect.',
  },
  {
    level: 'orange',
    code: 'kill',
    re: /\bkill(all)?\b|\bpkill\b/,
    msg: 'Force stops a running program. You could lose unsaved work in it.',
  },
  {
    level: 'orange',
    code: 'permissions',
    re: /\b(chmod|chown)\b/,
    msg: 'Changes who can read, edit, or run these files. Can create security holes.',
  },
  {
    level: 'orange',
    code: 'upload',
    re: /\bcurl\b[^|]*\s(-d|--data|--data-raw|--form|-F|-T|--upload-file)\b|\bcurl\b.*-X\s*(POST|PUT|DELETE)/i,
    msg: 'Sends data from your computer to a server on the internet.',
    action: 'Check what is being sent, and to whom.',
  },
  {
    level: 'orange',
    code: 'system-settings',
    re: /\b(crontab|launchctl|defaults\s+write)\b/,
    msg: 'Changes settings on your Mac itself, not just this project. The change sticks.',
  },
  {
    level: 'orange',
    code: 'docker-delete',
    re: /\bdocker\s+(rm|rmi|system\s+prune|volume\s+rm)\b/,
    msg: 'Deletes Docker containers or storage. Any data inside them is lost.',
  },
];

function classifyBash(cmd) {
  if (!cmd) return null;
  const pick = (v) => (typeof v === 'function' ? v(cmd) : v);
  for (const rule of BASH_RULES) {
    if (rule.re.test(cmd)) {
      return { level: rule.level, code: rule.code, msg: pick(rule.msg), action: pick(rule.action) };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// File writes and edits
// ---------------------------------------------------------------------------

function classifyFileChange(filePath) {
  if (!filePath) return null;
  const p = filePath.replace(/\\/g, '/');

  if (/\.env(\.|$)/.test(p) || /(^|\/)(secrets?|credentials?)\.(json|ya?ml|txt)$/i.test(p))
    return {
      level: 'red',
      code: 'edit-secrets',
      msg: `Edits "${shortName(p)}", where your passwords and API keys live. A wrong edit can leak them or break your logins.`,
    };

  if (/\/\.ssh\//.test(p))
    return {
      level: 'red',
      code: 'edit-ssh',
      msg: 'Changes your SSH keys, which prove your identity to GitHub and other computers. Can lock you out, or let someone else in.',
    };

  if (/\/\.claude\/settings(\.local)?\.json$/.test(p) || /\/\.claude\/hooks\//.test(p))
    return {
      level: 'orange',
      code: 'edit-claude-config',
      msg: "Changes Claude's own settings. This can let Claude act in future without asking you.",
      action: 'Approve only if you asked Claude to change its setup.',
    };

  if (/(^|\/)\.(zshrc|bashrc|bash_profile|profile|gitconfig)$/.test(p))
    return {
      level: 'orange',
      code: 'edit-shell-config',
      msg: `Edits "${shortName(p)}", a personal settings file affecting your whole Mac, not just this project.`,
    };

  return null;
}

// ---------------------------------------------------------------------------
// Web fetches
// ---------------------------------------------------------------------------

function classifyWebFetch(url) {
  if (!url) return null;
  if (/^http:\/\//.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(url))
    return {
      level: 'orange',
      code: 'insecure-http',
      msg: 'Loads a web page over an insecure connection (http, not https). The content could be tampered with on the way.',
    };
  return null;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function classify(tool, ti) {
  if (tool === 'Bash') return classifyBash(String(ti.command || ''));
  if (EDIT_TOOLS.test(tool)) return classifyFileChange(String(ti.file_path || ti.notebook_path || ''));
  if (tool === 'WebFetch') return classifyWebFetch(String(ti.url || ''));
  return null;
}

const KNOWN_SAFE_BASH = [
  [/^\s*(ls|pwd|cat|head|tail|grep|rg|find|which|file|wc|tree|stat|du|df)\b/,
    'Only reads or lists files. Changes nothing.'],
  [/^\s*git\s+(status|log|diff|show|branch|remote)\b/,
    'Only checks your project status and history. Changes nothing.'],
  [/^\s*(npm|pnpm|yarn|bun)\s+(test|run\s+test)\b/,
    'Runs your project tests to check things still work.'],
  [/^\s*(npm|pnpm|yarn|bun)\s+run\s+(build|dev|start)\b/,
    'Builds or starts your project so you can preview it.'],
  [/^\s*(mkdir|touch)\b/, 'Creates a new empty file or folder.'],
  [/^\s*git\s+(add|commit)\b/,
    'Saves a snapshot of your work. Nothing leaves your Mac, and it can be undone.'],
  [/^\s*echo\b/, 'Just prints text on screen. Changes nothing.'],
];

function greenVerdict(tool, ti) {
  if (tool === 'Bash') {
    const cmd = String(ti.command || '');
    for (const [re, msg] of KNOWN_SAFE_BASH) {
      if (re.test(cmd)) return { level: 'green', code: 'known-safe', msg };
    }
    return {
      level: 'green',
      code: 'no-rule-matched',
      msg: 'Nothing risky found. Runs a command inside your project folder.',
    };
  }
  if (tool === 'WebFetch')
    return {
      level: 'green',
      code: 'web-read',
      msg: `Reads a page on ${hostOf(String(ti.url || ''))}. Nothing is sent from your computer.`,
    };
  if (tool === 'WebSearch')
    return {
      level: 'green',
      code: 'web-search',
      msg: 'Searches the web. Only the search words are sent, nothing from your files.',
    };
  if (EDIT_TOOLS.test(tool))
    return {
      level: 'green',
      code: 'normal-edit',
      msg: `Edits "${shortName(String(ti.file_path || ti.notebook_path || 'a file'))}", a normal project file. Can be undone.`,
    };
  return {
    level: 'orange',
    code: 'unknown-tool',
    msg: `Unrecognised tool "${tool}". VibeGuard cannot check this one.`,
    action: 'Read the request above before deciding.',
  };
}

// The verdict for a tool call, always non-null for a prompting tool.
function verdictFor(tool, ti) {
  return classify(tool, ti) || greenVerdict(tool, ti);
}

// ---------------------------------------------------------------------------
// Rendering
//
// The permission dialog strips ALL line breaks, so the card has to read as a
// single line. Keep messages short and let the separators carry the rhythm:
//
//   <emoji> LEVEL · what it does · → what to do
// ---------------------------------------------------------------------------

const HEADERS = {
  green: '\u{1F7E2} SAFE',
  orange: '\u{1F7E0} CHECK FIRST',
  red: '\u{1F534} HIGH RISK',
};
const ACTIONS = {
  green: 'OK to approve.',
  orange: 'Approve only if this is what you asked for.',
  red: 'If you did not ask for this, click Deny.',
};

function card(v) {
  return `${HEADERS[v.level]} · ${v.msg} → ${v.action || ACTIONS[v.level]}`;
}

// What the tool call is actually about, for display: the command, the file, or
// the URL.
function targetOf(tool, ti) {
  if (tool === 'Bash' || tool === 'PowerShell') return String(ti.command || '');
  if (ti.file_path || ti.notebook_path) return String(ti.file_path || ti.notebook_path);
  if (ti.url) return String(ti.url);
  return '';
}

function shortName(p) {
  return p.split('/').slice(-2).join('/');
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return 'an unknown site';
  }
}

module.exports = {
  LEVELS,
  PROMPTING_TOOLS,
  EDIT_TOOLS,
  ACTIONS,
  HEADERS,
  isPromptingTool,
  isReadOnlyBash,
  classify,
  greenVerdict,
  verdictFor,
  card,
  targetOf,
  shortName,
  hostOf,
};
