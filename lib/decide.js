'use strict';

// The decision engine. Harness-agnostic: adapters hand it a normalised tool
// call and get back a verdict plus the plain-English card that made Rockfort Legend
// worth using in the first place.
//
// Two families of rule run here:
//   egress   — where is this call sending bytes, and is that destination in
//              policy? This is the part that answers "block bad network
//              requests without allowlisting the entire internet".
//   local    — the original Rockfort Legend rules about destructive local actions.
//
// Egress wins ties, because an exfil path is worse than a messy rm.

const { classify } = require('./policy');
const { secretReads } = require('./extract');

const LEVEL_BY_DECISION = { deny: 'red', ask: 'orange', allow: 'green' };

// "mcp__linear__create_issue" → "linear". Server names can contain underscores,
// so match the same way remember.js does rather than splitting naively.
function serverOf(tool) {
  const m = /^mcp__([^_]+(?:_[^_]+)*?)__(.+)$/.exec(String(tool || ''));
  return m ? m[1] : String(tool || '').replace(/^mcp__/, '');
}

function decide(policy, call, ext) {
  const text = ext.raw || call.text || '';
  const secrets = secretReads(text + ' ' + (ext.writePath || ''), policy);
  const sending = ext.destinations.filter((d) => d.direction === 'send' || d.pipedFrom);
  const redAction = policy.defaults.redAction === 'deny' ? 'deny' : 'ask';

  // --- egress: hard stops --------------------------------------------------

  if (ext.flags.pipeToShell) {
    return verdict('deny', 'red', 'egress.pipe-to-shell',
      'Downloads a script from the internet and runs it immediately, unchecked. It could do anything to your Mac.',
      'Blocked. Ask for the script to be saved and read first.', ext);
  }

  if (secrets.length && (sending.length || ext.destinations.length)) {
    const where = ext.destinations.map((d) => d.host).filter(Boolean).join(', ') || 'the internet';
    return verdict('deny', 'red', 'egress.secret-exfiltration',
      `Reads your ${describeSecret(secrets[0])} and sends it to ${where}. This is how credentials leak.`,
      'Blocked. Nothing that reads secrets should be talking to the network.', ext, secrets);
  }

  // A credential in an MCP argument, with no URL anywhere in the call. The
  // server itself is the destination, and Rockfort Legend cannot see past it — no
  // hostname, no idea whether it stays local or crosses the internet.
  //
  // So this asks; it does not block. The deny above means "reads a secret AND
  // opens a socket to somewhere I can name", and widening it to cover a
  // destination nobody can see would make it mean something much vaguer while
  // still being unappealable. Being specific is what makes the red one credible.
  if (secrets.length && ext.mcp) {
    return verdict('ask', 'orange', 'mcp.secret-argument',
      `Passes your ${describeSecret(secrets[0])} to the MCP server "${serverOf(ext.mcp)}". Rockfort Legend cannot see what that server does with it, or where it sends it.`,
      'Approve only if this server is meant to handle credentials.', ext, secrets);
  }

  // --- egress: destination policy -----------------------------------------

  const judged = ext.destinations.map((d) => ({ dest: d, match: d.host ? classify(policy, d) : null }));

  const denied = judged.find((j) => j.match && j.match.decision === 'deny');
  if (denied) {
    return verdict('deny', 'red', 'egress.denied-destination',
      `Contacts ${denied.dest.host}, which your policy blocks (${labelFor(denied.match.via)}). Destinations like this are used to move data out.`,
      'Blocked by policy.', ext);
  }

  const unresolved = judged.find((j) => j.dest.unresolved);
  if (unresolved) {
    return verdict(policy.defaults.unknownDestination, 'orange', 'egress.unresolved',
      `Talks to the network, but Rockfort Legend could not work out where (${unresolved.dest.unresolved}).`,
      'Check the command above before approving.', ext);
  }

  // A bare IP is checked before the allowlist, because an IP will never be on
  // one — it would otherwise always surface as a generic unknown host and the
  // more specific warning would be dead code.
  const rawIp = judged.find((j) => j.dest.isIp && !j.dest.isLoopback && !j.match);
  if (rawIp && policy.defaults.rawIpDestination !== 'allow') {
    return verdict(policy.defaults.rawIpDestination, 'orange', 'egress.raw-ip',
      `Connects straight to the IP address ${rawIp.dest.host} instead of a named site. Legitimate tools rarely need this.`,
      'Approve only if you set up that server yourself.', ext);
  }

  const unknown = judged.find((j) => j.dest.host && !j.dest.isLoopback && !j.match);
  if (unknown) {
    const d = unknown.dest;
    const verb = d.direction === 'send' ? 'Sends data to' : 'Downloads from';
    const insecureNote = d.scheme === 'http' ? ' It also uses an insecure http connection.' : '';
    return verdict(policy.defaults.unknownDestination, 'orange', 'egress.unknown-destination',
      `${verb} ${d.host}, which is not on your allowlist.${insecureNote}`,
      `Approve once, or run: rlegend allow ${d.host}`, ext);
  }

  const asked = judged.find((j) => j.match && j.match.decision === 'ask');
  if (asked) {
    return verdict('ask', 'orange', 'egress.sensitive-destination',
      `Contacts ${asked.dest.host}${asked.dest.direction === 'send' ? ' and sends data to it' : ''}. That is a ${labelFor(asked.match.via)} — real changes can happen there.`,
      'Approve only if this is what you asked for.', ext);
  }

  const insecure = judged.find((j) => j.dest.scheme === 'http' && !j.dest.isLoopback);
  if (insecure && policy.defaults.insecureHttp !== 'allow') {
    return verdict(policy.defaults.insecureHttp, 'orange', 'egress.insecure-http',
      `Loads ${insecure.dest.host} over an insecure connection (http, not https). The content could be tampered with on the way.`,
      'Prefer https if you have the choice.', ext);
  }

  if (ext.flags.listener) {
    return verdict('ask', 'orange', 'egress.listener',
      'Opens a port on this machine so something outside can connect in.',
      'Approve only if you meant to expose a local server.', ext);
  }

  // --- local action rules --------------------------------------------------

  // The same thing through a shell. `readPath` is only ever set for the Read
  // tool, so until v1.2.0 `cat .env` was a green verdict with nothing to say —
  // the exact question a first-time user asks ("does it notice something
  // reading my keys?") answered wrongly. There is no destination here, so this
  // is not exfiltration and it is not a block; it is worth a question.
  if (!ext.destinations.length && secrets.length && call.tool !== 'Read' && !ext.mcp) {
    return verdict('ask', 'orange', 'local.read-secrets',
      `Reads your ${describeSecret(secrets[0])}. Once read, the agent can repeat it anywhere — including into a reply.`,
      'Approve only if the task genuinely needs those keys.', ext, secrets);
  }

  if (ext.readPath) {
    const hits = secretReads(ext.readPath, policy);
    if (hits.length) {
      return verdict('ask', 'orange', 'local.read-secrets',
        `Opens "${ext.readPath.split('/').slice(-2).join('/')}", which holds your passwords or API keys. Once read, the agent can repeat them anywhere.`,
        'Approve only if the task genuinely needs those keys.', ext, hits);
    }
    return verdict('allow', 'green', 'ok', 'Reads a normal project file.', 'OK to approve.', ext);
  }

  const local = call.tool === 'Bash' ? classifyBash(text) : classifyFileChange(ext.writePath || '');
  if (local) {
    const decision = local.level === 'red' ? redAction : 'ask';
    return verdict(decision, local.level, local.rule, local.msg, local.action, ext);
  }

  // --- nothing to say ------------------------------------------------------

  const allowedHosts = judged.filter((j) => j.match && j.match.decision === 'allow').map((j) => j.dest.host);
  return verdict('allow', 'green', 'ok',
    allowedHosts.length
      ? `Contacts ${[...new Set(allowedHosts)].join(', ')}, which is on your allowlist.`
      : 'Nothing risky found. Stays on this machine.',
    'OK to approve.', ext);
}

function verdict(decision, level, rule, msg, action, ext, secrets) {
  return {
    decision,
    level: level || LEVEL_BY_DECISION[decision],
    rule,
    msg,
    action,
    destinations: ext ? ext.destinations : [],
    secrets: secrets || [],
  };
}

function describeSecret(hit) {
  if (hit.kind === 'file') return `credentials file (${hit.match})`;
  if (hit.kind === 'env') return `${hit.match} key`;
  return `stored credentials (${hit.match})`;
}

function labelFor(via) {
  const LABELS = {
    'class:exfil-sinks': 'known data-drop service',
    'class:anonymizers': 'anonymising network',
    'class:cloud-control-planes': 'cloud control plane',
    'class:crypto': 'crypto or wallet endpoint',
  };
  return LABELS[via] || via.replace(/^class:/, '').replace(/-/g, ' ');
}

// --- the original local rules, unchanged in spirit -------------------------

const ROUTINE_DELETE = /(node_modules|dist\b|build\b|\.next|\.cache|\.turbo|coverage|__pycache__|\.pytest_cache|\btmp\b|\btemp\b|\.DS_Store)/;

const BASH_RULES = [
  { level: 'red', rule: 'local.sudo', re: /\bsudo\b/,
    msg: 'Gives full administrator power over your Mac. Could change or delete anything, including system files.' },
  { level: 'red', rule: 'local.rm-home', re: /\brm\s+(-\w*[rR]\w*f|-\w*f\w*[rR])\b.*(\s(\/|~\/?|\$HOME|\*)(\s|$))/,
    msg: 'Permanently deletes files from your home folder or whole disk. No undo, no Trash.' },
  { level: 'red', rule: 'local.force-push', re: /\bgit\s+push\b.*(--force\b|-f\b)/,
    msg: 'Overwrites the history of your online backup. Can permanently erase saved work, including your teammates work.' },
  { level: 'red', rule: 'local.disk-write', re: /\b(mkfs|diskutil\s+erase|dd\s+[^|]*of=\/dev)/i,
    msg: 'Writes directly to a disk or erases it. Can destroy everything on the drive.' },
  { level: 'red', rule: 'local.drop-db', re: /\bdrop\s+(table|database)\b/i,
    msg: 'Deletes an entire database or table. All the data in it is gone permanently.' },
  { level: 'red', rule: 'local.chmod-777', re: /\bchmod\s+(-\w+\s+)?777\b/,
    msg: 'Lets every program and user on this computer read and change these files. A known security hole.' },

  { level: 'orange', rule: 'local.git-discard', re: /\bgit\s+reset\s+--hard\b|\bgit\s+checkout\s+--\s|\bgit\s+clean\b/,
    msg: 'Throws away recent edits that were never saved as a snapshot.' },
  { level: 'orange', rule: 'local.rm', re: /\brm\s/,
    msg: (c) => ROUTINE_DELETE.test(c)
      ? 'Deletes files, but these look like rebuildable cache or build folders.'
      : 'Deletes files for good. There is no Trash here.',
    action: (c) => ROUTINE_DELETE.test(c) ? 'Usually fine to approve.' : 'Check the file names above first.' },
  { level: 'orange', rule: 'local.git-push', re: /\bgit\s+push\b/,
    msg: 'Publishes your code to your online backup, where other people may see it.' },
  { level: 'orange', rule: 'local.install', re: /\b(npm|pnpm|yarn|bun)\s+(i|install|add)\b|\bpip3?\s+install\b|\bbrew\s+install\b|\bgem\s+install\b|\bcargo\s+install\b/,
    msg: 'Downloads and installs software from the internet.',
    action: 'Check the package name is the one you expect.' },
  { level: 'orange', rule: 'local.kill', re: /\bkill(all)?\b|\bpkill\b/,
    msg: 'Force stops a running program. You could lose unsaved work in it.' },
  { level: 'orange', rule: 'local.perms', re: /\b(chmod|chown)\b/,
    msg: 'Changes who can read, edit, or run these files. Can create security holes.' },
  { level: 'orange', rule: 'local.persistence', re: /\b(crontab|launchctl|defaults\s+write)\b/,
    msg: 'Changes settings on your Mac itself, not just this project. The change sticks.' },
  { level: 'orange', rule: 'local.docker-rm', re: /\bdocker\s+(rm|rmi|system\s+prune|volume\s+rm)\b/,
    msg: 'Deletes Docker containers or storage. Any data inside them is lost.' },
];

function classifyBash(cmd) {
  if (!cmd) return null;
  const pick = (v) => (typeof v === 'function' ? v(cmd) : v);
  for (const r of BASH_RULES) {
    if (r.re.test(cmd)) return { level: r.level, rule: r.rule, msg: pick(r.msg), action: pick(r.action) };
  }
  return null;
}

function classifyFileChange(filePath) {
  if (!filePath) return null;
  const p = filePath.replace(/\\/g, '/');
  const short = p.split('/').slice(-2).join('/');

  if (/\.env(\.|$)/.test(p) || /(^|\/)(secrets?|credentials?)\.(json|ya?ml|txt)$/i.test(p))
    return { level: 'red', rule: 'local.edit-secrets',
      msg: `Edits "${short}", where your passwords and API keys live. A wrong edit can leak them or break your logins.` };

  if (/\/\.ssh\//.test(p))
    return { level: 'red', rule: 'local.edit-ssh',
      msg: 'Changes your SSH keys, which prove your identity to GitHub and other computers. Can lock you out, or let someone else in.' };

  if (/\/\.(claude|cursor|codex|rlegend)\//.test(p) && /(settings|hooks|config|policy)/.test(p))
    return { level: 'orange', rule: 'local.edit-agent-config',
      msg: "Changes the coding agent's own settings or guardrails. This can let it act in future without asking you.",
      action: 'Approve only if you asked for the setup to change.' };

  if (/(^|\/)\.(zshrc|bashrc|bash_profile|profile|gitconfig)$/.test(p))
    return { level: 'orange', rule: 'local.edit-shell-profile',
      msg: `Edits "${short}", a personal settings file affecting your whole Mac, not just this project.` };

  return null;
}

// --- card rendering --------------------------------------------------------

const HEADERS = { green: '\u{1F7E2} SAFE', orange: '\u{1F7E0} CHECK FIRST', red: '\u{1F534} HIGH RISK' };
const FALLBACK_ACTION = {
  green: 'OK to approve.',
  orange: 'Approve only if this is what you asked for.',
  red: 'If you did not ask for this, click Deny.',
};

// The permission dialog strips line breaks, so the card has to read as one line.
function card(v) {
  return `${HEADERS[v.level]} · ${v.msg} → ${v.action || FALLBACK_ACTION[v.level]}`;
}

module.exports = { decide, card, classifyBash, classifyFileChange };
