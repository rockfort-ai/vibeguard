'use strict';

// Turn an arbitrary agent tool call into a list of network destinations plus
// the signals we need to judge them.
//
// This is deliberately conservative in one direction: it would rather surface
// a destination that turns out to be harmless than miss one. Anything it
// cannot resolve to a host is reported as `unresolved`, which the policy
// treats as an unknown destination rather than as "no network".

const fs = require('fs');
const path = require('path');

const URL_RE = /\bhttps?:\/\/[^\s'"`)<>\\]+/gi;
const SCP_RE = /(?:^|\s)(?:[\w.-]+@)?([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}):(?:\/|~|[\w.-])/gi;
const GIT_SSH_RE = /\bgit@([a-z0-9.-]+):/gi;
const BARE_HOST_RE = /\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi;

// Package managers whose install/publish traffic goes to a known registry even
// though no URL appears in the command.
const REGISTRIES = [
  { re: /\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add|ci|publish|update|up)\b/, hosts: ['registry.npmjs.org'], send: /\bpublish\b/ },
  { re: /\b(?:pip|pip3|uv|uvx)\s+(?:install|download|sync|add)\b/, hosts: ['pypi.org', 'files.pythonhosted.org'] },
  { re: /\bbrew\s+(?:install|upgrade|update|tap)\b/, hosts: ['formulae.brew.sh', 'ghcr.io'] },
  { re: /\bcargo\s+(?:install|add|update|publish)\b/, hosts: ['crates.io', 'static.crates.io'], send: /\bpublish\b/ },
  { re: /\bgem\s+(?:install|push)\b/, hosts: ['rubygems.org'], send: /\bpush\b/ },
  { re: /\bgo\s+(?:get|install|mod\s+download)\b/, hosts: ['proxy.golang.org', 'sum.golang.org'] },
  { re: /\b(?:mvn|gradle)\b/, hosts: ['repo.maven.apache.org'] },
  { re: /\b(?:composer)\s+(?:install|require|update)\b/, hosts: ['repo.packagist.org'] },
  { re: /\b(?:dotnet|nuget)\s+(?:add|restore|install)\b/, hosts: ['api.nuget.org'] },
];

const SEND_FLAGS = /(?:^|\s)(?:-d|--data|--data-raw|--data-binary|--data-urlencode|--json|-F|--form|-T|--upload-file|--post-data|--post-file)\b/;
const SEND_METHOD = /-X\s*["']?(POST|PUT|PATCH|DELETE)/i;

function extract(tool, input, cwd) {
  const ti = input || {};
  if (tool === 'WebFetch' || tool === 'WebSearch') {
    return finish(fromUrls(String(ti.url || ti.query || ''), 'WebFetch', 'read'), {}, cwd);
  }
  if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool)) {
    return finish([], { writePath: String(ti.file_path || ti.notebook_path || '') }, cwd);
  }
  if (tool === 'Read') {
    return finish([], { readPath: String(ti.file_path || '') }, cwd);
  }
  if (tool === 'Bash' || tool === 'BashOutput' || tool === 'Shell') {
    return fromBash(String(ti.command || ti.script || ''), cwd);
  }
  if (tool.startsWith('mcp__')) {
    // MCP servers are their own egress path. We can only see the arguments.
    const blob = JSON.stringify(ti);
    return finish(fromUrls(blob, `mcp:${tool}`, 'send'), { mcp: tool }, cwd);
  }
  return finish([], {}, cwd);
}

// --- bash ------------------------------------------------------------------

function fromBash(command, cwd) {
  if (!command) return finish([], {}, cwd);

  const segments = splitSegments(command);
  const destinations = [];
  const flags = {
    pipeToShell: /\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/.test(command),
    listener: /\bnc\b[^|;&]*\s-\w*l/.test(command),
    execFromDownload: /\b(?:curl|wget)\b[^|;&]*&&[^|;&]*\.\/|chmod\s+\+x/.test(command),
  };

  segments.forEach((seg, i) => {
    const dests = destinationsInSegment(seg, cwd);
    // A segment that is piped *into* from a secret reader is an exfil path even
    // if it is only a GET, so record the pipe lineage.
    const pipedFrom = i > 0 && segments[i - 1].pipedInto ? segments[i - 1].text : null;
    for (const d of dests) destinations.push({ ...d, segment: seg.text, pipedFrom });
  });

  return finish(destinations, { flags, segments }, cwd, command);
}

function splitSegments(command) {
  const parts = command.split(/(\|\||&&|;|\||\n)/);
  const out = [];
  for (let i = 0; i < parts.length; i += 2) {
    const text = (parts[i] || '').trim();
    if (!text) continue;
    out.push({ text, pipedInto: parts[i + 1] === '|' });
  }
  return out;
}

function destinationsInSegment(seg, cwd) {
  const cmd = seg.text;
  const out = [];
  const sending = SEND_FLAGS.test(cmd) || SEND_METHOD.test(cmd);

  // 1. explicit URLs
  out.push(...fromUrls(cmd, binaryOf(cmd), sending ? 'send' : 'read'));

  // 2. ssh / scp / rsync / git-over-ssh
  for (const re of [SCP_RE, GIT_SSH_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(cmd))) {
      out.push(mkDest(m[1], '', 'ssh', binaryOf(cmd), scpDirection(cmd)));
    }
  }
  if (/^\s*ssh\s/.test(cmd)) {
    const host = (cmd.match(/^\s*ssh\s+(?:-\S+\s+)*(?:[\w.-]+@)?([a-z0-9.-]+)/i) || [])[1];
    if (host && host.includes('.')) out.push(mkDest(host, '', 'ssh', 'ssh', 'send'));
  }

  // 3. raw host:port for nc / telnet / socat
  if (/^\s*(?:nc|ncat|netcat|telnet|socat)\b/.test(cmd)) {
    BARE_HOST_RE.lastIndex = 0;
    let m;
    while ((m = BARE_HOST_RE.exec(cmd))) out.push(mkDest(m[1], '', 'tcp', 'nc', 'send'));
    const ip = cmd.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/);
    if (ip) out.push(mkDest(ip[0], '', 'tcp', 'nc', 'send'));
  }

  // 4. package registries implied by the tool being run
  for (const reg of REGISTRIES) {
    if (!reg.re.test(cmd)) continue;
    const dir = reg.send && reg.send.test(cmd) ? 'send' : 'read';
    for (const host of reg.hosts) out.push(mkDest(host, '', 'https', 'package-manager', dir));
  }

  // 5. docker
  const docker = cmd.match(/\bdocker\s+(pull|push)\s+(\S+)/);
  if (docker) {
    const ref = docker[2];
    const maybeHost = ref.split('/')[0];
    const host = maybeHost.includes('.') || maybeHost.includes(':') ? maybeHost.split(':')[0] : 'registry-1.docker.io';
    out.push(mkDest(host, '', 'https', 'docker', docker[1] === 'push' ? 'send' : 'read'));
  }

  // 6. git against a configured remote
  const git = cmd.match(/\bgit\s+(push|pull|fetch|clone|remote\s+add|ls-remote)\b/);
  if (git && !/https?:\/\//.test(cmd) && !GIT_SSH_RE.test(cmd)) {
    const remote = gitRemoteHost(cwd);
    const dir = /push/.test(git[1]) ? 'send' : 'read';
    if (remote) out.push(mkDest(remote, '', 'https', 'git', dir));
    else out.push({ host: null, unresolved: 'git remote', via: 'git', direction: dir });
  }

  return out;
}

function scpDirection(cmd) {
  // `scp local remote:` sends, `scp remote: local` reads. Cheap heuristic:
  // if the remote token is the last argument we are pushing to it.
  const tokens = cmd.trim().split(/\s+/).filter((t) => !t.startsWith('-'));
  const last = tokens[tokens.length - 1] || '';
  return last.includes(':') ? 'send' : 'read';
}

function fromUrls(text, via, direction) {
  const out = [];
  URL_RE.lastIndex = 0;
  let m;
  while ((m = URL_RE.exec(text))) {
    try {
      const u = new URL(m[0].replace(/[.,;'")]+$/, ''));
      out.push(mkDest(u.hostname, u.pathname, u.protocol.replace(':', ''), via, direction, u.href));
    } catch {
      /* not a usable URL */
    }
  }
  return out;
}

function mkDest(host, path_, scheme, via, direction, url) {
  return {
    host: String(host || '').toLowerCase().replace(/\.$/, ''),
    path: path_ || '',
    scheme: scheme || 'https',
    via: via || 'shell',
    direction: direction || 'read',
    url: url || '',
    isIp: /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(host)),
    isLoopback: /^(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)$/i.test(String(host)),
  };
}

function binaryOf(cmd) {
  const m = cmd.trim().match(/^([\w.\/-]+)/);
  return m ? path.basename(m[1]) : 'shell';
}

function gitRemoteHost(cwd) {
  if (!cwd) return null;
  try {
    const conf = fs.readFileSync(path.join(cwd, '.git', 'config'), 'utf8');
    const url = (conf.match(/url\s*=\s*(\S+)/) || [])[1];
    if (!url) return null;
    if (/^https?:\/\//.test(url)) return new URL(url).hostname;
    const ssh = url.match(/@([a-z0-9.-]+):/i);
    return ssh ? ssh[1] : null;
  } catch {
    return null;
  }
}

// --- secrets ---------------------------------------------------------------

function secretReads(text, policy) {
  const hits = [];
  const ind = (policy && policy.secretIndicators) || {};
  for (const p of ind.paths || []) {
    const re = new RegExp(globToRe(p), 'i');
    if (re.test(text)) hits.push({ kind: 'file', match: p });
  }
  for (const c of ind.commands || []) {
    if (new RegExp('\\b' + escapeRe(c) + '\\b', 'i').test(text)) hits.push({ kind: 'command', match: c });
  }
  for (const p of ind.patterns || []) {
    if (new RegExp('\\b' + escapeRe(p) + '\\b').test(text)) hits.push({ kind: 'env', match: p });
  }
  return hits;
}

function globToRe(glob) {
  return escapeRe(glob).replace(/\\\*/g, '[^\\s"\']*');
}
function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// --- assembly --------------------------------------------------------------

function finish(destinations, extra, cwd, rawText) {
  const seen = new Set();
  const deduped = [];
  for (const d of destinations) {
    const key = `${d.host || d.unresolved}|${d.direction}|${d.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(d);
  }
  return {
    destinations: deduped,
    raw: rawText || '',
    flags: extra.flags || {},
    segments: extra.segments || [],
    writePath: extra.writePath || '',
    readPath: extra.readPath || '',
    mcp: extra.mcp || '',
    cwd: cwd || '',
  };
}

module.exports = { extract, secretReads, fromBash, gitRemoteHost };
