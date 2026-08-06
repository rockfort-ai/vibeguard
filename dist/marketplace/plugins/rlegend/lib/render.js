'use strict';

// Compile one policy into each harness's native config.
//
// The point of this file: you maintain policy/policy.json, and every
// enforcement point below is generated. Nobody hand-maintains four allowlists
// that drift apart.
//
// Key names here are taken from the vendor docs as of July 2026. When a vendor
// renames something, this is the only file that changes.

const { domainsFor } = require('./policy');

// --- Claude Code -----------------------------------------------------------
//
// Enforcement strength: strong. The OS-level sandbox proxy enforces
// allowedDomains for Bash and every child process, PreToolUse hooks can return
// a hard deny, and managed settings can lock developers out of widening it.

function claudeCode(policy, {
  scope = 'user', hookPath, postHookPath, sessionHookPath, stopHookPath,
} = {}) {
  const allow = domainsFor(policy, 'allow');
  const deny = domainsFor(policy, 'deny');
  const managed = scope === 'managed';

  // WebFetch rules take a domain, so drop loopback and bare IPs — they are
  // meaningful to the sandbox proxy but produce junk rules here.
  const webfetch = (list) => list.filter(isDomain).map((d) => `WebFetch(domain:${d})`);

  const out = {
    permissions: {
      allow: webfetch(allow),
      deny: webfetch(deny),
    },
    sandbox: {
      enabled: true,
      network: {
        allowedDomains: allow,
        deniedDomains: deny,
      },
      credentials: {
        files: credentialFiles(policy).map((path) => ({ path, mode: 'deny' })),
        envVars: (policy.secretIndicators.patterns || []).map((name) => ({ name, mode: 'deny' })),
      },
    },
  };

  // strictAllowlist and the managed-only locks are ignored from project
  // settings, so only emit them where they will actually take effect.
  if (scope === 'user' || managed) {
    out.sandbox.network.strictAllowlist = true;
  }
  if (managed) {
    out.sandbox.failIfUnavailable = true;
    out.sandbox.allowUnsandboxedCommands = false;
    out.sandbox.allowManagedDomainsOnly = true;
    out.sandbox.allowManagedReadPathsOnly = true;
  }

  if (hookPath || postHookPath || sessionHookPath || stopHookPath) out.hooks = {};
  if (hookPath) {
    // 20s, matching the plugin manifest. It was 10 here, which is the same hook
    // doing the same work under two different ceilings depending on how you
    // installed it — and the editor bridge alone can wait 12s for a click.
    out.hooks.PreToolUse = [{
      matcher: '*',
      hooks: [{ type: 'command', command: `node "${hookPath}"`, timeout: 20 }],
    }];
  }
  // Without this, `rlegend sync` installs a PreToolUse hook whose questions can
  // never stop repeating: a hook-driven `ask` shows a dialog with no "don't ask
  // again", so the only signal that a question was answered yes is the tool
  // actually running. This was omitted entirely until v1.2.0, which meant
  // remembered answers worked for plugin installs and silently did nothing for
  // anyone who ran `rlegend sync`.
  if (postHookPath) {
    out.hooks.PostToolUse = [{
      matcher: '*',
      hooks: [{ type: 'command', command: `node "${postHookPath}"`, timeout: 10 }],
    }];
  }
  // Skill drift detection. `compact` is deliberately absent: compaction does
  // not reload skills, and re-reporting the whole inventory into a context that
  // was just trimmed wastes the tokens compaction reclaimed.
  if (sessionHookPath) {
    out.hooks.SessionStart = [{
      matcher: 'startup|resume|clear',
      hooks: [{ type: 'command', command: `node "${sessionHookPath}"`, timeout: 15 }],
    }];
  }
  // The recap. No `matcher` — Stop is not tool-scoped.
  if (stopHookPath) {
    out.hooks.Stop = [{
      hooks: [{ type: 'command', command: `node "${stopHookPath}"`, timeout: 10 }],
    }];
  }
  return out;
}

function isDomain(d) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(d) || d.includes(':')) return false;
  return d === 'localhost' ? false : d.includes('.');
}

function credentialFiles(policy) {
  // sandbox.credentials.files wants real paths, not globs.
  const CONCRETE = {
    '.env': './.env',
    '.aws/credentials': '~/.aws/credentials',
    '.aws/config': '~/.aws/config',
    '.ssh/*': '~/.ssh',
    '.npmrc': '~/.npmrc',
    '.pypirc': '~/.pypirc',
    '.netrc': '~/.netrc',
    '.pgpass': '~/.pgpass',
    '.docker/config.json': '~/.docker/config.json',
    'kubeconfig': '~/.kube/config',
  };
  const out = new Set();
  for (const p of policy.secretIndicators.paths || []) {
    if (CONCRETE[p]) out.add(CONCRETE[p]);
  }
  return [...out];
}

// --- Cursor ----------------------------------------------------------------
//
// Enforcement strength: medium. Hooks can deny, but Cursor's own command
// allow-list has been reported to take precedence over hook allow/ask, so
// treat the hook as a blocker only. Domain allowlisting for cloud agents lives
// in the team Network Access Policy, not in the repo — see the exported
// allowlist.txt.

function cursorHooks(policy, { hookPath = './.rlegend/adapters/cursor.js' } = {}) {
  const entry = [{ command: `node ${hookPath}` }];
  return {
    version: 1,
    hooks: {
      beforeShellExecution: entry,
      beforeMCPExecution: entry,
      beforeReadFile: entry,
    },
  };
}

// --- Codex -----------------------------------------------------------------
//
// Enforcement strength: strong but static. No pre-tool hook to call out to, so
// the policy has to be compiled into the proxy config ahead of time. Unlisted
// domains are denied; deny wins over allow.

function codexConfig(policy) {
  const allow = domainsFor(policy, 'allow');
  const deny = domainsFor(policy, 'deny');
  const lines = [
    '# Generated by rlegend — do not edit by hand. Run `rlegend sync --target codex`.',
    '',
    '[sandbox_workspace_write]',
    'network_access = true',
    '',
    '[features.network_proxy]',
    'enabled = true',
  ];
  const pairs = [
    ...deny.map((d) => `"${d}" = "deny"`),
    ...allow.map((d) => `"${d}" = "allow"`),
  ];
  lines.push('domains = { ' + pairs.join(', ') + ' }');
  lines.push('');
  return lines.join('\n');
}

// --- Vendor consoles (Devin, Cursor cloud, anything with a text box) -------

function allowlistText(policy) {
  return domainsFor(policy, 'allow').join('\n') + '\n';
}

function denylistText(policy) {
  return domainsFor(policy, 'deny').join('\n') + '\n';
}

// --- Squid / generic egress proxy ------------------------------------------
//
// The fallback for any harness with no hook and no allowlist UI: put the
// runner behind a proxy you control and enforce there.

function squidConf(policy) {
  const allow = domainsFor(policy, 'allow').map((d) => (d.startsWith('*.') ? d.slice(1) : d));
  const deny = domainsFor(policy, 'deny').map((d) => (d.startsWith('*.') ? d.slice(1) : d));
  return [
    '# Generated by rlegend — run `rlegend sync --target proxy`.',
    'acl agent_deny dstdomain ' + deny.join(' '),
    'acl agent_allow dstdomain ' + allow.join(' '),
    'http_access deny agent_deny',
    'http_access allow agent_allow',
    'http_access deny all',
    '',
  ].join('\n');
}

module.exports = { claudeCode, cursorHooks, codexConfig, allowlistText, denylistText, squidConf };
