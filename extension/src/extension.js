'use strict';

// Rockfort Legend for VS Code and Cursor.
//
// The Claude Code hook does the thinking; this shows the result properly. The
// terminal permission dialog is one line with no formatting, which is exactly
// the wrong place to explain risk to someone who is not a developer. Here the
// same verdict gets a real popup, a colour, the command in full, and — when the
// hook is running in interactive mode — Approve and Deny buttons that answer
// the prompt directly.

const vscode = require('vscode');
const { Bridge } = require('./bridge.js');
const { Panel, LEVELS } = require('./panel.js');

const HISTORY_LIMIT = 100;
const RANK = { green: 0, orange: 1, red: 2 };

let bridge = null;
let history = [];
let status = null;
let context = null;

function activate(ctx) {
  context = ctx;

  bridge = new Bridge(onEvent);
  bridge.start();
  ctx.subscriptions.push({ dispose: () => bridge.stop() });

  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.command = 'rlegend.showPanel';
  ctx.subscriptions.push(status);
  refreshStatus();

  ctx.subscriptions.push(
    vscode.commands.registerCommand('rlegend.showPanel', () => showPanel(true)),
    vscode.commands.registerCommand('rlegend.clearHistory', () => {
      history = [];
      refreshStatus();
      if (Panel.current) Panel.current.render(history);
    }),
    vscode.commands.registerCommand('rlegend.status', showDiagnostics),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('rlegend')) refreshStatus();
    })
  );
}

function deactivate() {
  if (bridge) bridge.stop();
}

// ---------------------------------------------------------------------------
// Incoming verdicts
// ---------------------------------------------------------------------------

function onEvent(ev, live) {
  history.unshift(ev);
  history = history.slice(0, HISTORY_LIMIT);
  refreshStatus();
  if (Panel.current) Panel.current.render(history);

  if (!live) return; // backfilled on startup, or already answered

  if (atLeast(ev.level, cfg('revealPanelOn', 'red'))) showPanel(false);
  if (ev.interactive) {
    askModal(ev);
  } else if (atLeast(ev.level, cfg('popupOn', 'orangeAndRed'))) {
    showNotification(ev);
  }
}

// Interactive mode: Claude Code is blocked on the hook, waiting for this answer.
async function askModal(ev) {
  const meta = LEVELS[ev.level] || LEVELS.green;
  const detail = [ev.msg, ev.action, '', ev.target].filter((x) => x !== undefined).join('\n');

  // The third button appears only when the hook says this answer is safe to
  // remember. It is absent for anything red and for skill drift — "always allow
  // admin access" is not a preference, and a standing yes to a changed skill
  // defeats the only reason skill pinning exists.
  const always = ev.allowAlways
    ? `Always allow ${ev.allowAlwaysLabel || 'this'}`
    : null;

  const buttons = always ? ['Approve', always, 'Deny'] : ['Approve', 'Deny'];

  const choice = await vscode.window.showWarningMessage(
    `${meta.dot} ${meta.label} — Claude wants to use ${ev.tool}`,
    { modal: true, detail },
    ...buttons
  );

  // Escape or Cancel deliberately writes nothing: the hook times out and falls
  // back to the normal Claude Code prompt, so no answer is never a silent yes.
  if (choice === 'Approve') bridge.decide(ev.id, 'allow');
  else if (always && choice === always) bridge.decide(ev.id, 'always');
  else if (choice === 'Deny') bridge.decide(ev.id, 'deny');
}

// Notify-only mode: the answer still happens in Claude Code itself.
async function showNotification(ev) {
  const meta = LEVELS[ev.level] || LEVELS.green;
  const text = `${meta.dot} ${meta.label} · ${ev.msg}`;
  const show =
    ev.level === 'red'
      ? vscode.window.showErrorMessage
      : ev.level === 'orange'
        ? vscode.window.showWarningMessage
        : vscode.window.showInformationMessage;

  const choice = await show.call(vscode.window, text, 'Details');
  if (choice === 'Details') showPanel(true);
}

// ---------------------------------------------------------------------------
// Chrome
// ---------------------------------------------------------------------------

function showPanel(reveal) {
  Panel.show(context.extensionUri, history, onDecide, reveal);
}

function onDecide(id, decision) {
  if (!bridge.decide(id, decision)) {
    vscode.window.showErrorMessage('Rockfort Legend could not send that answer to Claude Code.');
  }
}

function refreshStatus() {
  if (!cfg('statusBar', true)) {
    status.hide();
    return;
  }
  const last = history[0];
  const meta = last ? LEVELS[last.level] : null;
  status.text = meta ? `${meta.dot} Rockfort Legend` : '$(shield) Rockfort Legend';
  status.tooltip = last
    ? `${meta.label} — ${last.msg}\n\nClick to open the Rockfort Legend panel.`
    : 'Rockfort Legend is watching Claude Code permission prompts.';
  status.show();
}

function atLeast(level, setting) {
  if (setting === 'off' || setting === 'never') return false;
  const floor = { all: 'green', orangeAndRed: 'orange', red: 'red' }[setting] || 'orange';
  return RANK[level] >= RANK[floor];
}

function cfg(key, fallback) {
  return vscode.workspace.getConfiguration('rlegend').get(key, fallback);
}

async function showDiagnostics() {
  const info = bridge.info();
  const seenSomething = info.lastWrite !== null;
  const age = seenSomething ? Math.round((Date.now() - info.lastWrite) / 1000) : null;

  const lines = [
    seenSomething
      ? `Connected. Last verdict from Claude Code: ${age}s ago.`
      : 'No verdicts received yet.',
    '',
    `Watching: ${info.events}`,
    `Events this session: ${history.length}`,
    '',
    seenSomething
      ? 'Approve/Deny buttons appear only when the hook runs with RLEGEND_INTERACTIVE=1.'
      : 'Install the Rockfort Legend plugin in Claude Code, then run a command that needs permission.',
  ];

  const choice = await vscode.window.showInformationMessage(
    'Rockfort Legend',
    { modal: true, detail: lines.join('\n') },
    'Open panel'
  );
  if (choice === 'Open panel') showPanel(true);
}

module.exports = { activate, deactivate };
