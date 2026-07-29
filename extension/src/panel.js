'use strict';

// The VibeGuard panel: a running list of everything Claude has asked to do,
// colour-coded, newest first. This is where the full card lives — the terminal
// permission dialog strips line breaks, so the two-line form (what it does /
// what to do) can only be shown here.

const vscode = require('vscode');

const LEVELS = {
  red: { label: 'HIGH RISK', dot: '\u{1F534}' },
  orange: { label: 'CHECK FIRST', dot: '\u{1F7E0}' },
  green: { label: 'SAFE', dot: '\u{1F7E2}' },
};

class Panel {
  static current = null;

  static show(extensionUri, history, onDecide, reveal) {
    const column = vscode.ViewColumn.Beside;
    if (Panel.current) {
      if (reveal) Panel.current.panel.reveal(column, true);
      Panel.current.render(history);
      return Panel.current;
    }
    const panel = vscode.window.createWebviewPanel(
      'vibeguard.panel',
      'VibeGuard',
      { viewColumn: column, preserveFocus: true },
      { enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [extensionUri] }
    );
    Panel.current = new Panel(panel, onDecide);
    Panel.current.render(history);
    return Panel.current;
  }

  constructor(panel, onDecide) {
    this.panel = panel;
    this.panel.onDidDispose(() => {
      Panel.current = null;
    });
    this.panel.webview.onDidReceiveMessage((m) => {
      if (m && m.type === 'decide') onDecide(m.id, m.decision);
    });
    this.panel.webview.html = html(this.panel.webview);
  }

  render(history) {
    this.panel.webview.postMessage({ type: 'history', history, levels: LEVELS });
  }
}

function html(webview) {
  const nonce = String(Math.random()).slice(2) + String(Date.now());
  const csp = [
    "default-src 'none'",
    `style-src ${webview.cspSource} 'unsafe-inline'`,
    `script-src 'nonce-${nonce}'`,
  ].join('; ');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  :root {
    /* Severity colours stay semantic — they mean danger, not brand. */
    --red: #e5484d;
    --orange: #f76b15;
    --green: #30a46c;
    /* Rockfort AI: Signal */
    --signal: #2979FF;
  }
  body {
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
    padding: 12px 14px 32px;
    margin: 0;
  }
  h1 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .08em;
    opacity: .6;
    font-weight: 600;
    margin: 0 0 12px;
  }
  .empty {
    opacity: .6;
    line-height: 1.6;
    max-width: 46ch;
  }
  .card {
    border: 1px solid var(--vscode-panel-border, rgba(128,128,128,.3));
    border-left-width: 4px;
    border-radius: 5px;
    padding: 10px 12px;
    margin-bottom: 8px;
    background: var(--vscode-editorWidget-background);
  }
  .card.red { border-left-color: var(--red); }
  .card.orange { border-left-color: var(--orange); }
  .card.green { border-left-color: var(--green); }
  .head {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-weight: 600;
    font-size: 12px;
    letter-spacing: .04em;
    margin-bottom: 6px;
  }
  .card.red .level { color: var(--red); }
  .card.orange .level { color: var(--orange); }
  .card.green .level { color: var(--green); }
  .when { margin-left: auto; font-weight: 400; opacity: .5; font-size: 11px; }
  .msg { line-height: 1.5; margin-bottom: 6px; }
  .action { line-height: 1.5; opacity: .75; }
  .action::before { content: '\\2192\\00a0'; }
  pre {
    background: var(--vscode-textCodeBlock-background, rgba(128,128,128,.12));
    border-radius: 4px;
    padding: 7px 9px;
    margin: 8px 0 0;
    overflow-x: auto;
    font-family: var(--vscode-editor-font-family);
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .tool { opacity: .55; font-weight: 400; font-size: 11px; }
  .buttons { display: flex; gap: 8px; margin-top: 10px; }
  button {
    font-family: inherit;
    font-size: 12px;
    padding: 4px 12px;
    border: none;
    border-radius: 3px;
    cursor: pointer;
    background: var(--vscode-button-secondaryBackground);
    color: var(--vscode-button-secondaryForeground);
  }
  button.deny { background: var(--red); color: #fff; }
  button.allow { background: var(--signal); color: #fff; }
  .waiting { font-size: 11px; opacity: .6; margin-top: 8px; }
  footer {
    margin-top: 20px;
    padding-top: 12px;
    border-top: 1px solid var(--vscode-panel-border, rgba(128,128,128,.3));
    font-size: 11px;
    opacity: .5;
  }
</style>
</head>
<body>
<h1>Recent activity</h1>
<div id="list"></div>
<footer>VibeGuard &middot; Rockfort AI</footer>
<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  const list = document.getElementById('list');
  const answered = new Set();

  window.addEventListener('message', (e) => {
    if (e.data.type !== 'history') return;
    draw(e.data.history, e.data.levels);
  });

  function draw(history, levels) {
    if (!history.length) {
      list.innerHTML = '<p class="empty">Nothing yet. When Claude Code asks permission to run a command, edit a file, or fetch a page, the explanation appears here.</p>';
      return;
    }
    list.innerHTML = '';
    for (const ev of history) {
      const meta = levels[ev.level] || levels.green;
      const card = el('div', 'card ' + ev.level);

      const head = el('div', 'head');
      head.append(el('span', 'level', meta.dot + ' ' + meta.label));
      head.append(el('span', 'tool', ev.tool));
      head.append(el('span', 'when', ago(ev.ts)));
      card.append(head);

      card.append(el('div', 'msg', ev.msg));
      if (ev.action) card.append(el('div', 'action', ev.action));
      if (ev.target) {
        const pre = document.createElement('pre');
        pre.textContent = ev.target;
        card.append(pre);
      }

      if (ev.interactive && !answered.has(ev.id) && Date.now() - ev.ts < 20000) {
        const row = el('div', 'buttons');
        row.append(btn('Deny', 'deny', ev.id));
        row.append(btn('Approve', 'allow', ev.id));
        card.append(row);
        card.append(el('div', 'waiting', 'Claude Code is waiting for your answer.'));
      }
      list.append(card);
    }
  }

  function btn(label, decision, id) {
    const b = document.createElement('button');
    b.className = decision;
    b.textContent = label;
    b.addEventListener('click', () => {
      answered.add(id);
      b.parentElement.parentElement.querySelectorAll('button').forEach((x) => (x.disabled = true));
      vscode.postMessage({ type: 'decide', id, decision });
    });
    return b;
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function ago(ts) {
    const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.round(s / 60) + 'm ago';
    return Math.round(s / 3600) + 'h ago';
  }
</script>
</body>
</html>`;
}

module.exports = { Panel, LEVELS };
