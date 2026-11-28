// ZeroScript 2.0 — frontend
const API = ''; // same origin

async function apiGet(path) {
  const r = await fetch(API + path);
  return r.json();
}
async function apiPost(path, body) {
  const r = await fetch(API + path, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body || {}),
  });
  return r.json();
}

// ---------- Navigation ----------
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('view-' + name)?.classList.add('active');
  document.querySelector(`.nav-item[data-view="${name}"]`)?.classList.add('active');
  // Lazy-load
  if (name === 'debug') debugRefresh();
  if (name === 'assets') assetsRefresh();
  if (name === 'projects') projectsRefresh();
  if (name === 'library') libraryRefresh();
  if (name === 'plugins') pluginsRefresh();
  if (name === 'dashboard') dashboardRefresh();
  if (name === 'uibuilder') uiBuilderRefresh();
}
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
});

// ---------- Status polling ----------
async function pollStatus() {
  try {
    const s = await apiGet('/api/status');
    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    dot.className = 'dot ' + (s.studio?.place ? 'green' : s.bridge?.online ? 'yellow' : 'grey');
    txt.textContent = s.studio?.place ? 'Studio ready' : s.bridge?.online ? 'Bridge online' : 'Offline';
    document.getElementById('kpi-tools').textContent = (s.tools || []).length;
  } catch { }
}
setInterval(pollStatus, 3000);
pollStatus();

// ---------- Dashboard ----------
async function dashboardRefresh() {
  const [p, a] = await Promise.all([apiGet('/api2/projects'), apiGet('/api2/assets')]);
  document.getElementById('kpi-projects').textContent = (p.projects || []).length;
  document.getElementById('kpi-assets').textContent = (a.assets || []).length;
  const recent = document.getElementById('recent-projects');
  recent.innerHTML = (p.recent || []).map(x =>
    `<div class="list-item"><span>${x.name}</span><span class="meta">${x.template}</span></div>`
  ).join('') || '<div class="meta">No projects yet.</div>';
}

// ---------- Editor ----------
const editor = document.getElementById('editor');
const lineNums = document.getElementById('line-nums');
function updateLineNums() {
  const n = editor.value.split('\n').length;
  lineNums.textContent = Array.from({length: n}, (_, i) => i + 1).join('\n');
}
editor?.addEventListener('input', updateLineNums);
editor?.addEventListener('scroll', () => lineNums.scrollTop = editor.scrollTop);
editor?.addEventListener('keydown', e => {
  if (e.key === 'Tab') {
    e.preventDefault();
    const s = editor.selectionStart, en = editor.selectionEnd;
    editor.value = editor.value.slice(0, s) + '\t' + editor.value.slice(en);
    editor.selectionStart = editor.selectionEnd = s + 1;
    updateLineNums();
  }
});

async function editorSave() {
  const name = document.getElementById('doc-name').value || 'Untitled';
  const r = await apiPost('/api2/editor/save', { name, code: editor.value });
  if (r.ok) flash('Saved');
}
async function editorFormat() {
  const r = await apiPost('/api2/editor/format', { code: editor.value });
  if (r.ok) { editor.value = r.code; updateLineNums(); }
}
async function editorDiagnose() {
  const r = await apiPost('/api2/editor/diagnostics', { code: editor.value });
  const box = document.getElementById('editor-diags');
  box.innerHTML = (r.diagnostics || []).map(d =>
    `<div class="${d.severity}">L${d.line}:${d.col} — ${d.message}</div>`
  ).join('') || '<div class="info">No issues found.</div>';
}

// ---------- AI Assistant ----------
async function aiRun() {
  const action = document.getElementById('ai-action').value;
  const input = document.getElementById('ai-input').value;
  const r = await apiPost('/api2/ai/local', { action, input });
  document.getElementById('ai-output').textContent = r.result || '';
}
async function aiCopyPrompt() {
  const action = document.getElementById('ai-action').value;
  const input = document.getElementById('ai-input').value;
  const r = await apiPost('/api2/ai/prompt', { action, input });
  await navigator.clipboard.writeText(r.prompt || '');
  flash('Prompt copied');
}

// ---------- Debug ----------
async function debugRefresh() {
  const r = await apiGet('/api2/debug/errors');
  document.getElementById('debug-summary').textContent =
    `${r.summary?.lines || 0} lines · ${r.summary?.errors || 0} errors · ${r.summary?.warnings || 0} warnings`;
  const out = await apiGet('/api2/debug/output');
  document.getElementById('debug-output').innerHTML = (out.items || []).map(i =>
    `<div class="${i.level}">[${i.ts}] ${i.msg}</div>`
  ).join('');
  document.getElementById('debug-errors').innerHTML = (r.errors || []).map(e =>
    `<div class="error">${e.message} <small>×${e.count}</small></div>`
  ).join('') || '<div class="info">No errors.</div>';
  document.getElementById('debug-warnings').innerHTML = (r.warnings || []).map(w =>
    `<div class="warning">${w.message} <small>×${w.count}</small></div>`
  ).join('') || '<div class="info">No warnings.</div>';
}
async function debugClear() { await apiPost('/api2/debug/clear', {}); debugRefresh(); }

// ---------- Assets ----------
async function assetsRefresh() {
  const q = document.getElementById('asset-search').value;
  const kind = document.getElementById('asset-kind').value;
  const r = await apiGet('/api2/assets');
  const items = (r.assets || []).filter(a =>
    (!q || a.name.toLowerCase().includes(q.toLowerCase())) && (!kind || a.kind === kind));
  document.getElementById('asset-list').innerHTML = items.map(a =>
    `<div class="asset-card">
       <div><strong>${a.name}</strong> ${a.favorite ? '<span class="fav">★</span>' : ''}</div>
       <div class="meta">${a.kind} · ${a.assetId || 'no id'}</div>
     </div>`
  ).join('') || '<div class="meta">No assets.</div>';
}
async function assetAdd() {
  const name = prompt('Asset name:');
  if (!name) return;
  const kind = prompt('Kind (model/image/sound/mesh):', 'model');
  await apiPost('/api2/assets/add', { name, kind });
  assetsRefresh();
}

// ---------- Projects ----------
async function projectsRefresh() {
  const r = await apiGet('/api2/projects');
  document.getElementById('project-list').innerHTML = (r.projects || []).map(p =>
    `<div class="list-item"><span>${p.name}</span><span class="meta">${p.template}</span></div>`
  ).join('') || '<div class="meta">No projects yet.</div>';
}
async function projectCreate() {
  const name = document.getElementById('proj-name').value;
  const template = document.getElementById('proj-template').value;
  if (!name) return;
  const r = await apiPost('/api2/projects/create', { name, template });
  if (r.ok) { document.getElementById('proj-name').value = ''; projectsRefresh(); }
  else alert(r.error);
}

// ---------- UI Builder ----------
let uiTree = [];
function uiBuilderRefresh() { renderTree(); }
function uiBuilderAdd(type) {
  uiTree.push({ type, props: {}, children: [] });
  renderTree();
}
function renderTree() {
  const box = document.getElementById('ui-tree');
  box.innerHTML = uiTree.map((n, i) =>
    `<div class="ui-node">${n.type} <button onclick="uiBuilderRemove(${i})">✕</button></div>`
  ).join('') || '<div class="meta">Empty tree. Add a component.</div>';
}
function uiBuilderRemove(i) { uiTree.splice(i, 1); renderTree(); }
async function uiBuilderGenerate() {
  const r = await apiPost('/api2/uibuilder/build', { tree: { type: 'frame', children: uiTree } });
  document.getElementById('ui-code').textContent = r.code || '';
}

// ---------- Library ----------
async function libraryRefresh() {
  const r = await apiGet('/api2/library');
  document.getElementById('library-list').innerHTML = (r.items || []).map(i =>
    `<div class="list-item"><span>${i.title}</span><span class="meta">${i.saved}</span></div>`
  ).join('') || '<div class="meta">No saved scripts.</div>';
}
async function librarySave() {
  const title = document.getElementById('lib-title').value;
  if (!title) return;
  await apiPost('/api2/library/save', { title, code: editor.value });
  libraryRefresh();
}

// ---------- Plugins ----------
async function pluginsRefresh() {
  const r = await apiGet('/api2/plugins');
  document.getElementById('plugin-list').innerHTML = (r.available || []).map(p =>
    `<div class="list-item">
       <span>${p.name || p.id}</span>
       <button onclick="pluginLoad('${p.id}')">Load</button>
     </div>`
  ).join('') || '<div class="meta">No plugins found in plugins/.</div>';
}
async function pluginLoad(id) {
  const r = await apiPost('/api2/plugins/load', { id });
  alert(r.ok ? 'Loaded' : r.error);
}

// ---------- Settings ----------
async function settingsSave() {
  const accent = document.getElementById('set-accent').value;
  const globalPrompt = document.getElementById('set-global-prompt').value;
  await apiPost('/api/settings', { accentTheme: accent, globalPrompt });
  applyAccent(accent);
  flash('Settings saved');
}
function applyAccent(a) {
  const map = {
    indigo: ['#7c5cff', '#22d3ee'],
    cyan: ['#22d3ee', '#38bdf8'],
    emerald: ['#22c55e', '#14b8a6'],
    amber: ['#f59e0b', '#f97316'],
    crimson: ['#ef4444', '#f43f5e'],
    prism: ['#a78bfa', '#f472b6'],
  };
  const [c1, c2] = map[a] || map.indigo;
  document.documentElement.style.setProperty('--accent', c1);
  document.documentElement.style.setProperty('--accent-2', c2);
}

// ---------- Misc ----------
function flash(msg) {
  const t = document.createElement('div');
  t.textContent = msg;
  t.style.cssText = `position:fixed;bottom:20px;right:20px;background:var(--accent);
    color:#fff;padding:10px 16px;border-radius:8px;z-index:9999;font-size:13px;
    box-shadow:0 10px 30px rgba(0,0,0,.4);animation:fade .2s ease;`;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 1800);
}

// Init
window.addEventListener('load', () => {
  dashboardRefresh();
  updateLineNums();
  editor.value = '--!strict\n-- Welcome to ZeroScript 2.0\nlocal Players = game:GetService("Players")\n\nPlayers.PlayerAdded:Connect(function(player)\n\tprint("Hi", player.Name)\nend)\n';
  updateLineNums();
});