const $ = id => document.getElementById(id);
let fragment = location.hash.slice(1);
let bootstrap = /^bootstrap=[0-9a-f]{64}$/.test(fragment) ? fragment.slice(10) : null;
fragment = null;
let poller = null;
const state = { csrf: null, active: false, route: 'memories', query: {selection: {kind: 'all'}, include_global: false, kind: 'all', order: 'recorded_newest', epistemic_status: null, authority: null, atom_lifecycle: null}, after: null, frontier: null, next: null, selected: null, content: null, controller: null };
const directory = {query: {parent: null, name: ''}, after: null, frontier: null, next: null, controller: null};
history.replaceState(null, '', '#memories');
const channel = new BroadcastChannel('evertrace-web-session');
function clear() { $('memory-items').replaceChildren(); $('detail-body').replaceChildren(); $('detail-ref').textContent = ''; $('system-status').replaceChildren(); $('page-count').textContent = ''; $('next-page').disabled = true; }
function cancel() { state.controller?.abort(); state.controller = null; }
function notice(text) { $('notice').textContent = text; }
function closed(text, broadcast = false) { cancel(); clear(); clearInterval(poller); poller = null; state.csrf = null; state.active = false; state.query = {...state.query, selection: {kind: 'all'}, include_global: false}; updateScopeControls(); clearDirectory(); if ($('scope-dialog').open) $('scope-dialog').close(); state.selected = null; state.content = null; state.after = null; state.frontier = null; state.next = null; $('reader').hidden = true; $('system-panel').hidden = true; notice(text); if (broadcast) channel.postMessage('closed'); }
channel.onmessage = () => closed('网页会话已结束；请重新运行 evertrace --web。');
async function api(path, body, signal) {
  const headers = { 'X-EverTrace-Web': '1' };
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; if (state.csrf) headers['X-EverTrace-CSRF'] = state.csrf; }
  let response;
  try { response = await fetch('/api/' + path, { method: body === undefined ? 'GET' : 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', cache: 'no-store', signal }); }
  catch (error) { if (error.name !== 'AbortError') closed('网页服务连接已断开，旧内容已清除；可刷新页面重新连接。'); throw error; }
  if (response.status === 401) closed('网页会话已失效，旧内容已清除。', true);
  if (!response.ok) throw new Error('read unavailable');
  return response.json();
}
function fragmentInto(target, html) { const template = document.createElement('template'); template.innerHTML = html; target.replaceChildren(template.content); }
async function detail(item, frontier, controller, scroll = 0) {
  const result = await api('read', { kind: 'detail', reference: item.key, frontier, revision: item.revision || null }, controller.signal);
  if (state.controller !== controller || document.hidden) return;
  if (result.conflict) { $('detail-body').textContent = '记录已变化，请重新选择；没有改用当前版本。'; return; }
  fragmentInto($('detail-body'), result.html); $('detail-ref').textContent = item.revision || item.key; $('detail-body').scrollTop = scroll;
}
async function readContent(item, representation, after, controller, scroll = 0) {
  const result = await api('read', {kind: 'content', reference: item.key, revision: item.revision, frontier: state.frontier, representation, after}, controller.signal);
  if (state.controller !== controller || document.hidden) return;
  if (result.conflict) { state.content = null; $('detail-ref').textContent = ''; $('detail-body').textContent = '读取水位不可用；没有换用当前修订。'; return; }
  fragmentInto($('detail-body'), result.html);
  const body = $('detail-body').querySelector('.chunk-text'); if (body) body.textContent = result.text;
  $('detail-body').scrollTop = scroll;
  // Retain only the requested identity/cursor for fresh authorization checks;
  // never retain text, previews, ranges or byte counts outside the DOM.
  state.content = {representation, after, previous: result.previous_cursor, next: result.next_cursor};
  $('detail-ref').textContent = result.state === 'ready' ? item.revision : '';
}
async function openContent(representation, after = null) {
  const item = state.selected; if (!item?.revision || !state.active || document.hidden) return;
  cancel(); const controller = new AbortController(); state.controller = controller;
  state.content = {representation, after}; $('detail-body').replaceChildren(); $('detail-ref').textContent = '';
  try { await readContent(item, representation, after, controller); }
  catch { if (state.controller === controller && !controller.signal.aborted) { clear(); state.content = null; notice('分段读取失败，旧正文和区间已清除。'); } }
  finally { if (state.controller === controller) state.controller = null; }
}
async function select(item) {
  state.content = null;
  cancel(); const controller = new AbortController(); state.controller = controller; state.selected = item; $('detail-ref').textContent = ''; $('detail-body').textContent = '正在读取…';
  try { await detail(item, state.frontier, controller); } catch { if (state.controller === controller && !controller.signal.aborted) { clear(); notice('读取失败，旧内容已清除。'); } }
  finally { if (state.controller === controller) state.controller = null; }
}
async function refresh() {
  if (!state.active || document.hidden) return;
  if ($('scope-dialog').open) { await loadDirectory(); return; }
  if (state.controller) return;
  const controller = new AbortController(); state.controller = controller;
  try {
    const health = await api('status', undefined, controller.signal);
    if (state.controller !== controller || document.hidden) return;
    $('connection-status').textContent = 'daemon 已连接';
    if (state.route === 'system') { $('system-status').textContent = JSON.stringify(health, null, 2); return; }
    if (state.route !== 'memories') return;
    const page = await api('read', { kind: 'list', query: state.query, after: state.after, expected_frontier: state.after ? state.frontier : null }, controller.signal);
    if (state.controller !== controller || document.hidden) return;
    const listScroll = $('memory-items').scrollTop, detailScroll = $('detail-body').scrollTop;
    clear();
    if (page.conflict) { state.after = null; state.frontier = null; state.next = null; state.selected = null; state.content = null; notice('分页水位已变化；请刷新读取当前列表。'); return; }
    state.frontier = page.frontier; state.next = page.next_cursor;
    fragmentInto($('memory-items'), page.html); $('memory-items').scrollTop = listScroll;
    $('page-count').textContent = !page.scope_available ? '范围不可用 · 计数未知' : '本页 ' + page.count + ' · ' + (page.counts_complete ? '' : '已判定范围 ≥ ') + '筛选 ' + page.matching_count + ' / 当前条目 ' + page.total_count;
    $('next-page').disabled = !page.next_cursor;
    notice(!page.scope_available ? '所选身份不存在、已移除或当前不可用，未改查全部范围。' : page.degraded ? '只读数据有降级；不是完整成功。' : '按录入顺序浏览所选关联范围；计数不是可读正文数，也不表示方法可执行。' + (page.unresolved_scope_count !== '0' ? ' 另有 ' + page.unresolved_scope_count + ' 条元数据归属尚未判定。' : '') + ' 搜索和网页修改尚未接入。');
    if (state.selected && [...$('memory-items').children].some(row => row.dataset.key === state.selected.key)) {
      if (state.content) await readContent(state.selected, state.content.representation, state.content.after, controller, detailScroll);
      else await detail(state.selected, page.frontier, controller, detailScroll);
    } else { state.selected = null; state.content = null; $('detail-body').textContent = '选择一条记忆查看正文。'; }
  } catch { if (state.controller === controller && !controller.signal.aborted) { clear(); $('connection-status').textContent = '读取不可用'; notice('daemon 或读取暂不可用，旧内容已清除。'); } }
  finally { if (state.controller === controller) state.controller = null; }
}
function route(name) {
  cancel(); clear(); state.route = name; state.after = null; state.frontier = null; state.selected = null; state.content = null;
  history.replaceState(null, '', '#' + name);
  for (const button of document.querySelectorAll('[data-route]')) button.classList.toggle('active', button.dataset.route === name);
  $('reader').hidden = !state.active || name !== 'memories'; $('system-panel').hidden = !state.active || name !== 'system';
  const label = document.querySelector('[data-route="' + name + '"]')?.textContent.trim() || name;
  $('breadcrumb').textContent = label; $('page-title').textContent = label;
  $('page-description').textContent = '独立 Python Web，只读调用现有 daemon；未接入的页面不使用示例数据。';
  notice(['memories', 'system'].includes(name) ? '正在读取…' : '该页面尚未接入真实后端。');
  refresh();
}
$('detail-body').onclick = event => {
  const button = event.target.closest('[data-content-open], [data-content-nav]');
  if (!button || button.disabled) return;
  if (button.dataset.contentOpen) openContent(button.dataset.contentOpen);
  else if (state.content) openContent(state.content.representation, button.dataset.contentNav === 'first' ? null : state.content[button.dataset.contentNav]);
};
$('memory-items').onclick = event => { const row = event.target.closest('.memory-item'); if (row) select({ key: row.dataset.key, revision: row.dataset.revision }); };
for (const button of document.querySelectorAll('[data-route]')) button.onclick = () => route(button.dataset.route);
function clearDirectory() {
  directory.controller?.abort(); directory.controller = null;
  directory.query = {parent: null, name: ''}; directory.after = null; directory.frontier = null; directory.next = null;
  $('scope-items').replaceChildren(); $('scope-notice').textContent = ''; $('scope-parent').textContent = ''; $('scope-name').value = ''; $('scope-next').disabled = true;
}
function scopeLabel(selection) {
  const labels = {all: '全部元数据', global: '仅 global', unassigned: '未归属元数据', task: '任务', repository: '仓库', worktree: '工作树'};
  const id = selection.task_id || selection.repository_id || selection.worktree_id;
  return labels[selection.kind] + (id ? ' ' + id.split(':').at(-1).slice(0, 8) : '');
}
async function loadDirectory() {
  if (!state.active || document.hidden || !$('scope-dialog').open || directory.controller) return;
  const controller = new AbortController(); directory.controller = controller;
  $('scope-items').replaceChildren(); $('scope-notice').textContent = '正在从后端复核目录…'; $('scope-next').disabled = true;
  try {
    const page = await api('read', {kind: 'scopes', query: directory.query, after: directory.after, expected_frontier: directory.after ? directory.frontier : null}, controller.signal);
    if (directory.controller !== controller || document.hidden || !$('scope-dialog').open) return;
    if (page.conflict) { directory.after = null; directory.frontier = null; directory.next = null; $('scope-notice').textContent = '目录有更新；保留原条件，请回到目录首页重新读取。'; return; }
    directory.frontier = page.frontier; directory.next = page.next_cursor;
    fragmentInto($('scope-items'), page.html); $('scope-next').disabled = !page.next_cursor;
    $('scope-parent').textContent = directory.query.parent ? scopeLabel(directory.query.parent) : '全部已知身份';
    $('scope-notice').textContent = !page.parent_available ? '父级身份不可用，未回退到全部目录。' : !page.complete ? '本次目录读取未完成；可继续下一页或重新读取。' : !page.names_complete ? '部分任务名称暂时读不到，搜索结果可能不全。' : '本页按稳定身份排列；名称与限制已重新检查，目录可见不代表正文可读。';
  } catch { if (directory.controller === controller && !controller.signal.aborted) { $('scope-items').replaceChildren(); $('scope-notice').textContent = '目录读取不可用，旧名称和路径已清除。'; } }
  finally { if (directory.controller === controller) directory.controller = null; }
}
function directoryQuery(parent, name = '') {
  directory.controller?.abort(); directory.controller = null; directory.query = {parent, name}; directory.after = null; directory.frontier = null; directory.next = null; loadDirectory();
}
function updateScopeControls() {
  const selection = state.query.selection;
  $('include-global').checked = state.query.include_global;
  $('include-global').disabled = !['task', 'repository', 'worktree'].includes(selection.kind);
  $('scope-open').textContent = '范围：' + scopeLabel(selection);
}
function chooseScope(selection) {
  cancel(); clear(); state.after = null; state.frontier = null; state.next = null; state.selected = null; state.content = null;
  state.query = {...state.query, selection, include_global: false};
  updateScopeControls();
  $('scope-dialog').close();
}
$('scope-open').onclick = () => { cancel(); clear(); clearDirectory(); $('scope-dialog').showModal(); loadDirectory(); };
$('scope-close').onclick = () => $('scope-dialog').close();
$('scope-dialog').onclose = () => { clearDirectory(); refresh(); };
$('scope-search').onsubmit = event => { event.preventDefault(); directoryQuery(directory.query.parent, $('scope-name').value.trim()); };
$('scope-root').onclick = () => { $('scope-name').value = ''; directoryQuery(null); };
$('scope-first').onclick = () => directoryQuery(directory.query.parent, directory.query.name);
$('scope-next').onclick = () => { if (directory.next) { directory.after = directory.next; loadDirectory(); } };
$('scope-items').onclick = event => {
  const button = event.target.closest('[data-scope-choose], [data-scope-children]'); if (!button) return;
  const selection = JSON.parse(button.closest('.scope-entry').dataset.selection);
  if (button.hasAttribute('data-scope-choose')) chooseScope(selection); else { $('scope-name').value = ''; directoryQuery(selection); }
};
for (const button of document.querySelectorAll('[data-scope-fixed]')) button.onclick = () => chooseScope({kind: button.dataset.scopeFixed});
$('include-global').onchange = () => changeQuery();
function changeQuery() {
  cancel(); clear(); state.after = null; state.frontier = null; state.selected = null; state.content = null; state.next = null;
  const atomAxes = ['all', 'facts_and_constraints'].includes($('reading-kind').value);
  for (const id of ['epistemic-filter', 'authority-filter', 'lifecycle-filter']) { $(id).disabled = !atomAxes; if (!atomAxes) $(id).value = ''; }
  state.query = {selection: state.query.selection, include_global: $('include-global').checked, kind: $('reading-kind').value, order: $('browse-order').value, epistemic_status: $('epistemic-filter').value || null, authority: $('authority-filter').value || null, atom_lifecycle: $('lifecycle-filter').value || null};
  refresh();
}
for (const id of ['reading-kind', 'browse-order', 'epistemic-filter', 'authority-filter', 'lifecycle-filter']) $(id).onchange = changeQuery;
$('refresh').onclick = refresh;
$('first-page').onclick = () => { cancel(); clear(); state.after = null; state.frontier = null; state.selected = null; state.content = null; refresh(); };
$('next-page').onclick = () => { if (state.next) { cancel(); clear(); state.after = state.next; state.selected = null; state.content = null; refresh(); } };
$('logout').onclick = async () => { try { await api('logout', {}); } finally { closed('网页会话已结束。', true); } };
document.addEventListener('visibilitychange', () => { if (document.hidden) { cancel(); clear(); clearDirectory(); if ($('scope-dialog').open) $('scope-dialog').close(); } else if (state.active) refresh(); });
window.addEventListener('pagehide', () => closed('网页会话已离开。'));
window.addEventListener('pageshow', event => { if (event.persisted) start(); });
async function start() {
  try {
    const login = bootstrap ? await api('bootstrap', { token: bootstrap }) : await api('session');
    bootstrap = null; state.csrf = login.csrf; state.active = true; clearInterval(poller); poller = setInterval(refresh, 5000); route('memories');
  } catch { bootstrap = null; closed('请使用终端打印的一次性链接打开网页；不要分享该链接。'); }
}
start();
