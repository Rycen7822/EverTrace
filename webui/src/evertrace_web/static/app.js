const $ = id => document.getElementById(id);
let fragment = location.hash.slice(1);
let bootstrap = /^bootstrap=[0-9a-f]{64}$/.test(fragment) ? fragment.slice(10) : null;
fragment = null;
let poller = null;
const state = { csrf: null, active: false, route: 'memories', after: null, frontier: null, next: null, selected: null, controller: null };
history.replaceState(null, '', '#memories');
const channel = new BroadcastChannel('evertrace-web-session');
function clear() { $('memory-items').replaceChildren(); $('detail-body').replaceChildren(); $('detail-ref').textContent = ''; $('system-status').replaceChildren(); $('page-count').textContent = ''; $('next-page').disabled = true; }
function cancel() { state.controller?.abort(); state.controller = null; }
function notice(text) { $('notice').textContent = text; }
function closed(text, broadcast = false) { cancel(); clear(); clearInterval(poller); poller = null; state.csrf = null; state.active = false; state.selected = null; state.after = null; state.frontier = null; state.next = null; $('reader').hidden = true; $('system-panel').hidden = true; notice(text); if (broadcast) channel.postMessage('closed'); }
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
async function select(item) {
  cancel(); const controller = new AbortController(); state.controller = controller; state.selected = item; $('detail-ref').textContent = ''; $('detail-body').textContent = '正在读取…';
  try { await detail(item, state.frontier, controller); } catch { if (state.controller === controller && !controller.signal.aborted) { clear(); notice('读取失败，旧内容已清除。'); } }
  finally { if (state.controller === controller) state.controller = null; }
}
async function refresh() {
  if (!state.active || state.controller || document.hidden) return;
  const controller = new AbortController(); state.controller = controller;
  try {
    const health = await api('status', undefined, controller.signal);
    if (state.controller !== controller || document.hidden) return;
    $('connection-status').textContent = 'daemon 已连接';
    if (state.route === 'system') { $('system-status').textContent = JSON.stringify(health, null, 2); return; }
    if (state.route !== 'memories') return;
    const page = await api('read', { kind: 'list', after: state.after, expected_frontier: state.after ? state.frontier : null }, controller.signal);
    if (state.controller !== controller || document.hidden) return;
    const listScroll = $('memory-items').scrollTop, detailScroll = $('detail-body').scrollTop;
    clear();
    if (page.conflict) { state.after = null; state.frontier = null; state.selected = null; notice('分页水位已变化；请刷新读取当前列表。'); return; }
    state.frontier = page.frontier; state.next = page.next_cursor;
    fragmentInto($('memory-items'), page.html); $('memory-items').scrollTop = listScroll;
    $('page-count').textContent = '本页 ' + page.count + ' 条';
    $('next-page').disabled = !page.next_cursor;
    notice(page.degraded ? '只读数据有降级；不是完整成功。' : '只读连接已建立；筛选、搜索及网页修改尚未接入。');
    if (state.selected && [...$('memory-items').children].some(row => row.dataset.key === state.selected.key)) await detail(state.selected, page.frontier, controller, detailScroll);
    else { state.selected = null; $('detail-body').textContent = '选择一条记忆查看正文。'; }
  } catch { if (state.controller === controller && !controller.signal.aborted) { clear(); $('connection-status').textContent = '读取不可用'; notice('daemon 或读取暂不可用，旧内容已清除。'); } }
  finally { if (state.controller === controller) state.controller = null; }
}
function route(name) {
  cancel(); clear(); state.route = name; state.after = null; state.frontier = null; state.selected = null;
  history.replaceState(null, '', '#' + name);
  for (const button of document.querySelectorAll('[data-route]')) button.classList.toggle('active', button.dataset.route === name);
  $('reader').hidden = !state.active || name !== 'memories'; $('system-panel').hidden = !state.active || name !== 'system';
  const label = document.querySelector('[data-route="' + name + '"]')?.textContent.trim() || name;
  $('breadcrumb').textContent = label; $('page-title').textContent = label;
  $('page-description').textContent = '独立 Python Web，只读调用现有 daemon；未接入的页面不使用示例数据。';
  notice(['memories', 'system'].includes(name) ? '正在读取…' : '该页面尚未接入真实后端。');
  refresh();
}
$('memory-items').onclick = event => { const row = event.target.closest('.memory-item'); if (row) select({ key: row.dataset.key, revision: row.dataset.revision }); };
for (const button of document.querySelectorAll('[data-route]')) button.onclick = () => route(button.dataset.route);
$('refresh').onclick = refresh;
$('first-page').onclick = () => { cancel(); clear(); state.after = null; state.frontier = null; state.selected = null; refresh(); };
$('next-page').onclick = () => { if (state.next) { cancel(); clear(); state.after = state.next; state.selected = null; refresh(); } };
$('logout').onclick = async () => { try { await api('logout', {}); } finally { closed('网页会话已结束。', true); } };
document.addEventListener('visibilitychange', () => { if (document.hidden) { cancel(); clear(); } else if (state.active) refresh(); });
window.addEventListener('pagehide', () => closed('网页会话已离开。'));
window.addEventListener('pageshow', event => { if (event.persisted) start(); });
async function start() {
  try {
    const login = bootstrap ? await api('bootstrap', { token: bootstrap }) : await api('session');
    bootstrap = null; state.csrf = login.csrf; state.active = true; clearInterval(poller); poller = setInterval(refresh, 5000); route('memories');
  } catch { bootstrap = null; closed('请使用终端打印的一次性链接打开网页；不要分享该链接。'); }
}
start();
