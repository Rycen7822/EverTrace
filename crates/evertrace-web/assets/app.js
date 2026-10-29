const $ = id => document.getElementById(id);
const navigation = [...document.querySelectorAll('.sidebar [data-route]')];
const routes = Object.fromEntries(navigation.map(button => [button.dataset.route, button.querySelector('span').textContent.trim()]));
const kinds = { semantic_digest: '摘要', atom_revision: '记忆条目', procedure_revision: '方法', core_membership: 'Core 成员', revision_proposal_revision: '修订提议' };
const navPaths = {
  overview: 'm3 10 9-7 9 7v10H3V10Zm6 10v-7h6v7',
  memories: 'M3 3h7v7H3V3Zm11 0h7v7h-7V3ZM3 14h7v7H3v-7Zm11 0h7v7h-7v-7Z',
  work: 'M8 4H4v17h16V4h-4M8 2h8v5H8V2Zm0 10h8m-8 4h6',
  research: 'M9 3h6m-4 0v7L4 21h16l-7-11V3M8 15h8',
  sources: 'M14 2H5v20h14V7l-5-5Zm0 0v6h5M8 13h8m-8 4h6',
  review: 'M9 3H3v18h18v-6M8 11l4 4L22 5',
  system: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Zm0-6v3m0 14v3M2 12h3m14 0h3M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2',
};
for (const button of navigation) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const [key, value] of Object.entries({ class: 'icon', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(key, value);
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', navPaths[button.dataset.route]); svg.append(path); button.prepend(svg);
}
const contentStates = { too_large: '正文超出当前读取上限；分块阅读尚未接入。', access_denied: '当前没有正文读取权限。', missing: '正文已不存在。', unsupported: '当前不支持展开此类正文。', unavailable: '正文暂时不可用。' };
const fragment = location.hash.slice(1);
let bootstrap = /^bootstrap=[0-9a-f]{64}$/.test(fragment) ? fragment.slice(10) : null;
const state = { route: Object.hasOwn(routes, fragment) ? fragment : 'memories', csrf: null, authenticated: false, after: null, frontier: null, next: null, selected: null, controller: null };
// No object refs, paths, search text or bootstrap credential remain in the URL.
history.replaceState(null, '', `#${state.route}`);
const channel = new BroadcastChannel('evertrace-web-session');

function clean(value) { return String(value ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '�'); }
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = clean(text);
  if (className) element.className = className;
  return element;
}
function notice(text) { $('notice').textContent = text; $('notice').hidden = false; }
function cancel() { state.controller?.abort(); state.controller = null; }
function clearReader() {
  $('memory-items').replaceChildren(); $('detail-body').replaceChildren(); $('detail-ref').textContent = '';
  $('system-status').replaceChildren(); $('page-count').textContent = ''; $('next-page').disabled = true;
  state.next = null; state.selected = null;
}
function closeLocal(message, broadcast = true) {
  cancel(); clearReader(); state.csrf = null; state.authenticated = false; state.after = null; state.frontier = null;
  $('reader').hidden = true; $('system-panel').hidden = true;
  $('connection-status').textContent = '网页会话已结束'; $('status-dot').className = 'status-dot gray';
  notice(message);
  if (broadcast) channel.postMessage('closed');
}
channel.onmessage = event => { if (event.data === 'closed') closeLocal('网页会话已结束，请重新运行 evertrace --web。', false); };
async function api(path, body, signal) {
  const headers = { 'X-EverTrace-Web': '1' };
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; if (state.csrf) headers['X-EverTrace-CSRF'] = state.csrf; }
  const response = await fetch(`/api/${path}`, { method: body === undefined ? 'GET' : 'POST', headers,
    body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer', signal });
  if (!response.ok) {
    if (response.status === 401 && state.authenticated) closeLocal('网页会话已过期，请重新运行 evertrace --web。');
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}
function current(controller) { return state.controller === controller && !controller.signal.aborted && !document.hidden; }
function begin() { cancel(); const controller = new AbortController(); state.controller = controller; return controller; }
function failure(controller) {
  if (!current(controller)) return;
  clearReader(); state.after = null; state.frontier = null;
  $('connection-status').textContent = '读取不可用'; $('status-dot').className = 'status-dot gray';
  notice('读取失败，旧内容已清除。请确认 daemon、版本和所选配置一致，再点击刷新。');
}
function section(title, value, code = false) {
  const block = node('section'); block.append(node('h3', title), node(code ? 'pre' : 'p', value, code ? '' : 'memory-prose')); return block;
}
function scopeLabel(scope) {
  if (!scope) return null;
  if (scope.kind === 'global') return '全局（仍受适用条件限制）';
  if (scope.kind === 'task') return `任务 ${scope.task_id}`;
  if (scope.kind === 'repository') return `仓库 ${scope.repository_instance_id || scope.repository_id}`;
  if (scope.kind === 'worktree') return `工作树 ${scope.worktree_instance_id || scope.worktree_id}`;
  return null;
}
function conditionText(value) {
  if (value.kind === 'always') return '始终适用';
  const expression = value.expr;
  if (value.kind === 'constraint' && expression.op === 'eq') return `${expression.field === 'phase' ? '阶段' : expression.field} = ${expression.value.value}`;
  return null;
}
function renderDetail(item) {
  const body = $('detail-body'); body.replaceChildren();
  $('detail-ref').textContent = clean(item.revision_ref || item.object_ref || item.stable_key);
  const semantic = item.semantic_detail;
  const title = node('div', undefined, 'detail-title');
  const badges = node('div', undefined, 'badges');
  badges.append(node('span', kinds[item.object_kind] || item.object_kind, 'badge'));
  const epistemic = { unverified: '未验证', supported: '有证据支持', refuted: '已反驳', not_applicable: '不适用' };
  if (item.epistemic) badges.append(node('span', epistemic[item.epistemic] || item.epistemic, 'badge'));
  const content = semantic?.content;
  const value = content?.value;
  const excerpt = content?.kind === 'procedure' ? value.draft.title : content?.kind === 'atom' ? value.value.text.split('\n')[0].slice(0, 80) : kinds[item.object_kind] || item.object_kind;
  title.append(badges, node('h2', excerpt), node('p', scopeLabel(value?.scope || value?.draft?.scope) || item.scope_ref || '范围未提供'));
  body.append(title);
  if (!semantic || semantic.state !== 'ready' || !semantic.content) {
    body.append(node('p', contentStates[semantic?.state] || '当前条目没有可展开的语义正文。'));
    return;
  }
  const { kind } = semantic.content;
  if (kind === 'atom') {
    body.append(node('div', value.value.text, 'memory-prose'));
    const scope = node('div', undefined, 'detail-scope');
    const condition = conditionText(value.applicability_expr);
    scope.append(node('div', condition ? `适用条件：${condition}` : '适用条件见下方原始结构。'));
    body.append(scope);
    if (!condition) body.append(section('条件原始结构', JSON.stringify(value.applicability_expr, null, 2), true));
  } else if (kind === 'digest') {
    const labels = { progress_delta: '进展', decision_delta: '决定', failed_routes: '未走通的路线', resolved_items: '已解决', open_loops: '待处理', outcome_delta: '结果' };
    for (const [field, label] of Object.entries(labels)) {
      for (const delta of value.application[field]) {
        body.append(section(`${label} · ${delta.label}`, delta.value));
        if (delta.direct_refs.length) body.append(section('来源引用', delta.direct_refs.join('\n'), true));
      }
    }
    for (const omission of value.application.omissions) body.append(section(`未覆盖 · ${omission.category}`, omission.reason));
    body.append(section('完整性', value.application.completeness));
  } else if (kind === 'procedure') {
    const draft = value.draft;
    body.append(section(draft.title, draft.summary));
    for (const [label, field] of [['适用条件', 'applicability_expr'], ['避用条件', 'avoid_expr'], ['步骤', 'actions'], ['完成条件', 'done']]) {
      body.append(section(label, JSON.stringify(draft[field], null, 2), true));
    }
    if (draft.pitfalls.length) body.append(section('注意事项', draft.pitfalls.join('\n')));
  } else if (kind === 'core_membership') {
    body.append(section('成员关系', `Atom revision: ${value.atom_revision_id}\nActive: ${value.active}`));
  }
  const metadata = node('div', undefined, 'detail-metadata');
  for (const [label, value] of [['Authority', item.authority], ['Epistemic', item.epistemic], ['Lifecycle', item.lifecycle], ['Revision', item.revision_ref]]) {
    if (!value) continue;
    const pair = node('div', undefined, 'metadata-item'); pair.append(node('small', label), node('span', value)); metadata.append(pair);
  }
  body.append(metadata);
}
async function select(item, frontier) {
  if (!state.authenticated) return;
  const controller = begin(); state.selected = item.stable_key;
  $('detail-body').replaceChildren(node('p', '正在读取正文…'));
  try {
    const data = await api('read', { kind: 'detail', surface: 'explorer', object_ref: item.stable_key, expected_frontier: frontier, expected_revision_ref: item.revision_ref }, controller.signal);
    if (!current(controller)) return;
    if (data.kind !== 'snapshot' || data.items.length !== 1) {
      $('detail-body').replaceChildren(node('p', data.kind === 'conflict' ? '记录已变化，请刷新后重新选择。' : '当前条目不可读或已不存在。'));
      $('detail-ref').textContent = ''; return;
    }
    if (data.status !== 'ready') notice(`当前数据不完整：${clean(data.degraded_reasons.join('、'))}`);
    renderDetail(data.items[0]);
    for (const row of $('memory-items').children) { const selected = row.dataset.key === item.stable_key; row.classList.toggle('selected', selected); row.setAttribute('aria-pressed', String(selected)); }
  } catch { failure(controller); }
  finally { if (state.controller === controller) state.controller = null; }
}
async function refresh() {
  if (!state.authenticated || document.hidden || state.controller) return;
  const controller = begin();
  try {
    const health = await api('status', undefined, controller.signal);
    if (!current(controller)) return;
    $('connection-status').textContent = 'daemon 已连接'; $('status-dot').className = 'status-dot green';
    if (state.route === 'system') {
      $('system-status').replaceChildren(section('协议版本', health.protocol_version), section('运行模式', health.mode), section('算法版本', health.algorithm_revision));
      notice('这是当前 daemon 的连接状态。配置、任务和维护操作尚未接入。'); return;
    }
    if (state.route !== 'memories') return;
    const data = await api('read', { kind: 'list', surface: 'explorer', explorer_selection: 'memories', expected_frontier: state.frontier, after: state.after, limit: 32 }, controller.signal);
    if (!current(controller)) return;
    const selected = state.selected;
    clearReader();
    if (data.kind !== 'snapshot' || !Number.isSafeInteger(data.frontier)) {
      state.after = null; state.frontier = null;
      notice('记录已变化，旧内容已清除；点击刷新读取当前列表。'); return;
    }
    state.frontier = data.frontier; state.next = data.next_cursor;
    $('page-count').textContent = `本页 ${data.items.length} 条`;
    notice(data.status === 'ready' ? '只读连接已建立。修改、搜索和范围筛选仍未开放。' : `当前数据不完整：${clean(data.degraded_reasons.join('、'))}`);
    for (const item of data.items) {
      const row = node('button', undefined, `memory-item${item.stable_key === selected ? ' selected' : ''}`);
      row.dataset.key = item.stable_key;
      const top = node('div', undefined, 'memory-item-top'); top.append(node('span', kinds[item.object_kind] || item.object_kind, 'badge'));
      row.append(top, node('h3', item.semantic_detail?.preview || item.object_ref || item.stable_key), node('p', item.scope_ref || '只读条目；点击展开正文'));
      row.onclick = () => select(item, data.frontier);
      $('memory-items').append(row);
    }
    if (!data.items.length) $('memory-items').append(node('div', data.status === 'ready' ? '当前没有可读记忆。' : '暂时无法完整读取记忆。', 'empty'));
    $('next-page').disabled = !data.next_cursor;
    const chosen = data.items.find(item => item.stable_key === selected);
    state.controller = null;
    if (chosen) await select(chosen, data.frontier);
    else $('detail-body').append(node('div', '选择一条记忆查看正文与修订。', 'empty'));
  } catch { failure(controller); }
  finally { if (state.controller === controller) state.controller = null; }
}
function route(name) {
  cancel(); clearReader(); state.after = null; state.frontier = null; state.route = name;
  history.replaceState(null, '', `#${name}`); document.title = `${routes[name]} · EverTrace`;
  $('breadcrumb').textContent = routes[name]; $('page-title').textContent = routes[name]; $('frame').className = `app-main route-${name}`;
  for (const button of navigation) {
    button.classList.toggle('active', button.dataset.route === name);
    if (button.dataset.route === name) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  }
  $('reader').hidden = name !== 'memories' || !state.authenticated;
  $('system-panel').hidden = name !== 'system' || !state.authenticated;
  $('page-description').textContent = name === 'memories' ? '查看 daemon 中当前可读的记忆。暂未开放网页修改。' : name === 'system' ? '查看当前本机连接，不运行探测或维护任务。' : '此页尚未接入后端。当前可以查看记忆和连接状态。';
  if (!['memories', 'system'].includes(name)) notice('尚未接入，不展示演示数据，也不会执行操作。');
  refresh();
}
for (const button of navigation) button.onclick = () => route(button.dataset.route);
$('refresh').onclick = refresh;
$('first-page').onclick = () => { cancel(); state.after = null; state.frontier = null; clearReader(); refresh(); };
$('next-page').onclick = () => { const after = state.next; cancel(); clearReader(); state.after = after; refresh(); };
document.querySelector('.brand').onclick = event => { event.preventDefault(); route('memories'); };
$('logout').onclick = async () => { try { await api('logout', {}); } catch { /* Local contents must still be cleared. */ } finally { closeLocal('网页会话已结束，请重新运行 evertrace --web。'); } };
document.addEventListener('visibilitychange', () => { if (document.hidden) { cancel(); clearReader(); } else refresh(); });
window.addEventListener('pagehide', () => { cancel(); clearReader(); state.csrf = null; state.authenticated = false; });
window.addEventListener('pageshow', event => { if (event.persisted) start(); });
setInterval(refresh, 5000);
async function start() {
  try {
    let session;
    try { session = await api('session'); }
    catch { if (!bootstrap) throw new Error('bootstrap required'); session = await api('bootstrap', { token: bootstrap }); }
    bootstrap = null; state.csrf = session.csrf; state.authenticated = true;
    route(state.route);
  } catch { bootstrap = null; closeLocal('无法验证网页会话。请使用终端输出的短时链接，或重新运行 evertrace --web。'); }
}
start();
