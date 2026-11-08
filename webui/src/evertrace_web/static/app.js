const $ = (id) => document.getElementById(id);
let fragment = location.hash.slice(1);
let bootstrap = /^bootstrap=[0-9a-f]{64}$/.test(fragment) ? fragment.slice(10) : null;
fragment = null;
let poller = null;
const state = {
  csrf: null,
  active: false,
  route: "memories",
  query: {
    selection: { kind: "all" },
    include_global: false,
    kind: "all",
    order: "recorded_newest",
    epistemic_status: null,
    authority: null,
    atom_lifecycle: null,
    time_range: null,
  },
  after: null,
  frontier: null,
  next: null,
  selected: null,
  content: null,
  revisions: null,
  links: null,
  comparison: null,
  compareBase: null,
  controller: null,
};
let restoreSourceControls = false;
let archive = null;
let sourceQuery = { session_id: null, source_instance_id: null, unassigned_only: false };
const directory = {
  query: { parent: null, name: "" },
  after: null,
  frontier: null,
  next: null,
  controller: null,
};
history.replaceState(null, "", "#memories");
const channel = new BroadcastChannel("evertrace-web-session");
function clear() {
  $("source-picked").textContent = "";
  $("time-applied").textContent = "";
  $("memory-items").replaceChildren();
  $("detail-body").replaceChildren();
  $("detail-ref").textContent = "";
  $("system-status").replaceChildren();
  $("page-count").textContent = "";
  $("next-page").disabled = true;
}
function cancel() {
  state.controller?.abort();
  state.controller = null;
}
function notice(text) {
  $("notice").textContent = text;
}
function closed(text, broadcast = false) {
  archive = null;
  restoreSourceControls = false;
  sourceQuery = { session_id: null, source_instance_id: null, unassigned_only: false };
  $("source-session").value = "";
  $("source-record-id").value = "";
  $("work-record-id").value = "";
  $("work-record-revision").value = "";
  $("source-unassigned").checked = false;
  cancel();
  clear();
  state.comparison = null;
  state.compareBase = null;
  state.links = null;
  clearInterval(poller);
  poller = null;
  state.csrf = null;
  state.active = false;
  $("job-id").value = "";
  state.query = {
    ...state.query,
    selection: { kind: "all" },
    include_global: false,
    time_range: null,
  };
  $("time-from").value = "";
  $("time-until").value = "";
  $("time-from").setCustomValidity("");
  $("time-until").setCustomValidity("");
  $("time-basis").value = "recorded";
  updateScopeControls();
  clearDirectory();
  if ($("scope-dialog").open) $("scope-dialog").close();
  state.selected = null;
  state.content = null;
  state.revisions = null;
  state.after = null;
  state.frontier = null;
  state.next = null;
  $("reader").hidden = true;
  $("system-panel").hidden = true;
  notice(text);
  if (broadcast) channel.postMessage("closed");
}
channel.onmessage = () => closed("网页会话已结束；请重新运行 evertrace --web。");
async function api(path, body, signal) {
  const headers = { "X-EverTrace-Web": "1" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    if (state.csrf) headers["X-EverTrace-CSRF"] = state.csrf;
  }
  let response;
  try {
    response = await fetch("/api/" + path, {
      method: body === undefined ? "GET" : "POST",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      signal,
    });
  } catch (error) {
    if (error.name !== "AbortError")
      closed("网页服务连接已断开，旧内容已清除；可刷新页面重新连接。");
    throw error;
  }
  if (response.status === 401) closed("网页会话已失效，旧内容已清除。", true);
  if (!response.ok) throw new Error("read unavailable");
  return response.json();
}
function fragmentInto(target, html) {
  const template = document.createElement("template");
  template.innerHTML = html;
  target.replaceChildren(template.content);
}
function navigationControls() {
  for (const button of $("detail-body").querySelectorAll("[data-result-compare]"))
    button.disabled = state.compareBase?.kind !== "result_evidence";
  for (const button of $("detail-body").querySelectorAll("[data-nav-back]"))
    button.hidden = !state.selected?.path?.length;
  for (const button of $("detail-body").querySelectorAll("[data-compare-key]"))
    button.disabled =
      !state.compareBase ||
      state.compareBase.object !== state.selected?.object ||
      state.compareBase.kind !== state.selected?.kind;
}
async function readComparison(comparison, controller, scroll = 0) {
  const frontier = comparison.after ? comparison.frontier : state.frontier;
  const result = await api(
    "read",
    { kind: comparison.research ? "research_compare" : "compare", query: comparison.query, after: comparison.after, frontier },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden) return;
  if (result.conflict) {
    state.comparison = { query: comparison.query, after: null, frontier: null, research: comparison.research === true };
    $("detail-ref").textContent = "";
    fragmentInto(
      $("detail-body"),
      `<p>比较水位有更新；没有混入另一份结果。</p>
      <button class="button" type="button" data-compare-first>从头读取对照</button>
      <button class="button" type="button" data-nav-back hidden>返回上一页</button>`,
    );
    navigationControls();
    return;
  }
  fragmentInto($("detail-body"), result.html);
  navigationControls();
  $("detail-body").scrollTop = scroll;
  state.comparison = {
    query: comparison.query,
    after: comparison.after,
    frontier: result.frontier,
    next: result.next_cursor,
    research: comparison.research === true,
  };
  const next = $("detail-body").querySelector("[data-compare-next]");
  if (next) next.disabled = !result.next_cursor;
  if (comparison.research) notice("读取状态和比较资格见下方；此次对照未改变记录或生成结论。");
  $("detail-ref").textContent =
    result.status === "ready"
      ? comparison.query.left.revision_ref + " / " + comparison.query.right.revision_ref
      : "";
}
async function openComparisonPage(after = null) {
  if (!state.comparison || !state.active || document.hidden) return;
  cancel();
  const controller = new AbortController();
  state.controller = controller;
  const comparison = { ...state.comparison, after };
  state.comparison = comparison;
  $("detail-body").replaceChildren();
  $("detail-ref").textContent = "";
  try {
    await readComparison(comparison, controller);
  } catch {
    if (state.controller === controller && !controller.signal.aborted) {
      clear();
      notice("比较读取失败，旧字段和计数已清除。");
    }
  } finally {
    if (state.controller === controller) state.controller = null;
  }
}
function compareResult(button, pin) {
  const current = { key: button.dataset.resultBase || button.dataset.resultCompare,
    revision: button.dataset.revision, object: button.dataset.object, kind: "result_evidence" };
  if (pin) {
    state.compareBase = current;
    navigationControls();
    notice("已固定结果左侧；打开另一份结果后选择对照。资格由原生比较器判定。");
    return;
  }
  const left = state.compareBase;
  if (left?.kind !== "result_evidence") return;
  const query = { left: { stable_key: left.key, revision_ref: left.revision },
    right: { stable_key: current.key, revision_ref: current.revision } };
  followRecord(current, { comparison: { query, after: null, frontier: state.frontier, research: true } });
}
function pinComparison() {
  const item = state.selected;
  if (!item?.revision) return;
  state.compareBase = {
    key: item.key,
    revision: item.revision,
    object: item.object,
    kind: item.kind,
  };
  navigationControls();
  notice("已固定左侧；请在此对象的历史中选择右侧修订。");
}
function compareRevision(button) {
  const left = state.compareBase,
    current = state.selected;
  if (!left || !current || left.object !== current.object || left.kind !== current.kind) return;
  const right = {
    key: button.dataset.compareKey,
    revision: button.dataset.revision,
    object: current.object,
    kind: current.kind,
  };
  const query = {
    left: { stable_key: left.key, revision_ref: left.revision },
    right: { stable_key: right.key, revision_ref: right.revision },
  };
  followRecord(right, { comparison: { query, after: null, frontier: state.frontier } });
}
function readComparisonSide(side) {
  const reference = state.comparison?.query[side];
  if (!reference) return;
  followRecord(
    {
      key: reference.stable_key,
      revision: reference.revision_ref,
      object: state.selected.object,
      kind: state.selected.kind,
    },
    { content: { representation: "semantic_json", after: null } },
  );
}

async function detail(item, frontier, controller, scroll = 0) {
  const result = await api(
    "read",
    {
      kind: "detail",
      reference: item.key,
      frontier,
      revision: item.revision || null,
      surface: item.surface || "explorer",
      object_kind: item.kind,
    },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden) return;
  if (result.conflict) {
    $("detail-body").textContent = "记录已变化，请重新选择；没有改用当前版本。";
    return;
  }
  fragmentInto($("detail-body"), result.html);
  // Native resolves exact public-ID aliases; keep its identity for subsequent navigation.
  if (result.selection) state.selected = { ...state.selected, ...result.selection };
  const source = $("detail-body").querySelector(".source-presentation");
  if (source) source.textContent = result.source_preview || "";
  const semantic = $("detail-body").querySelector(".semantic-body");
  if (semantic && typeof result.semantic_text === "string") semantic.textContent = result.semantic_text;
  navigationControls();
  $("detail-ref").textContent = item.surface && !result.selection ? "" : result.selection?.revision || item.revision || item.key;
  $("detail-body").scrollTop = scroll;
  if (item.surface && !result.selection) state.selected = null;
}
async function readSources(item, after, frontier, controller, scroll = 0) {
  const result = await api(
    "read",
    { kind: "sources", reference: item.key, revision: item.revision, frontier, after },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden) return;
  if (result.conflict) {
    state.links = { after: null, frontier: null, next: null };
    $("detail-ref").textContent = "";
    fragmentInto(
      $("detail-body"),
      `<p>关联水位有更新；没有拼接旧页。</p>
      <button class="button" type="button" data-sources-open>从头读取关联</button>
      <button class="button" type="button" data-nav-back hidden>返回上一条记录</button>`,
    );
    navigationControls();
    return;
  }
  fragmentInto($("detail-body"), result.html);
  navigationControls();
  $("detail-ref").textContent = item.revision;
  $("detail-body").scrollTop = scroll;
  state.links = { after, frontier: result.frontier, next: result.next_cursor };
  $("detail-body").querySelector("[data-sources-next]").disabled = !result.next_cursor;
}
async function openSources(after = null) {
  const item = state.selected;
  if (!item?.revision || !state.active || document.hidden) return;
  const frontier = after ? state.links?.frontier : state.frontier;
  if (frontier === null || frontier === undefined) return;
  cancel();
  const controller = new AbortController();
  state.controller = controller;
  state.comparison = null;
  state.content = null;
  state.revisions = null;
  state.links = { after, frontier, next: null };
  $("detail-body").replaceChildren();
  $("detail-ref").textContent = "";
  try {
    await readSources(item, after, frontier, controller);
  } catch {
    if (state.controller === controller && !controller.signal.aborted) {
      clear();
      notice("来源关联暂不可读取，旧内容已清除。");
    }
  } finally {
    if (state.controller === controller) state.controller = null;
  }
}
function followRecord(item, restore = null) {
  const current = state.selected;
  if (!current) return;
  const path = current.path || [];
  if (path.length >= 16) {
    notice("阅读路径已到上限，请先返回上一页。");
    return;
  }
  const parent = {
    item: {
      key: current.key,
      revision: current.revision,
      object: current.object,
      kind: current.kind,
      compiled: current.compiled ? { ...current.compiled } : null,
    },
    scroll: $("detail-body").scrollTop,
    links: state.links ? { after: state.links.after, frontier: state.links.frontier } : null,
    revisions: state.revisions
      ? { after: state.revisions.after, frontier: state.revisions.frontier }
      : null,
    comparison: state.comparison
      ? {
          query: state.comparison.query,
          after: state.comparison.after,
          frontier: state.comparison.frontier,
          research: state.comparison.research === true,
        }
      : null,
  };
  select({ ...item, path: [...path, parent] }, restore);
}
function followSource(button) {
  followRecord({
    key: button.dataset.linkKey,
    revision: button.dataset.revision,
    object: button.dataset.object,
    kind: button.dataset.kind,
  });
}
function returnSource() {
  const path = state.selected?.path || [];
  const previous = path.at(-1);
  if (!previous) return;
  if (previous.archive) {
    state.selected = null;
    state.content = null;
    state.links = null;
    state.revisions = null;
    state.comparison = null;
    archive = previous.archive;
    openArchive(archive.query, archive.after, archive.parent, previous.scroll, archive.frontier);
    return;
  }
  select({ ...previous.item, path: path.slice(0, -1) }, previous);
}
async function readRevisions(item, after, frontier, controller, scroll = 0) {
  const result = await api(
    "read",
    { kind: "revisions", reference: item.key, revision: item.revision, frontier, after },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden) return;
  if (result.conflict) {
    state.revisions = { after: null, frontier: null, next: null };
    $("detail-ref").textContent = "";
    fragmentInto(
      $("detail-body"),
      `<p>历史水位有更新；没有拼接两次结果。</p>
      <button class="button" type="button" data-revisions-open>从头读取历史</button>
      <button class="button" type="button" data-nav-back hidden>返回上一条记录</button>`,
    );
    navigationControls();
    return;
  }
  fragmentInto($("detail-body"), result.html);
  navigationControls();
  $("detail-ref").textContent = item.revision;
  $("detail-body").scrollTop = scroll;
  state.revisions = { after, frontier: result.frontier, next: result.next_cursor };
  $("detail-body").querySelector("[data-revisions-next]").disabled = !result.next_cursor;
}
async function openRevisions(after = null) {
  const item = state.selected;
  if (!item?.revision || !state.active || document.hidden) return;
  const frontier = after ? state.revisions?.frontier : state.frontier;
  if (frontier === null || frontier === undefined) return;
  cancel();
  const controller = new AbortController();
  state.controller = controller;
  state.comparison = null;
  state.links = null;
  state.content = null;
  state.revisions = { after, frontier, next: null };
  $("detail-body").replaceChildren();
  $("detail-ref").textContent = "";
  try {
    await readRevisions(item, after, frontier, controller);
  } catch {
    if (state.controller === controller && !controller.signal.aborted) {
      clear();
      notice("历史暂时不可读取，旧内容已清除。");
    }
  } finally {
    if (state.controller === controller) state.controller = null;
  }
}
async function readContent(item, representation, after, controller, scroll = 0) {
  const result = await api(
    "read",
    {
      kind: "content",
      reference: item.key,
      revision: item.revision,
      frontier: state.frontier,
      representation,
      after,
    },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden) return;
  if (result.conflict) {
    state.content = null;
    $("detail-ref").textContent = "";
    fragmentInto(
      $("detail-body"),
      '<p>读取水位不可用；没有换用当前修订。</p><button class="button" type="button" data-nav-back hidden>返回上一条记录</button>',
    );
    navigationControls();
    return;
  }
  fragmentInto($("detail-body"), result.html);
  navigationControls();
  const body = $("detail-body").querySelector(".chunk-text");
  if (body) body.textContent = result.text;
  $("detail-body").scrollTop = scroll;
  // Retain only the requested identity/cursor for fresh authorization checks;
  // never retain text, previews, ranges or byte counts outside the DOM.
  state.content = {
    representation,
    after,
    previous: result.previous_cursor,
    next: result.next_cursor,
  };
  $("detail-ref").textContent = result.state === "ready" ? item.revision : "";
}
async function openContent(representation, after = null) {
  const item = state.selected;
  if (!item?.revision || !state.active || document.hidden) return;
  cancel();
  const controller = new AbortController();
  state.controller = controller;
  state.comparison = null;
  state.links = null;
  state.revisions = null;
  state.content = { representation, after };
  $("detail-body").replaceChildren();
  $("detail-ref").textContent = "";
  try {
    await readContent(item, representation, after, controller);
  } catch {
    if (state.controller === controller && !controller.signal.aborted) {
      clear();
      state.content = null;
      notice("分段读取失败，旧正文和区间已清除。");
    }
  } finally {
    if (state.controller === controller) state.controller = null;
  }
}
async function select(item, restore = null) {
  state.content = restore?.content || null;
  state.revisions = restore?.revisions || null;
  state.links = restore?.links || null;
  state.comparison = restore?.comparison || null;
  cancel();
  const controller = new AbortController();
  state.controller = controller;
  state.selected = item;
  $("detail-ref").textContent = "";
  $("detail-body").textContent = "正在读取…";
  try {
    await readSelection(item, controller, restore?.scroll || 0);
  } catch {
    if (state.controller === controller && !controller.signal.aborted) {
      clear();
      notice("读取失败，旧内容已清除。");
    }
  } finally {
    if (state.controller === controller) state.controller = null;
  }
}
async function readSelection(item, controller, scroll = 0) {
  if (item.kind === "compiled_projection") await readCompiledEntries(item, controller, scroll);
  else if (item.surface === "inbox" || item.surface === "system")
    await detail(item, state.frontier, controller, scroll);
  else if (state.comparison) await readComparison(state.comparison, controller, scroll);
  else if (state.revisions)
    await readRevisions(
      item,
      state.revisions.after,
      state.revisions.after ? state.revisions.frontier : state.frontier,
      controller,
      scroll,
    );
  else if (state.content)
    await readContent(item, state.content.representation, state.content.after, controller, scroll);
  else if (state.links)
    await readSources(
      item,
      state.links.after,
      state.links.after ? state.links.frontier : state.frontier,
      controller,
      scroll,
    );
  else await detail(item, state.frontier, controller, scroll);
}
async function readArchive(controller, scroll = 0) {
  const current = archive;
  const page = await api(
    "read",
    {
      kind: "source_archive",
      query: current.query,
      after: current.after,
      expected_frontier: current.after ? current.frontier : state.frontier,
    },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden || archive !== current) return;
  $("detail-ref").textContent = "";
  if (page.conflict) {
    archive = { ...current, after: null, frontier: null, next: null };
    fragmentInto(
      $("detail-body"),
      `<p>归档目录水位已变化，没有拼接旧页。</p>
      <button class="button" type="button" data-archive-first>重新读取本组首页</button>
      <button class="button" type="button" data-archive-up>返回上一页</button>`,
    );
    return;
  }
  archive = { ...current, query: page.query, frontier: page.frontier, next: page.next_cursor };
  fragmentInto($("detail-body"), page.html);
  $("detail-body").scrollTop = scroll;
}
async function openArchive(query, after = null, parent = null, scroll = 0, frontier = null) {
  if (!state.active || document.hidden) return;
  cancel();
  const controller = new AbortController();
  state.controller = controller;
  state.selected = null;
  state.content = null;
  state.links = null;
  state.revisions = null;
  state.comparison = null;
  archive = { query, after, parent, frontier: frontier || state.frontier, next: null };
  $("detail-body").replaceChildren();
  $("detail-ref").textContent = "";
  try {
    await readArchive(controller, scroll);
  } catch {
    if (state.controller === controller && !controller.signal.aborted) {
      clear();
      notice("归档记录读取不可用，旧字段和续页引用已清除。");
    }
  } finally {
    if (state.controller === controller) state.controller = null;
  }
}
function archiveUp() {
  if (archive?.parent) {
    const parent = archive.parent;
    openArchive(parent.query, parent.after, null, parent.scroll, parent.frontier);
  } else {
    cancel();
    clear();
    archive = null;
    state.selected = null;
    refresh();
  }
}
async function readCatalogue(controller) {
  const page = await api(
    "read",
    {
      kind: "source_catalog",
      query: { ...sourceQuery, selection: state.query.selection },
      after: state.after,
      expected_frontier: state.after ? state.frontier : null,
    },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden || state.route !== "sources") return;
  const listScroll = $("memory-items").scrollTop,
    detailScroll = $("detail-body").scrollTop;
  clear();
  if (page.conflict) {
    state.after = null;
    state.frontier = null;
    state.next = null;
    notice("来源目录水位已变化；请从首页重新读取。");
    return;
  }
  state.frontier = page.frontier;
  state.next = page.next_cursor;
  sourceQuery = page.query;
  if (restoreSourceControls) {
    $("source-session").value = page.query.session_id || "";
    $("source-unassigned").checked = page.query.unassigned_only;
    restoreSourceControls = false;
  }
  fragmentInto($("memory-items"), page.html);
  // A known exact source record need not belong to the current catalogue page.
  if (state.selected) await readSelection(state.selected, controller, detailScroll);
  else if (archive) await readArchive(controller, detailScroll);
  else fragmentInto($("detail-body"), page.detail_html);
  $("memory-items").scrollTop = listScroll;
  $("detail-body").scrollTop = detailScroll;
  const count = page.matching_count === null ? "未知" : page.matching_count;
  $("page-count").textContent = `本页 ${page.count} / 匹配 ${count} 个已登记来源`;
  const conditions = [scopeLabel(page.query.selection)];
  if (page.query.session_id) conditions.push("Session：" + page.query.session_id);
  if (page.query.source_instance_id) conditions.push("来源：" + page.query.source_instance_id);
  if (page.query.unassigned_only) conditions.push("仅历史归属未确定");
  $("source-picked").textContent = conditions.join("；") + "；按原生来源键分页，不是时间排序。";
  $("next-page").disabled = !page.next_cursor;
  notice(
    page.state === "ready"
      ? "只读已登记来源，范围匹配不改变历史归属。目录不表示宿主历史已全部发现，也不表示正文已获许可或全部导入。"
      : `来源范围当前不可读取（${page.state}），计数未知；没有换成全部来源。`,
  );
}
function changeSourceQuery(patch) {
  cancel();
  clear();
  archive = null;
  state.selected = null;
  state.content = null;
  state.links = null;
  state.revisions = null;
  state.comparison = null;
  sourceQuery = { ...sourceQuery, ...patch };
  state.after = null;
  state.frontier = null;
  state.next = null;
  refresh();
}
$("source-filter").onsubmit = (event) => {
  event.preventDefault();
  changeSourceQuery({
    session_id: $("source-session").value.trim() || null,
    source_instance_id: null,
    unassigned_only: $("source-unassigned").checked,
  });
};
$("source-all").onclick = () => changeSourceQuery({ source_instance_id: null });
$("source-record-lookup").onsubmit = (event) => {
  event.preventDefault();
  const key = $("source-record-id").value.trim();
  if (!key) return;
  archive = null;
  select({ key, kind: $("source-record-kind").value, revision: null, object: null, path: [] });
};
$("work-record-lookup").onsubmit = (event) => {
  event.preventDefault();
  const key = $("work-record-id").value.trim();
  if (!key) return;
  select({ key, kind: $("work-record-kind").value, revision: $("work-record-revision").value.trim() || null,
    object: null, path: [] });
};
async function readWork(controller) {
  const research = state.route === "research", usage = state.route === "usage";
  const scroll = $("detail-body").scrollTop;
  clear();
  state.frontier ??= "0";
  if (!research && !usage && !state.selected && state.query.selection.kind === "task") {
    state.selected = { key: state.query.selection.task_id, kind: "task", revision: null, object: null, path: [] };
  }
  $("memory-items").textContent = usage
    ? "读取精确 Recall 快照、usage、负面事实或复核事件。这里不是请求清单，不调用 @due，不推进使用阶段。"
    : research
    ? "读取已知 Run、ResultEvidence 或研究 Atom；从结果可回到其对应 Run 的精确条件。"
    : "按精确工作记录读取。Task 的工作线、Workstream 的片段可从详情中的关联逐项展开。";
  $("page-count").textContent = usage ? "精确使用证据 · 非请求总数"
    : research ? "精确研究记录 · 非全局实验清单" : "精确工作 · 非任务总数";
  if (state.selected) await readSelection(state.selected, controller, scroll);
  else $("detail-body").textContent = usage
    ? "输入已知记录 ID。未选或不可用不表示没有召回义务或负面证据，不填入示例状态。"
    : research
    ? "输入已知研究记录 ID。未选记录不显示为空实验清单，也不填入示例结果。"
    : "请从范围目录选择 Task，或输入已知工作 ID。没有把未选择工作显示成空列表。";
  notice(usage
    ? "只读已存状态，不 claim、不投递、不推进 usage，也不从检索记录推断 agent 已采用。"
    : research
    ? "只读原始条件和证据；不自动聚合、判断胜出或接受为长期结论。"
    : "只读所选修订；目标、计划、来源关联和工作状态不等于执行、采用或验证完成。");
}
async function readObservations(controller, health) {
  const system = state.route === "system";
  const page = await api(
    "read",
    {
      kind: system ? "jobs" : "inbox",
      after: state.after,
      expected_frontier: state.after ? state.frontier : null,
    },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden) return;
  const listScroll = $("memory-items").scrollTop,
    detailScroll = $("detail-body").scrollTop;
  clear();
  if (system)
    $("system-status").textContent = "daemon：" + health.mode + " · 配置：" + health.config_hash;
  if (page.conflict) {
    state.after = null;
    state.frontier = null;
    state.next = null;
    state.selected = null;
    notice("列表水位有变化；请从首页重新读取。没有拼接旧页。");
    return;
  }
  state.frontier = page.frontier;
  state.next = page.next_cursor;
  fragmentInto($("memory-items"), page.html);
  $("memory-items").scrollTop = listScroll;
  $("page-count").textContent = "本页 " + page.count + " · 原生分页";
  $("next-page").disabled = !page.next_cursor;
  notice(
    page.degraded
      ? "原生读取有降级；不代表所有任务或审核已正常。"
      : system
        ? "只观察原任务和结果；离开页面不取消任务，也不自动重试。可用 CLI 返回的 Job ID 精确回查。"
        : "只读原生待处理队列。网页接受、编辑、拒绝及其它治理操作仍未开放。",
  );
  const selected = state.selected;
  if (
    selected &&
    (selected.direct ||
      [...$("memory-items").children].some((row) => row.dataset.key === selected.key))
  ) {
    await readSelection(selected, controller, detailScroll);
  } else {
    state.selected = null;
    $("detail-body").textContent = system
      ? "选择任务查看原生状态与结果。"
      : "选择待处理条目查看原生详情。";
  }
}
$("job-lookup").onsubmit = async (event) => {
  event.preventDefault();
  if (!state.active || document.hidden || state.route !== "system" || state.frontier === null)
    return;
  const jobId = $("job-id").value.trim();
  cancel();
  const controller = new AbortController();
  state.controller = controller;
  state.selected = null;
  $("detail-body").replaceChildren();
  $("detail-ref").textContent = "";
  try {
    const result = await api(
      "read",
      { kind: "job", job_id: jobId, frontier: state.frontier },
      controller.signal,
    );
    if (state.controller !== controller || document.hidden || state.route !== "system") return;
    if (result.conflict) {
      notice("任务水位有变化；没有用其它任务代替，请刷新后重查。");
      return;
    }
    fragmentInto($("detail-body"), result.html);
    state.selected = result.selection ? { ...result.selection, direct: true } : null;
    $("detail-ref").textContent = state.selected?.key || "";
  } catch {
    if (state.controller === controller && !controller.signal.aborted) {
      clear();
      notice("Job ID 无效或任务暂不可读；没有提交或重试任务。");
    }
  } finally {
    if (state.controller === controller) state.controller = null;
  }
};
async function readOverview(controller) {
  const selected = state.selected;
  const listScroll = $("memory-items").scrollTop,
    detailScroll = $("detail-body").scrollTop;
  const page = await api(
    "read",
    {
      kind: "overview",
      query: {
        selection: state.query.selection,
        include_global: state.query.include_global,
        time_range: state.query.time_range,
        limit: Number($("overview-limit").value),
      },
      expected_frontier: null,
    },
    controller.signal,
  );
  if (state.controller !== controller || document.hidden || state.route !== "overview") return;
  clear();
  if (page.conflict) {
    state.frontier = null;
    state.selected = null;
    notice("读取水位已变化，请刷新。");
    return;
  }
  state.frontier = page.frontier;
  fragmentInto($("memory-items"), page.html);
  $("memory-items").scrollTop = listScroll;
  showTimeRange(
    page.query.time_range,
    page.query.time_range?.basis === "event" ? "event_newest" : "recorded_newest",
  );
  $("page-count").textContent = "所选范围 · 当前修订";
  notice(
    !page.scope_available
      ? "范围不可用，未回退到其它范围。"
      : !page.complete
        ? "部分记录或正文未能完整读取；未触发生成或重试。"
        : "只读当前记录；这里的读取不会生成摘要，也不会提交或接受提案。",
  );
  const visible = selected && [...$("memory-items").querySelectorAll(".memory-item")]
    .some((row) => row.dataset.key === selected.key);
  if (selected && (selected.direct || visible)) {
    await readSelection(selected, controller, detailScroll);
  } else {
    state.selected = null;
    $("detail-body").textContent = "选择一条记录查看原文。";
  }
}
async function refresh() {
  if (!state.active || document.hidden) return;
  if ($("scope-dialog").open) {
    await loadDirectory();
    return;
  }
  if (state.controller) return;
  const controller = new AbortController();
  state.controller = controller;
  try {
    const health = await api("status", undefined, controller.signal);
    if (state.controller !== controller || document.hidden) return;
    $("connection-status").textContent = "daemon 已连接";
    if (state.route === "system" || state.route === "review") {
      await readObservations(controller, health);
      return;
    }
    if (["work", "research", "usage"].includes(state.route)) {
      await readWork(controller);
      return;
    }
    if (state.route === "sources") {
      await readCatalogue(controller);
      return;
    }
    if (state.route === "overview") {
      await readOverview(controller);
      return;
    }
    if (state.route !== "memories") return;
    if (isCompiledKind(state.query.kind)) {
      await readCompiledDirectory(controller);
      return;
    }
    const page = await api(
      "read",
      {
        kind: "list",
        query: state.query,
        after: state.after,
        expected_frontier: state.after ? state.frontier : null,
      },
      controller.signal,
    );
    if (state.controller !== controller || document.hidden) return;
    const listScroll = $("memory-items").scrollTop,
      detailScroll = $("detail-body").scrollTop;
    clear();
    if (page.conflict) {
      state.after = null;
      state.frontier = null;
      state.next = null;
      state.selected = null;
      state.content = null;
      state.revisions = null;
      notice("分页水位已变化；请刷新读取当前列表。");
      return;
    }
    state.frontier = page.frontier;
    state.next = page.next_cursor;
    fragmentInto($("memory-items"), page.html);
    $("memory-items").scrollTop = listScroll;
    showTimeRange(page.query.time_range, page.query.order);
    $("page-count").textContent = !page.scope_available
      ? "范围不可用 · 计数未知"
      : "本页 " +
        page.count +
        " · " +
        (page.counts_complete ? "" : "已判定范围 ≥ ") +
        "筛选 " +
        page.matching_count +
        " / 当前条目 " +
        page.total_count;
    $("next-page").disabled = !page.next_cursor;
    notice(
      !page.scope_available
        ? "所选身份不存在、已移除或当前不可用，未改查全部范围。"
        : page.degraded
          ? "只读数据有降级；不是完整成功。"
          : "按" + browseOrderLabel(page.query.order) + "浏览所选关联范围；计数不是可读正文数，也不表示方法可执行。" +
            (page.unresolved_scope_count !== "0"
              ? " 另有 " + page.unresolved_scope_count + " 条元数据归属尚未判定。"
              : "") +
            " 搜索和网页修改尚未接入。",
    );
    const anchor = state.selected?.path?.[0]?.item || state.selected;
    if (
      anchor &&
      [...$("memory-items").children].some(
        (row) => row.dataset.object === anchor.object && row.dataset.kind === anchor.kind,
      )
    ) {
      await readSelection(state.selected, controller, detailScroll);
    } else {
      state.selected = null;
      state.content = null;
      state.revisions = null;
      state.links = null;
      state.comparison = null;
      $("detail-body").textContent = "选择一条记忆查看正文。";
    }
  } catch {
    if (state.controller === controller && !controller.signal.aborted) {
      clear();
      if (state.route === "sources") {
        restoreSourceControls = true;
        $("source-session").value = "";
        $("source-unassigned").checked = false;
      }
      $("connection-status").textContent = "读取不可用";
      notice("daemon 或读取暂不可用，旧内容已清除。");
    }
  } finally {
    if (state.controller === controller) state.controller = null;
  }
}
function route(name) {
  archive = null;
  cancel();
  clear();
  state.comparison = null;
  state.compareBase = null;
  state.links = null;
  state.route = name;
  state.after = null;
  state.frontier = null;
  state.selected = null;
  state.content = null;
  state.revisions = null;
  history.replaceState(null, "", "#" + name);
  for (const button of document.querySelectorAll("[data-route]")) {
    const active = button.dataset.route === name;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  const reading = ["overview", "memories"].includes(name);
  const connected = ["overview", "memories", "sources", "work", "research", "usage", "review", "system"].includes(name);
  $("reader").hidden = !state.active || !connected;
  $("system-panel").hidden = !state.active || name !== "system";
  $("job-lookup").hidden = name !== "system";
  $("job-id").value = "";
  $("records-title").textContent =
    { overview: "范围总览", sources: "已登记来源", work: "所选工作", research: "研究记录", usage: "使用证据",
      review: "待处理条目", system: "后台任务" }[name] || "记忆记录";
  $("source-filter").hidden = name !== "sources";
  $("source-record-lookup").hidden = name !== "sources";
  $("work-record-lookup").hidden = !["work", "research", "usage"].includes(name);
  $("work-record-label").textContent = name === "usage" ? "记录 ID（精确）"
    : name === "research" ? "研究记录 ID" : "工作记录 ID";
  $("work-record-id").setAttribute("aria-label", $("work-record-label").textContent);
  $("work-record-submit").textContent = name === "usage" ? "读取使用证据" : "读取工作记录";
  for (const option of $("work-record-kind").options) {
    option.hidden = name === "usage" && !["recall_need", "procedure_usage_revision",
      "procedure_negative_evidence", "procedure_negative_review"].includes(option.value);
    option.disabled = option.hidden;
  }
  $("work-record-help").textContent = name === "usage"
    ? "usage 可选原修订；负面事实填证据 ID，复核填事件 ID。Need 修订仅固定计划身份，不选历史快照。"
    : name === "research"
    ? "选择 Run、ResultEvidence 或 Atom，输入精确 ID；修订留空只绑定原生当前版本。"
    : "也可从范围目录选择 Task。这里只读所选工作及有界关联，不把全局范围当空任务列表。";
  if (["work", "research", "usage"].includes(name)) {
    $("work-record-kind").value = name === "usage" ? "recall_need" : name === "research" ? "experiment_run" : "task";
    $("work-record-id").value = "";
    $("work-record-revision").value = "";
  }
  $("time-filter").hidden = !reading;
  $("overview-limit-control").hidden = name !== "overview";
  $("first-page").parentElement.hidden = ["overview", "work", "research", "usage"].includes(name);
  document.querySelector(".browse-filters").hidden = name !== "memories";
  $("scope-open").hidden = !reading && !["sources", "work"].includes(name);
  $("include-global").parentElement.hidden = !reading;
  const label = document.querySelector('[data-route="' + name + '"]')?.textContent.trim() || name;
  $("breadcrumb").textContent = label;
  $("page-title").textContent = label;
  readingControls();
  $("page-description").textContent =
    "独立 Python Web，只读调用现有 daemon；未接入的页面不使用示例数据。";
  notice(
    connected ? "正在读取…"
      : "该页面尚未接入真实后端。",
  );
  refresh();
}
$("detail-body").onclick = (event) => {
  const button = event.target.closest(
    `[data-archive-revisions], [data-archive-revision], [data-archive-record],
    [data-archive-next], [data-archive-first], [data-archive-up], [data-content-open],
    [data-content-nav], [data-revisions-open], [data-revisions-next], [data-detail-open],
    [data-revision-key], [data-sources-open], [data-sources-next], [data-link-key],
    [data-nav-back], [data-compare-base], [data-compare-key], [data-compare-side],
    [data-result-base], [data-result-compare],
    [data-compare-first], [data-compare-next], [data-compiled-first], [data-compiled-next], [data-compiled-refresh]`,
  );
  if (!button || button.disabled) return;
  if (button.hasAttribute("data-compiled-refresh")) {
    state.selected = null;
    state.after = null;
    state.frontier = null;
    refresh();
    return;
  }
  if (button.hasAttribute("data-compiled-first") || button.hasAttribute("data-compiled-next")) {
    const item = state.selected;
    if (item?.kind !== "compiled_projection" || !item.compiled) return;
    const next = button.hasAttribute("data-compiled-next");
    select({ ...item, compiled: { ...item.compiled,
      after: next ? item.compiled.next : null,
      frontier: next ? item.compiled.frontier : state.frontier,
    } });
    return;
  }
  if (button.hasAttribute("data-archive-revisions")) {
    openArchive({ kind: "revisions", source_instance_id: button.dataset.archiveRevisions });
    return;
  }
  if (button.hasAttribute("data-archive-revision")) {
    const parent = archive
      ? { ...archive, scroll: $("detail-body").scrollTop, parent: null }
      : null;
    openArchive(
      {
        kind: "records",
        source_instance_id: button.dataset.archiveSource,
        source_revision: button.dataset.archiveRevision,
        from_sequence: null,
        until_sequence: null,
      },
      null,
      parent,
    );
    return;
  }
  if (button.hasAttribute("data-archive-next")) {
    if (archive?.next)
      openArchive(archive.query, archive.next, archive.parent, 0, archive.frontier);
    return;
  }
  if (button.hasAttribute("data-archive-first")) {
    if (archive) openArchive(archive.query, null, archive.parent);
    return;
  }
  if (button.hasAttribute("data-archive-up")) {
    archiveUp();
    return;
  }
  if (button.hasAttribute("data-archive-record")) {
    const parent = { archive: { ...archive }, scroll: $("detail-body").scrollTop };
    select({
      key: button.dataset.linkKey,
      revision: button.dataset.revision,
      object: button.dataset.object,
      kind: button.dataset.kind,
      path: [parent],
    });
    return;
  }
  if (button.hasAttribute("data-result-base")) compareResult(button, true);
  else if (button.hasAttribute("data-result-compare")) compareResult(button, false);
  else if (button.hasAttribute("data-compare-base")) pinComparison();
  else if (button.dataset.compareKey) compareRevision(button);
  else if (button.dataset.compareSide) readComparisonSide(button.dataset.compareSide);
  else if (button.hasAttribute("data-compare-first")) openComparisonPage();
  else if (button.hasAttribute("data-compare-next")) {
    if (state.comparison?.next) openComparisonPage(state.comparison.next);
  } else if (button.hasAttribute("data-sources-open")) openSources();
  else if (button.hasAttribute("data-sources-next")) {
    if (state.links?.next) openSources(state.links.next);
  } else if (button.hasAttribute("data-nav-back")) returnSource();
  else if (button.dataset.linkKey) followSource(button);
  else if (button.hasAttribute("data-revisions-open")) openRevisions();
  else if (button.hasAttribute("data-revisions-next")) {
    if (state.revisions?.next) openRevisions(state.revisions.next);
  } else if (button.hasAttribute("data-detail-open")) select(state.selected);
  else if (button.dataset.revisionKey)
    select({
      ...state.selected,
      key: button.dataset.revisionKey,
      revision: button.dataset.revision,
    });
  else if (button.dataset.contentOpen) openContent(button.dataset.contentOpen);
  else if (state.content)
    openContent(
      state.content.representation,
      button.dataset.contentNav === "first" ? null : state.content[button.dataset.contentNav],
    );
};
$("memory-items").onclick = (event) => {
  const source = event.target.closest("[data-catalog-source]");
  if (source) {
    changeSourceQuery({ source_instance_id: source.dataset.catalogSource });
    return;
  }
  const row = event.target.closest(".memory-item");
  if (row?.dataset.projection) {
    select({ key: row.dataset.key, kind: "compiled_projection", compiled: {
      query: { kind: "entries", reference: row.dataset.projection,
        selection: state.query.selection, include_global: state.query.include_global },
      after: null, frontier: state.frontier, next: null,
    } });
    return;
  }
  if (row)
    select({
      key: row.dataset.key,
      revision: row.dataset.revision,
      object: row.dataset.object,
      kind: row.dataset.kind,
      surface: row.dataset.surface,
    });
};
for (const button of document.querySelectorAll("[data-route]"))
  button.onclick = () => route(button.dataset.route);
function clearDirectory() {
  directory.controller?.abort();
  directory.controller = null;
  directory.query = { parent: null, name: "" };
  directory.after = null;
  directory.frontier = null;
  directory.next = null;
  $("scope-items").replaceChildren();
  $("scope-notice").textContent = "";
  $("scope-parent").textContent = "";
  $("scope-name").value = "";
  $("scope-next").disabled = true;
}
function scopeLabel(selection) {
  const labels = {
    all: "全部元数据",
    global: "仅 global",
    unassigned: "未归属元数据",
    task: "任务",
    repository: "仓库",
    worktree: "工作树",
  };
  const id = selection.task_id || selection.repository_id || selection.worktree_id;
  return labels[selection.kind] + (id ? " " + id.split(":").at(-1).slice(0, 8) : "");
}
async function loadDirectory() {
  if (!state.active || document.hidden || !$("scope-dialog").open || directory.controller) return;
  const controller = new AbortController();
  directory.controller = controller;
  $("scope-items").replaceChildren();
  $("scope-notice").textContent = "正在从后端复核目录…";
  $("scope-next").disabled = true;
  try {
    const page = await api(
      "read",
      {
        kind: "scopes",
        query: directory.query,
        after: directory.after,
        expected_frontier: directory.after ? directory.frontier : null,
      },
      controller.signal,
    );
    if (directory.controller !== controller || document.hidden || !$("scope-dialog").open) return;
    if (page.conflict) {
      directory.after = null;
      directory.frontier = null;
      directory.next = null;
      $("scope-notice").textContent = "目录有更新；保留原条件，请回到目录首页重新读取。";
      return;
    }
    directory.frontier = page.frontier;
    directory.next = page.next_cursor;
    fragmentInto($("scope-items"), page.html);
    $("scope-next").disabled = !page.next_cursor;
    $("scope-parent").textContent = directory.query.parent
      ? scopeLabel(directory.query.parent)
      : "全部已知身份";
    $("scope-notice").textContent = !page.parent_available
      ? "父级身份不可用，未回退到全部目录。"
      : !page.complete
        ? "本次目录读取未完成；可继续下一页或重新读取。"
        : !page.names_complete
          ? `部分任务名称暂时读不到；${page.matching_count === null ? "匹配数量未知" : `共 ${page.matching_count} 个匹配身份`}。`
          : `共 ${page.matching_count} 个匹配身份，按稳定身份排列；目录可见不代表正文可读。`;
  } catch {
    if (directory.controller === controller && !controller.signal.aborted) {
      $("scope-items").replaceChildren();
      $("scope-notice").textContent = "目录读取不可用，旧名称和路径已清除。";
    }
  } finally {
    if (directory.controller === controller) directory.controller = null;
  }
}
function directoryQuery(parent, name = "") {
  directory.controller?.abort();
  directory.controller = null;
  directory.query = { parent, name };
  directory.after = null;
  directory.frontier = null;
  directory.next = null;
  loadDirectory();
}
function updateScopeControls() {
  const selection = state.query.selection;
  $("include-global").checked = state.query.include_global;
  $("include-global").disabled = !["task", "repository", "worktree"].includes(selection.kind);
  $("scope-open").textContent = "范围：" + scopeLabel(selection);
}
function chooseScope(selection) {
  cancel();
  clear();
  state.comparison = null;
  state.compareBase = null;
  state.after = null;
  state.frontier = null;
  state.next = null;
  state.selected = null;
  state.content = null;
  state.query = { ...state.query, selection, include_global: false };
  archive = null;
  state.links = null;
  state.revisions = null;
  sourceQuery = { ...sourceQuery, source_instance_id: null };
  updateScopeControls();
  $("scope-dialog").close();
  refresh();
}
$("scope-open").onclick = () => {
  cancel();
  clear();
  clearDirectory();
  $("scope-dialog").showModal();
  loadDirectory();
};
$("scope-close").onclick = () => $("scope-dialog").close();
$("scope-dialog").onclose = () => {
  clearDirectory();
  refresh();
};
$("scope-search").onsubmit = (event) => {
  event.preventDefault();
  directoryQuery(directory.query.parent, $("scope-name").value.trim());
};
$("scope-root").onclick = () => {
  $("scope-name").value = "";
  directoryQuery(null);
};
$("scope-first").onclick = () => directoryQuery(directory.query.parent, directory.query.name);
$("scope-next").onclick = () => {
  if (directory.next) {
    directory.after = directory.next;
    loadDirectory();
  }
};
$("scope-items").onclick = (event) => {
  const button = event.target.closest("[data-scope-choose], [data-scope-children]");
  if (!button) return;
  const selection = JSON.parse(button.closest(".scope-entry").dataset.selection);
  if (button.hasAttribute("data-scope-choose")) chooseScope(selection);
  else {
    $("scope-name").value = "";
    directoryQuery(selection);
  }
};
for (const button of document.querySelectorAll("[data-scope-fixed]"))
  button.onclick = () => chooseScope({ kind: button.dataset.scopeFixed });
$("include-global").onchange = () => changeQuery();
$("overview-limit").onchange = () => changeQuery();
function isCompiledKind(kind) {
  return ["compiled_wiki", "compiled_core"].includes(kind);
}
function readingControls() {
  const compiled = state.route === "memories" && isCompiledKind(state.query.kind);
  $("browse-order").disabled = compiled;
  $("time-filter").hidden = !["overview", "memories"].includes(state.route) || compiled;
}
async function readCompiledDirectory(controller) {
  const selected = state.selected;
  const listScroll = $("memory-items").scrollTop;
  const detailScroll = $("detail-body").scrollTop;
  const page = await api("read", {
    kind: "compiled", query: { kind: "directory", selection: state.query.selection,
      include_global: state.query.include_global, projection: state.query.kind === "compiled_wiki" ? "wiki" : "core" },
    expected_frontier: state.after ? state.frontier : null, after: state.after,
  }, controller.signal);
  if (state.controller !== controller || document.hidden) return;
  clear();
  if (page.conflict) {
    state.after = null;
    state.frontier = null;
    state.selected = null;
    notice("编译目录水位已变，请从头读取；没有拼接两次结果。");
    return;
  }
  fragmentInto($("memory-items"), page.html);
  $("memory-items").scrollTop = listScroll;
  state.frontier = page.frontier;
  state.next = page.next_cursor;
  $("next-page").disabled = !state.next;
  $("page-count").textContent = page.matching_count === null ? "总数未完整计算" : page.matching_count + " 个编译视图";
  const status = page.scope_available ? (page.complete ? "已读取当前发布的编译目录；打开后按原权限读取来源。" :
    "目录读取不完整；未把未知数量当成零。") : "所选范围不可用，没有回退到全部范围。";
  notice(status + "读取水位：" + page.frontier + "；目录按原生引用分页，不使用资产时间排序。");
  if (selected && page.scope_available) {
    const visible = [...$("memory-items").querySelectorAll(".memory-item")].some(row => row.dataset.key === selected.key);
    if (visible || selected.direct) {
      state.selected = selected;
      await readSelection(selected, controller, detailScroll);
      return;
    }
  }
  state.selected = null;
}
async function readCompiledEntries(item, controller, scroll = 0) {
  const view = item.compiled;
  if (!view) throw new Error("missing compiled selection");
  const page = await api("read", {
    kind: "compiled", query: view.query, expected_frontier: view.frontier, after: view.after,
  }, controller.signal);
  if (state.controller !== controller || document.hidden) return;
  $("detail-ref").textContent = item.key;
  if (page.conflict) {
    fragmentInto($("detail-body"), `<p>编译视图读取水位已变；未拼接旧来源。</p>
      <button class="button" type="button" data-compiled-refresh>刷新目录后重新选择</button>
      <button class="button" type="button" data-nav-back hidden>返回上一条记录</button>`);
  } else {
    fragmentInto($("detail-body"), page.html);
    state.selected = { ...item, compiled: { ...view, frontier: page.frontier, next: page.next_cursor } };
  }
  navigationControls();
  $("detail-body").scrollTop = scroll;
}
function changeQuery() {
  cancel();
  clear();
  state.comparison = null;
  state.compareBase = null;
  state.after = null;
  state.frontier = null;
  state.selected = null;
  state.content = null;
  state.revisions = null;
  state.next = null;
  const atomAxes = ["all", "facts_and_constraints"].includes($("reading-kind").value);
  for (const id of ["epistemic-filter", "authority-filter", "lifecycle-filter"]) {
    $(id).disabled = !atomAxes;
    if (!atomAxes) $(id).value = "";
  }
  state.query = {
    selection: state.query.selection,
    include_global: $("include-global").checked,
    kind: $("reading-kind").value,
    order: $("browse-order").value,
    epistemic_status: $("epistemic-filter").value || null,
    authority: $("authority-filter").value || null,
    atom_lifecycle: $("lifecycle-filter").value || null,
    time_range: isCompiledKind($("reading-kind").value) ? null : state.query.time_range,
  };
  if (isCompiledKind(state.query.kind)) {
    $("time-from").value = "";
    $("time-until").value = "";
  }
  readingControls();
  refresh();
}
function displayTime(value) {
  if (value === null) return "不限";
  const us = BigInt(value);
  let ms = us / 1000n;
  if (us < 0n && us % 1000n !== 0n) ms -= 1n;
  if (ms < -8640000000000000n || ms > 8640000000000000n) return value + " µs";
  return (
    new Date(Number(ms)).toLocaleString(undefined, { hour12: false }) +
    (us % 1000n ? " (" + value + " µs)" : "")
  );
}
function browseOrderLabel(order) {
  return {
    recorded_newest: "录入顺序（后录入在前）",
    recorded_oldest: "录入顺序（先录入在前）",
    event_newest: "原生事件时间（从新到旧）",
    event_oldest: "原生事件时间（从旧到新）",
  }[order] || "未知顺序";
}
function showTimeRange(range, order = state.query.order) {
  const sort = "按" + browseOrderLabel(order) + "排序。";
  $("time-applied").textContent = range
    ? "已应用" +
      (range.basis === "recorded" ? "原生录入时间" : "原生事件时间") +
      "：[" +
      displayTime(range.from_us) +
      "，" +
      displayTime(range.until_us) +
      ")；不是来源消息或生成时间。" + sort
    : "未设时间窗；" + sort;
}
function timeInput(id) {
  const value = $(id).value;
  if (!value) return null;
  const ms = new Date(value).getTime();
  if (!Number.isSafeInteger(ms)) throw new Error("invalid time");
  const us = BigInt(ms) * 1000n;
  if (us < -(2n ** 63n) || us >= 2n ** 63n) throw new Error("invalid time");
  return us.toString();
}
for (const id of ["time-from", "time-until"])
  $(id).oninput = () => {
    $("time-from").setCustomValidity("");
    $("time-until").setCustomValidity("");
  };
$("time-filter").onsubmit = (event) => {
  event.preventDefault();
  try {
    const from = timeInput("time-from"),
      until = timeInput("time-until");
    if (from === null && until === null) {
      $("time-from").setCustomValidity("请至少填写一个时间边界。");
      $("time-from").reportValidity();
      return;
    }
    if (from !== null && until !== null && BigInt(from) >= BigInt(until)) {
      $("time-until").setCustomValidity("终点必须晚于起点。");
      $("time-until").reportValidity();
      return;
    }
    state.query.time_range = { basis: $("time-basis").value, from_us: from, until_us: until };
    changeQuery();
  } catch {
    $("time-from").setCustomValidity("无法无损转换这个时间，请重新填写。");
    $("time-from").reportValidity();
  }
};
$("time-clear").onclick = () => {
  $("time-from").value = "";
  $("time-until").value = "";
  $("time-from").setCustomValidity("");
  $("time-until").setCustomValidity("");
  state.query.time_range = null;
  changeQuery();
};
for (const id of [
  "reading-kind",
  "browse-order",
  "epistemic-filter",
  "authority-filter",
  "lifecycle-filter",
])
  $(id).onchange = changeQuery;
$("refresh").onclick = refresh;
$("first-page").onclick = () => {
  cancel();
  clear();
  state.after = null;
  state.frontier = null;
  state.selected = null;
  state.content = null;
  state.revisions = null;
  refresh();
};
$("next-page").onclick = () => {
  if (state.next) {
    cancel();
    clear();
    state.after = state.next;
    state.selected = null;
    state.content = null;
    state.revisions = null;
    refresh();
  }
};
$("detail-body").onsubmit = (event) => {
  if (event.target.id !== "archive-range" || !archive) return;
  event.preventDefault();
  const from = $("archive-from").value || null,
    until = $("archive-until").value || null;
  if ((from && !/^[0-9]{1,20}$/.test(from)) || (until && !/^[0-9]{1,20}$/.test(until))) return;
  openArchive(
    { ...archive.query, from_sequence: from, until_sequence: until },
    null,
    archive.parent,
  );
};
$("logout").onclick = async () => {
  try {
    await api("logout", {});
  } finally {
    closed("网页会话已结束。", true);
  }
};
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    $("job-id").value = "";
    restoreSourceControls = true;
    $("source-session").value = "";
    $("source-unassigned").checked = false;
    cancel();
    clear();
    clearDirectory();
    if ($("scope-dialog").open) $("scope-dialog").close();
  } else if (state.active) refresh();
});
window.addEventListener("pagehide", () => closed("网页会话已离开。"));
window.addEventListener("pageshow", (event) => {
  if (event.persisted) start();
});
async function start() {
  try {
    const login = bootstrap ? await api("bootstrap", { token: bootstrap }) : await api("session");
    bootstrap = null;
    state.csrf = login.csrf;
    state.active = true;
    clearInterval(poller);
    poller = setInterval(refresh, 5000);
    route("memories");
  } catch {
    bootstrap = null;
    closed("请使用终端打印的一次性链接打开网页；不要分享该链接。");
  }
}
start();
