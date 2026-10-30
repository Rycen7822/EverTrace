# 使用方法 / Usage

[文档目录 / Documentation](README.md) · [安装与接入 / Setup](getting-started.md)

## 基本使用流程 / Everyday workflow

正常工作 → 获准采集/导入的记录 → 后台摘要；方法提议和后续复核是独立流程。需要回忆时通过 MCP 检索，在结果中查看来源、适用范围和未验证警告。基本记忆无需前台 agent 每次调用 add/organize，也无需你逐条接受摘要。

Normal work → permitted capture/import → background summaries. Method proposals and later review are separate flows. Read memory through MCP when needed, checking source, scope and uncertainty. Basic memory requires neither an add/organize call after each task nor manual acceptance of every summary.

摘要只来自受支持且有正文许可的记录。记录存在、导入已排队、摘要完成、检索返回和“方法确实有效”是不同状态；不要互相替代。后台整理需要新来源证据和预算，不会靠反复启动自动补出缺失事实。

Summaries require supported records with body permission. Record existence, queued import, completed summary, returned content and proven method effectiveness are different states. Review requires new source evidence and budget; restarting does not supply missing facts.

## 本机网页 / Local WebUI

**当前状态：旧 Rust Web 已回撤；正式 `--web` exec、显式隔离组件装配及基础只读记忆/详情/分页/状态已通过真实 daemon/浏览器验证。先按开发说明装配匹配组件。当前版本元数据的后端种类/Atom 状态筛选、录入顺序和 query/frontier 绑定分页计数也已验证；已接入原生 Task/Repository/Worktree 目录与关联范围筛选，global 资产需单独选择或明确包含；原修订语义值的 8 KiB 分段读取已接入，每次复验当前权限；同对象历史分页及 exact 逐版阅读也已接入；详情中的精确来源/直接关联及受保护文本归档分段也已接入；两个指定修订的原生字段比较也已接入；独立来源目录、完整关联、完整范围/搜索、非文本/捕获/制品区间和最终功能/资源验收仍未闭合，旧日志不作为新版本完成证明。**

**Current status: Rust Web was rolled back. Formal CLI exec, explicit isolated assembly and basic Python memory/detail/paging/status have real daemon/browser evidence. Assemble the matching optional component first. Native current-only filters/counts, typed scopes, exact history, source/dependency navigation and protected source-text ranges and native exact-revision field comparison are available. The standalone source directory, source/time filters, full search/governance/management and complete functionality/lifecycle/resource acceptance remain unfinished; old logs are not new acceptance.**

先启动同一构建的 daemon，再在另一终端运行：

Start the matching daemon first, then use a separate terminal:

```sh
evertrace --config /absolute/config.toml --daemon
# 另一个终端 / Separate terminal:
evertrace --config /absolute/config.toml --web
# 可选固定端口 / Optional fixed port:
evertrace --config /absolute/config.toml --web --port 4173
```

打开终端打印的 `http://127.0.0.1:PORT/#bootstrap=...` 链接。它是两分钟内有效的一次性登录凭据，请勿分享或写进日志。服务只监听本机；不自动启动 daemon，不安装宿主接线。Ctrl-C 关闭前台 Web 服务，不停止 daemon。旧 Rust 实现已回撤，独立 Python 基础只读包已建立，正式启动器已用 Unix exec 对接；Python/模板/资源修改不需 Cargo；基础启动链已验证无 `--web` 时不访问 Python/页面资源，缺失组件不影响核心入口。该基础证据不替代完整功能接入后的最终资源复验。

Open the printed loopback URL. Its fragment is a single-use login credential valid for two minutes: do not share or log it. The service listens locally only, never starts a daemon or installs host wiring, and Ctrl-C closes Web without stopping the daemon. The old Rust implementation has been rolled back; an independent Python read-only package exists, its formal launcher now uses Unix exec; no-Cargo Web edits and no dormant Web runtime remain migration targets, not completed claims.

当前 Python 网页默认只列每个对象的当前版本，不混入历史修订；在当前权限允许时显示已有标题和短摘录，而不是只显示内部类型与引用。标题与摘录由原生后端在原修订、来源和删除门检查后提供，不为列表调用模型。Core 规则摘录来自 membership 指定的原 Atom 修订；提案始终标为参考，不把草案展示成正式方法。确定性汇总、模型整理、生成结果未通过检查和普通已有内容摘录分别标明；真值、权威、生命周期、发布和支持状态独立呈现。没有权限时不返回标题、摘录或它们的截短信息；类型和短引用只是占位，不是正文。列表摘录最多 1 KiB，标题最多 512 字节；CSS 也会折叠较长片段，完整内容应打开条目读取。支持后端种类筛选、Atom 真值/权威/生命周期三个独立轴和录入顺序分页。总数与筛选数由原生后端计算，表示当前元数据记录，不是可读正文数量；缺正文权限时不能据此推断正文可用。详情中的“修订历史”列出同一 Atom、Procedure、Core membership、提案或摘要的保留版本，每页 32 条，按录入顺序从新到旧；摘要只有一条不可变记录时就只列这一条。分页游标绑定打开历史时的 exact 源修订及读取水位，水位变化不拼接旧页。选中某版后重新检查权限并读取该版，刷新不会换成 current。历史页只列元数据，不凭状态或序号判断哪版是 current，也不显示已删除版本。“来源与直接关联”只沿原生返回的引用跳转，包含来源、支持和范围依赖；原始对象与共享修订别名的投影会区分，不凭名称或scope猜目标。选中关联记录后可返回原修订及该关联页；只保留至多16层身份/游标/视口，不缓存正文。来源详情显示原生角色、信任和捕获完整性，来源文字没有执行权；保存的Inline与Preview明确区分，字段缺失保持缺失，不补造预览。同一逻辑记忆的两个指定修订也可由原生端比较：先将某版“设为比较左侧”，再在该对象历史中选右侧。左右只是选择方向，不猜时间或真假；每侧重过原来源/删除门，一侧不可读就不返回字段名、值、长度和差异数，不补 current 或空值。字段按JSON Pointer排列，每页8项；缺字段与JSON null分开，字段JSON超过2KiB则明确标注，可分别打开两侧完整语义分段阅读。列表及深层结构作为整个字段比较，不用浏览器diff裁定业务。返回会恢复原历史/比较页的身份、游标和视口，再次读取不缓存旧值。Wiki 历史与完整关联仍未闭合；旧 Rust Web 日志不作为这些能力的证明。语义结构超过原单次上限时可按原修订分段读取，每段至多 8 KiB；Atom 另可按原文读取正文，保留 UTF-8、换行和空白。页面只显示当前段，可前后翻段，不自动加载全文；游标绑定对象、修订和表示，每次都重新检查当前权限及删除门。SourceReceipt/SourceObservation的文本可从Native受保护归档按段读取，不以EvidenceSurface或预览代替。每段重新过当前来源与删除门，并校验CAS、长度、呈现前缀、原观察指纹及脱敏关系；只返回保护后的字节，不恢复秘密。非文本、CaptureReceipt和制品区间仍未闭合。来源范围虽有8KiB响应上限，当前每段仍由Native完整验证/解码归档（编码64MiB/解码128MiB上限），不宣称流式常量内存或完整资源资格。原生列表选页已改为借用canonical typed记录，按原删除/仓库规则完成筛选、计数和keyset后，只物化选中页；不会先为所有候选编码正文。但列表摘录、历史和分段等读面仍有完整快照成本；归档分段仍完整验证/解码，不代表大库读取成本已完成优化。可通过范围按钮按名称、后端记录的路径或分支查找 Task、Repository 和 Worktree，也可查看下级。目录从原生端按至多 64 个候选的窗口读取，仅为这些候选准备直接来源和范围权限输入，不再为列目录取全库记忆正文。冷校验与必要投影追平仍保留；窗口化不代表所有大库读取或资源验收已完成。Task 视图列出该任务及其声明关联的仓库/工作树资产；仓库/工作树视图列出对应资产及关联任务，global 不会自动混入，需单选或勾选“同时列 global”。范围不存在或不可用时显示计数未知，不回退到全部范围；归属未判定时计数标为不完整。计数始终表示元数据，不是可读正文或方法执行资格。任务名称也受当前来源许可约束，暂时读不到的名称不会参与名称匹配，页面会提示结果可能不全；关闭或隐藏页面会清空目录。来源页/未归属来源、来源及时间段过滤、搜索与其余业务页面仍待闭合，不把录入顺序当作事件发生时间。未接入的页面不会显示样例。正文按文本显示，网页会话不将记忆存入 localStorage、IndexedDB 或离线缓存。会话空闲 15 分钟或满 8 小时后失效；可用侧栏按钮提前结束。这里是本机 HTTP，不提供 TLS，也不防护同一 OS 用户下的恶意进程。

The independent Python package now provides native current-only browsing, kind/Atom-axis and typed-scope filters, recording-order keyset pages/counts, permission-checked stored titles/excerpts, semantic details and exact-revision ranges of at most 8 KiB. Detail views also provide 32-item same-object revision pages for Atom, Procedure, Core membership, proposals and digests, newest recorded first; a single immutable digest is not presented as an invented lineage. History continuations bind the exact source and frontier. Selecting a version rechecks current access and never substitutes the current head; metadata alone does not promise body access, and deleted revisions are not listed. Neither status nor sequence is used to guess which version is current. Pin one version as the left side, then select a right version from that logical object's history. Native comparison rechecks each exact side; an unreadable side suppresses all difference names/values/lengths/counts without substituting current or empty values. Eight fields are shown per page, absent differs from JSON null, and field JSON over 2 KiB links to each side's complete exact semantic ranges. Arrays/deep structures are whole fields; this is not browser-derived semantic truth. History/comparison return paths retain only identities/cursors/viewport and reauthorize rather than caching values. Native source/dependency links now open exact records with a bounded identity-only return path. SourceReceipt/SourceObservation text ranges read the complete native-verified protected archive, not a projection or stored preview, with current source/delete checks on every range. Source role/trust/completeness remain explicit; absent presentations are not fabricated. Native CAS/length/prefix/observation-fingerprint/redaction checks fail closed. Each range still fully verifies/decodes its archive within the existing 64 MiB encoded/128 MiB decoded limits, not streaming constant-RSS access. The standalone source directory, Wiki history, complete lineage links, source/time filters, non-text/capture/artifact ranges, search and other business pages remain unfinished. Scope-directory reads use finite native candidate windows and direct source/scope cohorts, retaining canonical freshness and deletion checks; they no longer request all memory bodies. Cold validation/catch-up remains mandatory. Native memory-page selection borrows canonical typed records and materializes only the selected page after original deletion/repository checks, full filtering/counting and keyset selection. List previews, history and body access still use native request-local full snapshots; bounded responses do not prove bounded large-corpus cost or final resource qualification. Old Rust Web evidence does not establish these remaining capabilities. Content is escaped as text without browser database/offline persistence. Sessions expire after 15 idle minutes or eight hours total, or explicitly through the sidebar. This is local HTTP, not TLS or protection against a malicious process running as the same OS user.

## CLI 与 MCP 的区别 / CLI versus MCP

`evertrace --help` 是当前 CLI 参数真源。CLI 以互斥的 `--xxx` 模式提供配置、诊断、安装、管理、备份和 TUI 等入口；旧顶层子命令已停止接受。无参数只显示帮助，不启动服务。**没有 `evertrace search` 或 `evertrace get` 子命令**。search/get 是 MCP 工具的 action。

Use `evertrace --help` for CLI arguments. Mutually exclusive `--xxx` modes handle configuration, diagnostics, installation, administration, backup and TUI. Retired top-level subcommands are rejected; no arguments prints help without starting a service. **There are no `evertrace search` or `evertrace get` CLI subcommands**; these are actions on the MCP tool.

`--config PATH` 必须放在顶层模式之前；CLI、daemon 和 MCP 应使用同一配置，避免连接到不同数据目录。`--config-check` 只校验文件，`--config-show` 只展示该文件合并默认值后的结果，不代表 daemon 当前活动配置或模型连通性。

Put `--config PATH` before the top-level mode, and use the same configuration for the CLI, daemon and MCP so they resolve the same data root. `--config-check` validates the file; `--config-show` shows that file plus defaults, not the daemon's active configuration or provider connectivity.

```sh
evertrace --config /absolute/config.toml --config-check
evertrace --config /absolute/config.toml --config-show
```

新安装器生成的接线使用独立的 `evertrace-mcp --config PATH --mcp ...`；通用入口 `evertrace --config PATH --mcp ...` 仍存在，旧接线由安装/升级流程验证处理。独立程序只接受 `--mcp` 模式，不能用它运行 `--doctor`、`--tui` 等通用 CLI 操作；命令帮助仍查看 `evertrace --help`。当前安装包需要四个同版本程序，见 [README 的程序清单](../README.md#installation-package)，不要沿用只复制三个程序的旧示例。

New installer-managed wiring uses `evertrace-mcp --config PATH --mcp ...`. The general `evertrace --config PATH --mcp ...` entry point remains; installation/upgrade validates existing wiring. The dedicated program accepts only the `--mcp` mode and does not provide general CLI operations such as `--doctor` or `--tui`; use `evertrace --help` for command help. Current packages require four matching programs; see the [README package list](../README.md#installation-package), not older three-program copy examples.

两者都是 stdio MCP 传输，通过本地 UDS 联系 daemon，不监听公开 TCP，也不会替你启动 daemon。加载配置后等待 stdin 输入是正常行为，不是聊天提示符；宿主能发现工具也不证明 daemon 已连接、绑定有效或读取获准。优先使用安装器生成的完整接线，不手改程序路径、删除宿主定位参数，或伪造绑定标识与 claim。

Both are stdio MCP transports using local UDS, not a public TCP listener, and neither starts the daemon for you. Waiting for stdin after loading configuration is normal, not a chat prompt. Tool discovery alone does not establish daemon connectivity, a valid binding or read permission. Prefer the complete installer-generated wiring; do not hand-swap executable paths, remove host locator arguments or fabricate bindings/claims.

## MCP 输入与示例 / MCP input and examples

工具名为 `evertrace`（宿主可能显示为带 MCP server 前缀的名称）。它只有 `search`、`get`、`add`、`organize` 四个 action。参数为必需的 `action`、`workspace`、`input` 和可选 `refs`；`input` 是字符串，不是任意 JSON 对象。额外顶层字段会被拒绝。

The tool is named `evertrace` (a host may show a server-prefixed name). Its four actions are `search`, `get`, `add`, `organize`. Required fields are `action`, `workspace`, `input`; `refs` is optional. `input` is a string, not an arbitrary JSON object. Extra top-level fields are rejected.

`input` 最多 4096 UTF-8 bytes；workspace 最多 4096 bytes；最多 32 个 refs、每个最多 512 bytes。长中文输入不能简单按字符数计算。示例是工具参数，不是终端命令。

`input` is limited to 4096 UTF-8 bytes, workspace to 4096 bytes, and refs to 32 entries of at most 512 bytes each. Multibyte text is not counted by character count. The following are tool arguments, not shell commands.

有可解析的当前上下文时搜索： / Search with a resolvable current context:

```json
{"action":"search","workspace":"@active","input":"Why did the previous database migration fail?"}
```

没有可靠当前绑定时，可用实际仓库/worktree ID，或已知可信仓库的显式路径提示。路径提示不是创建身份或绕过权限的命令，不接受裸相对路径：

Without a reliable current binding, use an actual repository/worktree ID or an explicit path hint for a known trusted repository. A path hint does not create identity or bypass authorization; bare relative paths are not accepted:

```json
{"action":"search","workspace":"path_hint:/absolute/path/to/project","input":"Lessons from the last migration"}
```

读取搜索返回的真实 object ref，将下面占位值替换成返回值，不手工拼造 ID： / Read an actual object ref returned by search; replace the placeholder rather than inventing an ID:

```json
{"action":"get","workspace":"path_hint:/absolute/path/to/project","input":"<object_ref returned by search>"}
```

`@due` 是保留的主动召回输入，仅在宿主提供相应 cue 且独立能力门、绑定和权限都满足时使用；不要用它测试普通关键词搜索。无可靠绑定时，显式范围普通读取仍需满足对应来源/信任条件，并非全库搜索后门。

`@due` is reserved for active recall when a host cue and the independent gate/binding/permissions allow it. Do not use it as a general search test. Explicit-scope reads still require source access and trust; they are not a full-database bypass.

`add`/`organize` 用于支持的显式声明或整理，不是“让记忆正常工作”所必需的日常动作。它们的内部载荷是受限格式；不要让 agent 自行发明 task、接受状态、效果证明或权限字段。人工治理优先在 TUI 查看当前对象和可用操作。

`add`/`organize` serve supported explicit declarations or organization, not mandatory daily bookkeeping. Their payloads are closed formats; do not invent task identities, acceptance states, effectiveness evidence or authority fields. Prefer TUI actions for human governance of current objects.

## 如何理解返回结果 / Interpret results

| 返回内容 / Content | 意义 / Meaning |
|---|---|
| 来源证据、摘要 / Source evidence, digest | 可追溯的事实或派生记忆；不是执行许可。 / Traceable facts or derived memory, not execution permission. |
| 未接受的方法提议 / Unaccepted method proposal | Pending/Validating 的本地参考，效果未验证；不等于正式 Procedure APPLY。 / A local reference with unverified effectiveness, not an accepted Procedure APPLY. |
| 正式方法 / Accepted procedure | 仍有适用范围、版本、状态和使用条件；返回不证明使用成功。 / Still constrained by scope, version, state and use conditions; returned does not mean successfully used. |
| 规范性约束 / Normative constraint | 需要独立策略来源和权限验证；普通文本不能自授此身份。 / Requires separately verified policy source and authority. |
| Warning/partial/unavailable | 阅读警告和来源缺项；不把缺证当成反证，也不忽略降级继续执行危险操作。 / Inspect missing evidence and warnings; absence is not proof, and degraded results are not permission for risky actions. |

## 终端界面 / Terminal UI

```sh
evertrace --config /absolute/config.toml --tui
```

三个主要页面：Inbox 查看待治理的提议；Explorer 浏览来源和对象、详情与关联；System 查看 daemon、配置、后台 job、备份和诊断。显示为空时先刷新，再检查来源许可和任务状态，不猜造对象。

The three main pages are Inbox (proposals), Explorer (sources, objects, details and relations), and System (daemon/configuration/jobs/backups/diagnostics). Refresh and check access/job state before interpreting an empty view.

当前可见页按上次读取结束时间判断自动刷新：System 至少间隔 15 秒，Inbox/Explorer 至少 5 秒。只有已连接、没有读取/待处理请求、编辑/确认弹窗或筛选输入时才会自动刷新；不是固定周期轮询。空闲时可按 `r` 请求手动刷新，不能用它绕过正在处理的操作。

Auto-refresh is measured from the previous read's completion: at least 15 seconds for the visible System page, five seconds for Inbox/Explorer. It requires a connection and no read, pending request, edit/confirmation dialog or filter input; it is not a fixed-rate poll. Press `r` when idle to request a manual refresh, not to bypass an operation already in progress.

这些间隔不是后台采集、摘要或 job 完成的期限。完整诊断可能比普通列表慢；读取失败或耗时较长时，界面可能保留上次数据，应看状态提示，不能把旧数据显示成“任务已经完成”。

These intervals are not capture, summary or job-completion deadlines. Full diagnostics can be slower than list reads. Slow or failed reads may leave the previous data visible; inspect the status rather than treating retained data as proof of completion.

| 按键 / Key | 操作 / Action |
|---|---|
| `1` / `2` / `3` | Inbox / Explorer / System |
| `j` / `k` | 下一项 / 上一项；next / previous |
| `Enter` | 打开所选详情；open selected detail |
| `?` / `:` | 帮助 / 当前命令；help / current commands |
| `/` | 筛选当前页，不是 MCP 全局检索；filter the current page, not a global MCP search |
| `o` | 打开支持的来源/依赖关联；open supported source/dependency relations |
| `Esc` | 取消当前编辑或确认；cancel the current editor/confirmation |
| `r` | 刷新；refresh |
| `n` / `b` | 下一页 / 首页；next / first page |
| `q` | 退出 TUI；quit TUI |
| System 中 `C` | 编辑配置；edit configuration |
| System 中 `B` / `V` | 创建备份 / 验证所选备份；create / verify selected backup |

以页面底部提示和当前对象支持的操作为准；编辑/确认模式下按键含义可能不同。写操作依赖当前 revision/frontier，发生冲突应刷新并重新判断，不循环提交旧版本。Recovery/Forget/Accept 等动作必须先看详情和确认提示。

Use the footer and actions supported by the selected object; keys differ in edit/confirmation modes. Writes depend on current revisions/frontiers. On conflict, refresh and reassess instead of repeatedly submitting stale state. Inspect details before Recovery, Forget or Accept actions.

### 提议与支持详情 / Proposal and support details

`E` 的含义取决于详情：符合条件的待治理提议可进入“编辑并接受”；已验证资产的 support 详情只有在提供替换草稿时才允许“提交替换”。替换草稿必须有实际修改，提交产生 Pending 提议，不直接替换已生效资产，也不自动满足后续接受/资格条件。

`E` depends on the detail: an eligible proposal may offer edit-and-accept; a validated asset's support detail offers submit-replacement only when a replacement draft is available. The draft must actually change. Submitting it creates a Pending proposal, not an immediate replacement of the active asset or automatic acceptance/qualification.

`D` 仅在 support 详情允许全局 Atom 弃用时打开原因编辑，必须填写合法原因；它提交 Pending 弃用提议，不直接删除资产。操作不可用或发生冲突时，查看当前条件并刷新，不手造 revision、权限或提议载荷来绕过限制。

`D` opens a reason editor only when the support detail permits global Atom deprecation. A valid reason is required; this submits a Pending deprecation proposal, not direct deletion. If unavailable or conflicting, inspect the current conditions and refresh; do not invent revisions, permissions or payloads to bypass them.

## 会话导入和范围管理 / Import and scope administration

元数据回填不等于所有历史正文都会自动上传或导入。先在 System/Explorer 找到实际会话及来源许可；需要手动补导入或撤销时，可使用：

Metadata backfill is not automatic permission to import/upload every historical body. Find the actual session and source access state in System/Explorer. For explicit import/revocation:

```sh
evertrace --config /absolute/config.toml --admin session queue SESSION_ID
evertrace --config /absolute/config.toml --admin session revoke SESSION_ID
```

请求仍受来源、路径、信任和并发/大小限制；queue 是提交，不是完成。revoke 不是删除原始宿主会话文件。查看 System 的最终 job 和诊断。

Requests remain subject to source/path/trust/concurrency/size checks. Queueing is not completion; revocation does not delete the original host session file. Inspect the final System job/diagnostic.

仓库管理命令的 ID、revision、worktree 和可选 inventory job 必须来自当前状态： / Repository administration requires IDs, revisions, worktrees and optional inventory jobs from current state:

```sh
evertrace --config /absolute/config.toml --admin repository disable REPOSITORY_ID REVISION
evertrace --config /absolute/config.toml --admin repository enable REPOSITORY_ID REVISION WORKTREE_ID
evertrace --config /absolute/config.toml --admin repository rescan REPOSITORY_ID REVISION WORKTREE_ID INVENTORY_JOB_ID
```

disable/enable/rescan 不等于 Forget 或物理 purge，也不自动授予宿主未给出的信任。删除、导出和维护的区别见[运维与隐私](operations.md)。

Disable/enable/rescan are not Forget or physical purge, and do not manufacture host trust. See [Operations and privacy](operations.md) for deletion, export and maintenance distinctions.
