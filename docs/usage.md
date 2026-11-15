# 使用方法 / Usage

[文档目录 / Documentation](README.md) · [安装与接入 / Setup](getting-started.md)

## 基本使用流程 / Everyday workflow

正常工作 → 获准采集/导入的记录 → 后台摘要；方法提议和后续复核是独立流程。需要回忆时通过 MCP 检索，在结果中查看来源、适用范围和未验证警告。基本记忆无需前台 agent 每次调用 add/organize，也无需你逐条接受摘要。

Normal work → permitted capture/import → background summaries. Method proposals and later review are separate flows. Read memory through MCP when needed, checking source, scope and uncertainty. Basic memory requires neither an add/organize call after each task nor manual acceptance of every summary.

摘要只来自受支持且有正文许可的记录。记录存在、导入已排队、摘要完成、检索返回和“方法确实有效”是不同状态；不要互相替代。后台整理需要新来源证据和预算，不会靠反复启动自动补出缺失事实。

Summaries require supported records with body permission. Record existence, queued import, completed summary, returned content and proven method effectiveness are different states. Review requires new source evidence and budget; restarting does not supply missing facts.

## 本机网页 / Local WebUI

**当前状态：开发中。** 旧 Rust Web 已回撤，正式 `--web` exec 与显式隔离组件装配已通过真实 daemon/浏览器验证。使用前先装配匹配的可选组件。

已接入的只读功能见下文。生产搜索、管理写操作、完整关联、部分内容表示及最终资源/桌面验收尚未完成。

**Current status: in development.** Rust Web was rolled back. Formal CLI exec, isolated assembly and basic Python reads have real daemon/browser evidence. Assemble the matching optional component first.

The sections below describe the connected memory/source reads. Production search, governance/management, complete associations, some representations and final functionality/resource/desktop acceptance remain unfinished. Old logs are not new acceptance.

先启动同一构建的 daemon，再在另一终端运行：

Start the matching daemon first, then use a separate terminal:

```sh
evertrace --config /absolute/config.toml --daemon
# 另一个终端 / Separate terminal:
evertrace --config /absolute/config.toml --web
# 可选固定端口 / Optional fixed port:
evertrace --config /absolute/config.toml --web --port 4173
```

打开终端打印的 `http://127.0.0.1:PORT/#bootstrap=...` 链接。它是两分钟内有效的一次性登录凭据，请勿分享或写进日志。

服务只监听本机，不自动启动 daemon，也不安装宿主接线。Ctrl-C 关闭前台 Web 服务，不停止 daemon。

旧 Rust 实现已回撤，独立 Python 基础只读包已建立，正式启动器已用 Unix exec 对接。Python、模板和资源修改不需 Cargo。基础启动链已验证：没有 `--web` 时不访问 Python 或页面资源，缺失组件不影响核心入口。这不替代完整功能接入后的最终资源复验。

Open the printed loopback URL. Its fragment is a single-use login credential valid for two minutes: do not share or log it.

The service is loopback-only. It does not start a daemon or install host wiring, and Ctrl-C stops Web without stopping the daemon.

The Rust Web implementation was rolled back.

The independent Python read-only package and Unix-exec launcher are now connected.

Python, templates and assets can be edited without Cargo.

Basic lazy-start checks show no Python or Web-resource access without `--web`, and a missing optional component does not break core modes.

Final resource acceptance after full integration remains pending.

当前 Python 网页默认只列每个对象的当前版本，不混入历史修订。权限允许时显示已有标题和短摘录；这些字段由原生后端在原修订、来源和删除门检查后提供，不为列表调用模型。

Core 规则摘录来自 membership 指定的原 Atom 修订。提案始终标为参考，不把草案展示成正式方法。确定性汇总、模型整理、生成结果未通过检查和普通已有内容摘录分别标明；真值、权威、生命周期、发布和支持状态独立呈现。

没有权限时，不返回标题、摘录或截短信息，类型和短引用只是占位。列表摘录最多 1 KiB，标题最多 512 字节；CSS 也会折叠较长片段，完整内容需打开条目读取。

列表支持后端种类筛选、Atom 真值/权威/生命周期三个独立轴，以及录入顺序分页。总数和筛选数由原生后端计算，表示当前元数据记录，不是可读正文数量，也不是方法执行资格。

时间窗可选当前修订的原生事件时间（journal occurred_at_us）或原生录入时间（ingested_at_us）。这不是最初建档时间、来源消息时间或生成时间。起点包含、终点不包含，可只填一边；输入按浏览器本地时间转换，应用后显示后端实际采用的条件。

时间过滤在后端计数和选页前完成，换条件后不能继续使用原游标。排序仍按原生录入序号，不按可能回拨的时钟值排序。

详情中的“修订历史”列出同一 Atom、Procedure、Core membership、提案或摘要的保留版本，每页 32 条，按录入顺序从新到旧。摘要只有一条不可变记录时就只列这一条。历史只列元数据，不凭状态或序号猜哪版是 current，也不显示已删除版本。

历史游标绑定打开时的 exact 源修订及读取水位，水位变化不拼接旧页。选中某版后重新检查权限并读取该版，刷新不会换成 current。

“来源与直接关联”只沿原生返回的引用跳转，包含来源、支持和范围依赖。原始对象与共享修订别名的投影会区分，不凭名称或 scope 猜目标。返回会恢复原修订及关联页；只保留至多 16 层身份、游标和视口，不缓存正文。

来源详情显示原生角色、信任和捕获完整性，来源文字没有执行权。保存的 Inline 与 Preview 明确区分，缺字段仍保持缺失，不补造预览。

同一逻辑记忆的两个指定修订可由原生端比较：先将某版“设为比较左侧”，再从该对象历史中选右侧。左右只是选择方向，不猜时间或真假。每侧重过来源与删除门；一侧不可读，就不返回差异字段名、值、长度或数量，不补 current 或空值。

比较字段按 JSON Pointer 排列，每页 8 项。缺字段与 JSON null 分开；字段 JSON 超过 2 KiB 则明确标注，可分别打开两侧完整语义分段。数组及深层结构作为整个字段比较，不用浏览器 diff 裁定业务。返回恢复原历史或比较页，并重新读取，不缓存旧值。

语义结构超过原单次上限时，可按原修订分段读取，每段至多 8 KiB。Atom 还可按原文读取正文，保留 UTF-8、换行和空白。页面只显示当前段，不自动加载全文；游标绑定对象、修订和表示，每次都复验当前权限及删除门。

SourceReceipt/SourceObservation 的文本从 Native 受保护归档分段读取，不用 EvidenceSurface 或预览代替。每段复验来源和删除门，并校验 CAS、长度、呈现前缀、原观察指纹及脱敏关系；只返回保护后的字节，不恢复秘密。

归档范围虽有 8 KiB 响应上限，当前每段仍需完整验证和解码归档，限额为编码 64 MiB、解码 128 MiB。这不是流式常量内存读取。非文本来源和制品的全部表示尚未闭合；CaptureReceipt 的结构化字段走工作记录读取，不冒原始来源文本。

列表选页借用 canonical typed 记录，完成原删除/仓库规则、筛选、计数和 keyset 后，只物化选中页，不先为所有候选编码正文。有界响应不代表所有内部读面已消除完整快照成本，大库读取和资源资格尚未完成。

范围按钮可按名称、后端记录的路径或分支查找 Task、Repository 和 Worktree，也可查看下级。原生目录每次读取至多 64 个候选，只为该窗口准备直接来源和范围权限输入，不取全库记忆正文。冷校验与必要投影追平仍保留。

Task 视图列出该任务及其声明关联的仓库/工作树资产。仓库/工作树视图列出对应资产及关联任务；global 不会自动混入，需单选或勾选“同时列 global”。范围不存在或不可用时显示计数未知，不回退全部范围；归属未判定时标明计数不完整。

任务名称也受当前来源许可约束，读不到的名称不参与名称匹配，页面会提示结果可能不全。关闭或隐藏页面会清空目录。

“来源”页只读原生端已登记的来源，按来源键分页，每页 32 个。浏览不触发宿主扫描、批准或导入，本页数量也不表示宿主全部历史。同一逻辑 Session 的多个 source instance 分别保留。

来源目录可按精确 Session ID、来源或尚未证明仓库/工作树归属筛选。目录提示不是归属证明，未归属不等于 global。选择来源后，可查看目录/来源修订、历史归属、读取限制、显式访问意图、原记录的导入状态、同修订归档水位及当前导入 job。

批准或 imported 状态不等于当前正文可读，正文仍经原门复验。前瞻观察边界、后续完整记录起点/水位与较早前缀水位分别显示。文件长度不是归档长度，部分进展不写成整份已导入。

隐藏或读取不可用会清空目录、详情、引用、计数和来源筛选输入。恢复后重新读取原生状态。

从“已保留的归档修订”可选择 exact source/revision，再按原生 sequence/receipt 分页，每页最多 32 条。修订目录按修订键排列，不冒时间先后或正文许可。

记录可按原生序号半开区间定位。导入 sequence 可能是字节终点，不把它当作消息数量；metadata header 也不会因不是 message 而被漏掉。记录来自现有 source/revision 索引，不扫描全库 Evidence，也不要求原 JSONL 仍存在。

已有 Inline/Preview 只按原生保存字段显示至多 512 字节的 UTF-8 节选，并标明出处及截短。缺失仍缺失，不为了补预览读取 CAS 或调用模型。

记录页每次检查来源、仓库、删除和检索抑制状态。无权读取时显示原因并清掉字段、预览及续页引用。水位或条件变化后重新选页，保留原修订。

点击记录后，按 exact observation/receipt 进入原详情和受保护 CAS 分段入口。返回恢复原修订目录、记录页及视口，只保留身份和游标，不缓存正文。同源真实改写后的旧归档仍可按旧修订读取，当前原文件离线也不改用新正文。

工作页可按已知 ID 读取 Task、Workstream、Episode、Attempt、Operation、ExecutionLane 和 CaptureReceipt 等已开放记录。通道可选当前或编号历史修订，凭证按其精确 ID 读取；导航保留所选版本，不用 current 替换旧记录。缺终态、采用或验证证据仍显示未知，不把捕获完成或 exit code 当成工作完成。

原证通过 SourceObservation/SourceReceipt 的精确 ID 读取。当前已知的物理范围仍在读取时复验；同一个 Native 会话跨多个仓库，不等于这些原证共享一个权限范围。撤权不交付此前暂存的正文，恢复须重新读取，不能复用旧预览。

直接打开通道或覆盖凭证的正文会核其聚合来源范围。普通工作记录引用凭证，不等于读取该凭证的全部内容；一个仓库停用不应仅因同会话关联而关闭独立仓库的工作记录。

工作状态编辑尚未开放。来源事件/时间筛选、完整关联、Wiki 历史、生产搜索和其余业务页面仍在接入，未接入页面不显示样例。

正文按文本显示，不将记忆写入 localStorage、IndexedDB 或离线缓存。网页会话空闲 15 分钟或满 8 小时后失效，也可用侧栏按钮提前结束。这里是本机 HTTP，不提供 TLS，也不防护同一 OS 用户下的恶意进程。

The independent Python package provides native current-only metadata browsing, kind/Atom-axis filters, recording-order pages/counts and windows on the current revision's native event or ingestion time.

These are not source-message or generated times.

The typed scope directory supports Task/Repository/Worktree relations and explicit opt-in Global assets.

Readable lists use permission-checked stored titles/excerpts and explicit summary provenance.

Details provide semantic values and original-revision ranges of at most 8 KiB.

Counts describe metadata records, not readable bodies or method eligibility; independent semantic axes are not collapsed into one status.

Scope-directory reads use finite native candidate windows and direct source/scope permission facts rather than all unrelated memory bodies.

Memory-page selection filters and counts borrowed canonical records before materializing the selected page.

Cold validation and required projection catch-up remain intact.

A bounded response does not establish that every internal read avoids whole snapshots. Large-corpus reads and resource use are not fully qualified.

Same-object history pages bind continuations to the exact source and frontier.

Opening a version rechecks current access and does not substitute current.

Two exact revisions of the same logical memory can also be compared natively, with fresh checks on both sides and bounded field pages.

Missing, null and oversized values remain distinct; full values use exact semantic ranges.

Native source/dependency links follow authoritative references, distinguish primary objects from shared-revision aliases and return to the original revision. Stored Inline and Preview presentations are distinct. Missing presentation stays missing, and source text has no instruction authority.

Text archives are read from Native's protected storage in exact-source 8 KiB ranges.

Each request rechecks access/deletion and verifies CAS identity, lengths, presentation prefix, original observation fingerprint and protection/redaction relations.

These are bounded responses, not streaming constant-memory verification: each range still fully verifies/decodes its archive, within 64 MiB encoded and 128 MiB decoded limits.

The source directory reads already committed metadata only.

It preserves distinct source instances per logical session and shows recorded access intent, import state, revision-specific watermarks and the current job.

Browsing does not scan, approve or import.

Catalogued state is not proof of effective body access or complete import.

Retained archive revisions can be selected by exact source/revision.

Indexed records are paged by native sequence/receipt, with optional half-open sequence windows and fresh source/repository/deletion/suppression checks.

Sequence may be a byte endpoint, not a message count; metadata headers are not silently omitted.

Stored record presentations may produce a native UTF-8 excerpt of at most 512 bytes, clearly marked as Inline/Preview and truncated where needed.

Missing presentation is not invented or filled by reading CAS.

Exact record references open the original detail/protected-content path, and returning restores the original record page without caching bodies or substituting current revisions.

The original JSONL need not remain present to read authorized retained archives. Hidden or unavailable pages clear old fields, references and counts; restoration rereads Native.

The Work page supports known-ID reads of connected Task/Workstream/Episode/Attempt/Operation, ExecutionLane and CaptureReceipt records. Lane history uses numbered revisions; receipt reads use exact IDs. Navigation does not replace a selected old revision with current.

Exact source records retain their own current physical-scope checks, even within a shared Native session. A direct lane/receipt body checks its aggregate sources; merely linking that receipt from an independent work record does not read the aggregate body.

Missing execution, adoption or verification evidence stays unknown. Capture completion does not mark work complete. Work editing is not yet available.

Further source/time/event filters, complete associations, Wiki history, full search/governance/management and all non-text/artifact representations remain unfinished. Full functionality/resource/desktop acceptance is also pending; unconnected pages do not show samples.

The browser does not persist bodies in localStorage, IndexedDB or offline caches. A Web session expires after 15 idle minutes or eight hours total. This is local HTTP, not TLS, and it does not defend against a malicious process running as the same OS user.

## CLI 与 MCP 的区别 / CLI versus MCP

`evertrace --help` 是当前 CLI 参数真源。CLI 以互斥的 `--xxx` 模式提供配置、诊断、安装、管理、备份和 TUI 等入口；旧顶层子命令已停止接受。无参数只显示帮助，不启动服务。**没有 `evertrace search` 或 `evertrace get` 子命令**。search/get 是 MCP 工具的 action。

Use `evertrace --help` for CLI arguments.

Mutually exclusive `--xxx` modes handle configuration, diagnostics, installation, administration, backup and TUI.

Retired top-level subcommands are rejected; no arguments prints help without starting a service. **There are no `evertrace search` or `evertrace get` CLI subcommands**; these are actions on the MCP tool.

`--config PATH` 必须放在顶层模式之前；CLI、daemon 和 MCP 应使用同一配置，避免连接到不同数据目录。`--config-check` 只校验文件，`--config-show` 只展示该文件合并默认值后的结果，不代表 daemon 当前活动配置或模型连通性。

Put `--config PATH` before the top-level mode, and use the same configuration for the CLI, daemon and MCP so they resolve the same data root. `--config-check` validates the file; `--config-show` shows that file plus defaults, not the daemon's active configuration or provider connectivity.

```sh
evertrace --config /absolute/config.toml --config-check
evertrace --config /absolute/config.toml --config-show
```

新安装器生成的接线使用独立的 `evertrace-mcp --config PATH --mcp ...`；通用入口 `evertrace --config PATH --mcp ...` 仍存在，旧接线由安装/升级流程验证处理。独立程序只接受 `--mcp` 模式，不能用它运行 `--doctor`、`--tui` 等通用 CLI 操作；命令帮助仍查看 `evertrace --help`。当前安装包需要四个同版本程序，见 [README 的程序清单](../README.md#installation-package)，不要沿用只复制三个程序的旧示例。

New installer-managed wiring uses `evertrace-mcp --config PATH --mcp ...`.

The general `evertrace --config PATH --mcp ...` entry point remains; installation/upgrade validates existing wiring.

The dedicated program accepts only the `--mcp` mode and does not provide general CLI operations such as `--doctor` or `--tui`; use `evertrace --help` for command help.

Current packages require four matching programs; see the [README package list](../README.md#installation-package), not older three-program copy examples.

两者都是 stdio MCP 传输，通过本地 UDS 联系 daemon，不监听公开 TCP，也不会替你启动 daemon。加载配置后等待 stdin 输入是正常行为，不是聊天提示符；宿主能发现工具也不证明 daemon 已连接、绑定有效或读取获准。优先使用安装器生成的完整接线，不手改程序路径、删除宿主定位参数，或伪造绑定标识与 claim。

Both are stdio MCP transports using local UDS, not a public TCP listener, and neither starts the daemon for you.

Waiting for stdin after loading configuration is normal, not a chat prompt.

Tool discovery alone does not establish daemon connectivity, a valid binding or read permission.

Prefer the complete installer-generated wiring; do not hand-swap executable paths, remove host locator arguments or fabricate bindings/claims.

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

`add`/`organize` 接受显式声明或整理提议，使用固定格式。人工接受和删除是单独操作，Web 写操作仍在接入。

`add`/`organize` accept explicit declarations or organization proposals in closed formats. Human acceptance and deletion remain separate; Web write actions are still being connected.

## 如何理解返回结果 / Interpret results

| 返回内容 / Content | 意义 / Meaning |
|---|---|
| 来源证据、摘要 / Source evidence, digest | 可追溯的事实或派生记忆；不是执行许可。 / Traceable facts or derived memory, not execution permission. |
| 未接受的方法提议 / Unaccepted method proposal | Pending/Validating 的本地参考，效果未验证；不等于正式 Procedure APPLY。 / A local reference with unverified effectiveness, not an accepted Procedure APPLY. |
| 正式方法 / Accepted procedure | 仍有适用范围、版本、状态和使用条件；返回不证明使用成功。 / Still constrained by scope, version, state and use conditions; returned does not mean successfully used. |
| 规范性约束 / Normative constraint | 需要独立策略来源和权限验证；普通文本不能自授此身份。 / Requires separately verified policy source and authority. |
| Warning/partial/unavailable | 阅读警告和来源缺项；不把缺证当成反证，也不忽略降级继续执行危险操作。 / Inspect missing evidence and warnings; absence is not proof, and degraded results are not permission for risky actions. |

## 旧终端入口（待退役） / Terminal entry pending retirement

管理入口正在统一到 `--web`。下列 TUI 功能仍有旧消费者，供迁移期间查阅；新功能不再往 TUI 扩展。

Management is moving to `--web`. The following terminal functions remain during migration; new management work belongs in Web.

```sh
evertrace --config /absolute/config.toml --tui
```

三个主要页面：Inbox 查看待治理的提议；Explorer 浏览来源和对象、详情与关联；System 查看 daemon、配置、后台 job、备份和诊断。显示为空时先刷新，再检查来源许可和任务状态，不猜造对象。

The three main pages are Inbox (proposals), Explorer (sources, objects, details and relations), and System (daemon/configuration/jobs/backups/diagnostics). Refresh and check access/job state before interpreting an empty view.

当前可见页按上次读取结束时间判断自动刷新：System 至少间隔 15 秒，Inbox/Explorer 至少 5 秒。只有已连接、没有读取/待处理请求、编辑/确认弹窗或筛选输入时才会自动刷新；不是固定周期轮询。空闲时可按 `r` 请求手动刷新，不能用它绕过正在处理的操作。

Auto-refresh is measured from the previous read's completion: at least 15 seconds for the visible System page, five seconds for Inbox/Explorer.

It requires a connection and no read, pending request, edit/confirmation dialog or filter input; it is not a fixed-rate poll.

Press `r` when idle to request a manual refresh, not to bypass an operation already in progress.

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

`E` depends on the detail: an eligible proposal may offer edit-and-accept; a validated asset's support detail offers submit-replacement only when a replacement draft is available.

The draft must actually change.

Submitting it creates a Pending proposal, not an immediate replacement of the active asset or automatic acceptance/qualification.

`D` 仅在 support 详情允许全局 Atom 弃用时打开原因编辑，必须填写合法原因；它提交 Pending 弃用提议，不直接删除资产。操作不可用或发生冲突时，查看当前条件并刷新，不手造 revision、权限或提议载荷来绕过限制。

`D` opens a reason editor only when the support detail permits global Atom deprecation.

A valid reason is required; this submits a Pending deprecation proposal, not direct deletion.

If unavailable or conflicting, inspect the current conditions and refresh; do not invent revisions, permissions or payloads to bypass them.

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
