# 架构与能力边界 / Architecture and capability boundaries

[文档目录 / Documentation](README.md) · [使用 / Usage](usage.md) · [开发 / Development](development.md)

本文解释当前产品的组件和使用边界，不是开发进度日志，也不把设计目标当成已交付保证。

This guide explains current components and user-visible boundaries. It is not a development journal, and design goals are not delivery guarantees.

## 数据流 / Data flow

```text
Supported host events / permitted session records
              |
      protect -> CAS + durable capture/import
              |
      daemon ingestion -> authoritative journal
              |
       current objects / relations / search projections
              |                         |
     bounded background jobs      scoped MCP reads / TUI
      |                |
   summaries     method proposals -> independent review
```

Hook 是同步、轻量的采集入口，不打开 LanceDB，不等待后台 LLM，也不向宿主注入记忆正文。daemon 负责摄入、状态解释、后台任务、权限判断和写入。用户入口通过同一 daemon 访问，不再各自直接写数据库。

The Hook is a synchronous capture entry point. It does not open LanceDB, wait for background LLM work, or inject memory bodies into the host. The daemon owns ingestion, interpretation, background work, access checks and writes. User interfaces use the daemon rather than independent database writers.

后台模型复用 Engine 的单一 `SemanticProvider`，显式选择 Chat Completions、Responses 或 Messages 的 wire 格式；共用 HTTP、并发、预算和业务 JSON 校验。协议差异不进入领域对象、持久化 schema、Hook 或 MCP 操作面；不增加 SDK、模型路由器、自动提供方回退或远程会话。配置与兼容限制见[后台模型](configuration.md#后台模型--background-model)。

Background models share the Engine's `SemanticProvider`: explicit Chat Completions, Responses or Messages wire formats, with common HTTP, concurrency, budgets and application validation. Protocol differences do not enter domain objects, storage schemas, Hook or MCP actions. No SDK, model router, automatic provider fallback or remote conversation is added; see the [configuration guide](configuration.md#后台模型--background-model).

## 模块职责 / Component responsibilities

| Crate | 职责 / Responsibility |
|---|---|
| `evertrace-domain` | ID、不可变 revision、配置、领域对象与校验；不承担 I/O。 / IDs, immutable revisions, config, domain types and validation, without I/O. |
| `evertrace-capture` | 内容保护、设备密钥、CAS、framing、durable spool、采集准入。 / Protection, device key, CAS, frames, durable spool and admission. |
| `evertrace-codex` | 宿主格式、能力探测、接线、绑定和来源适配；不是通用权限后门。 / Host formats, probes, wiring, bindings and source adaptation. |
| `evertrace-store` | SQLite 权威 journal/current/runtime/relations、Lance 派生检索、CAS 与持久化维护。 / Authoritative SQLite state, derived Lance search, CAS and persistence maintenance. |
| `evertrace-engine` | 业务编排、摄入/归一、后台合成与复核、权限、检索、恢复及治理服务。 / Runtime orchestration, ingestion, background synthesis/review, authorization and services. |
| `evertrace-protocol` | 本地协议 framing、握手、请求/响应、MCP schema 和 DTO。 / Local transport, handshake, envelopes, MCP schema and DTOs. |
| `evertrace-tui` | 终端界面和事件处理；不拥有第二套领域规则。 / Terminal UI, without a second domain implementation. |
| `evertrace-hook` | 同步 Hook 可执行程序。 / Synchronous capture executable. |
| `evertraced` | daemon 入口、信号与服务接线。 / Daemon entry point, signals and service wiring. |
| `evertrace-cli` | `evertrace` 的 CLI、MCP stdio 与 TUI 启动入口。 / CLI, MCP stdio and TUI launcher. |
| `evertrace-testkit` | 集成测试及必要的测试支持，不是生产控制器。 / Integration tests/support, not a production controller. |

## Web 呈现边界（迁移中） / Web presentation boundary (migration)

旧 `crates/evertrace-web/` 的 Rust HTTP/静态资源内嵌实现及未提交 G3 扩展已按用户确认回撤；当前产品代码保留 `cf4736a` 的正式 CLI，并已接入显式按需的 `--web` 启动链。独立 `webui/` Python 包已建立基础只读竖切（CLI exec/隔离组件装配已验证，完整迁移未完成），经受保护 UDS 调用原 Rust daemon；页面控制、模板、会话和窄 IPC 适配归 Python，领域规则、配置权威、数据权限与唯一 writer 留在 Rust。HTML/CSS/字体和必要 JavaScript 独立维护，修改 Web 不要求 Cargo。不把规划路径、接口通过或规范更新当成迁移交付。

The embedded Rust Web implementation and uncommitted G3 extensions have been rolled back. Product code retains the accepted flag-based CLI checkpoint, and now dispatches explicit `--web` to the matching isolated Python component. An independent Python package now has a basic read-only slice over the protected UDS, with verified CLI exec/assembly but unfinished complete migration; Rust retains business, configuration, authorization and the single writer. Templates/static assets and Python Web edits must not require Cargo. A target path, working backend interface or specification update is not a completed cutover.

`--web` 仅按需启动版本匹配的 Python Web 组件，不自动安装依赖或启用服务。未启动时核心入口不导入 Web、不读页面/字体、不建立 Web worker/listener/session/timer/cache/poller；Web 组件缺失不影响普通 CLI、TUI、MCP、Hook 或 daemon。最小启动器和共享人类业务协议保留在 Rust，不等于加载 Web 运行时。迁移后仍须实测进程、PSS/RSS、CPU与退出回收；不能从文件大小推算内存收益。

Only explicit `--web` starts the version-matched Python component, without implicit installation or a service. With Web absent/inactive, core modes must not import/preload it or create Web resources. Minimal Rust launch dispatch and shared human protocol are not a Web runtime. Process/PSS/RSS/CPU and post-exit reclamation still require measurement.

## 持久化与身份 / Persistence and identity

当前权威存储是嵌入式 SQLite：`evertrace.sqlite` 中的 `evertrace_journal` 保存唯一 append-only command/event journal，objects、runtime、relations 与必要索引由原单 writer 维护。`evertrace_search.lance/` 仅保存可重建的 exact/FTS/vector 检索派生投影。CAS 保存受保护 payload；不要求外部 Redis/数据库服务，不宣称 SQLite、Lance 与 CAS 之间存在通用跨存储原子事务，在线客户端也不能绕过 daemon 直开这些存储。

Embedded SQLite is authoritative: `evertrace.sqlite` holds the sole append-only command/event journal and writer-owned objects/runtime/relations/indexes. `evertrace_search.lance/` contains rebuildable exact/FTS/vector search projections only; CAS holds protected payloads. No external Redis/database service or general cross-storage atomicity is claimed. Online clients access these stores through the daemon, not directly.

逻辑对象使用真正的 UUIDv7，不以路径、文本或 digest 冒充身份。内容 digest 只用于具名的完整性/引用/去重消费者。revision 和历史证据保留，current 可推进；正常增量投影校验当前自洽和 delta，历史完整性复核需要相应 replay/rebuild，不等于每次读取扫描全部历史。

Logical objects use genuine UUIDv7 IDs, not paths or content hashes masquerading as identity. Digests serve specific integrity/reference/deduplication consumers. Revisions/history are retained while current state advances. Incremental checks are not a claim that every read replays all history.

## 记忆、方法与权限 / Memory, methods and authority

来源摘要保存决策、经验、待办和结果，是有价值的记忆，不要求先变成正式 Atom/Procedure。基本来源摘要不需要前台补造 Task/Attempt。方法提议独立生成，后续根据新的相关来源复核；LLM 不能直接自授发布、删除或策略权限。

Source summaries preserve decisions, lessons, open items and results as useful memory without first becoming formal Atom/Procedure assets. Basic source summaries do not require invented Task/Attempt state. Method proposals are generated independently and reviewed against new relevant sources; the model cannot grant publication, deletion or policy authority to itself.

区分这些结论： / Keep these conclusions separate:

- “已返回”只证明内容经实际出口送达，不证明 agent 采用。 / Returned content is not proof of adoption.
- 行为相似、时间接近或任务成功，不单独证明某个方法导致成功。 / Similar actions, timing or task success do not alone establish causal method effectiveness.
- 未接受的方法作为 evidence 参考，不是正式 APPLY，也不进入成功计数。 / Unaccepted references are not formal APPLY or success counts.
- 原始记录、README、注释、普通指令文件和检索正文不能自授长期规范性权限。 / Source text and retrieved content cannot grant themselves long-term policy authority.
- 删除、撤销、当前版本、信任和 scope 在读取时仍生效；旧摘要不是绕过这些边界的副本。 / Current deletion, revocation, version, trust and scope checks still apply to derived memory.

## 哪些保证不能依赖 / Guarantees not established

| 能力 / Capability | 当前边界 / Current boundary |
|---|---|
| 基本来源记忆 / Basic source memory | 有正常生产路径和本地集成测试；实际效果依赖支持的来源、正文许可、归属和模型。 / Production paths and local tests exist; real usefulness depends on sources, permission, scope and model. |
| 五项宿主能力 / Five host capabilities | Capture complete、Recovery complete、active search due、strong normalization、project-policy authority 分开证明；安装不等于全部启用。 / Each needs independent evidence; installation enables none by inference. |
| 主动送达 / Proactive delivery | 缺 cue/绑定/能力门时不可依赖；无普通读取也不保证送达。 / Not guaranteed without qualified cues/binding/gates, or without reads. |
| 完整 AutoFull / Complete AutoFull | 资格编译与首次自动受理消费者未交付，当前来源也不足以证明完整自然使用覆盖；不只是一个待开的开关。 / Qualification and initial automatic acceptance are undelivered, and current sources lack full natural-use coverage; this is not just a disabled switch. |
| 通用实验结果 / General experiment results | 服务级验证不等于任意正常工具输出已经自动接入；解析指标成功不是任务成功。 / Service-level verification is not universal automatic ingestion; metric parsing is not task success. |
| 真实模型与检索质量 / Real model/retrieval quality | 确定性测试不证明自然环境效果；高级检索诊断算子不等于已经验收的生产配置。 / Deterministic tests and diagnostic operators are not real-world quality qualification. |
| Recovery | 仅支持明确目标、合法输入和验证链；未知/部分结果必须保留。 / Only supported selected targets/inputs with verification; unknown/partial outcomes stay explicit. |

当前普通生产检索使用基础 A 路径；B–E 高级组合及 F 方法效果层没有已测 release-quality 资格。不要把研究/诊断代码存在理解为用户可通过新增配置随意启用。公开指南不要求用户修改宿主源码或日常手动维护记忆。

Ordinary production retrieval uses the base A path. Advanced B–E combinations and the F method-effect layer lack measured release-quality qualification. Diagnostic code is not an invitation to invent configuration switches. These guides require neither host source patches nor routine manual memory bookkeeping.

进一步实现定位见 [workspace](../Cargo.toml)、[Engine](../crates/evertrace-engine/src/lib.rs)、[Store](../crates/evertrace-store/src/lib.rs) 和 [MCP schema](../crates/evertrace-protocol/src/mcp.rs)。

Implementation anchors: [workspace](../Cargo.toml), [Engine](../crates/evertrace-engine/src/lib.rs), [Store](../crates/evertrace-store/src/lib.rs), and [MCP schema](../crates/evertrace-protocol/src/mcp.rs).
