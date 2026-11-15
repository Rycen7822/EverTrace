# 架构与能力边界 / Architecture and capability boundaries

[文档目录 / Documentation](README.md) · [使用 / Usage](usage.md) · [开发 / Development](development.md)

本文说明当前组件、数据流和正在迁移的部分。

Current components, data flow and migration status.

## 数据流 / Data flow

```text
Supported host events / permitted session records
              |
      protect -> CAS + durable capture/import
              |
      daemon ingestion -> authoritative journal
              |
       current objects / relations / search projections
              |                   |                  |
     bounded background jobs   scoped MCP      finite native reads
      |                |                             |
   summaries     method proposals             Python Web backend
                       |                             |
              independent review                local browser
```

Hook 是同步、轻量的采集入口，不打开 LanceDB，不等待后台 LLM，也不向宿主注入记忆正文。daemon 负责摄入、状态解释、后台任务、权限判断和写入。用户入口通过同一 daemon 访问，不再各自直接写数据库。

The Hook is a synchronous capture entry point. It does not open LanceDB, wait for background LLM work, or inject memory bodies into the host. The daemon owns ingestion, interpretation, background work, access checks and writes. User interfaces use the daemon rather than independent database writers.

后台模型复用 Engine 的单一 `SemanticProvider`，显式选择 Chat Completions、Responses 或 Messages 的 wire 格式；共用 HTTP、并发、预算和业务 JSON 校验。协议差异不进入领域对象、持久化 schema、Hook 或 MCP 操作面；不增加 SDK、模型路由器、自动提供方回退或远程会话。配置与兼容限制见[后台模型](configuration.md#后台模型--background-model)。

Background models share the Engine's `SemanticProvider`: explicit Chat Completions, Responses or Messages wire formats, with common HTTP, concurrency, budgets and application validation.

Protocol differences do not enter domain objects, storage schemas, Hook or MCP actions. No SDK, model router, automatic provider fallback or remote conversation is added; see the [configuration guide](configuration.md#后台模型--background-model).

## 模块职责 / Component responsibilities

| Crate | 职责 / Responsibility |
|---|---|
| `evertrace-domain` | ID、不可变 revision、配置、领域对象与校验；不承担 I/O。 / IDs, immutable revisions, config, domain types and validation, without I/O. |
| `evertrace-capture` | 内容保护、设备密钥、CAS、framing、durable spool、采集准入。 / Protection, device key, CAS, frames, durable spool and admission. |
| `evertrace-codex` | 宿主格式、能力探测、接线、绑定和来源适配；不是通用权限后门。 / Host formats, probes, wiring, bindings and source adaptation. |
| `evertrace-store` | SQLite 权威 journal/current/runtime/relations、Lance 派生检索、CAS 与持久化维护。 / Authoritative SQLite state, derived Lance search, CAS and persistence maintenance. |
| `evertrace-engine` | 业务编排、摄入/归一、后台合成与复核、权限、检索、恢复及治理服务。 / Runtime orchestration, ingestion, background synthesis/review, authorization and services. |
| `evertrace-protocol` | 本地协议 framing、握手、请求/响应、MCP schema 和 DTO。 / Local transport, handshake, envelopes, MCP schema and DTOs. |
| `evertrace-tui` | 迁移期保留的旧终端消费者，不是管理功能的目标入口。 / Retained terminal consumer during migration, not the target management UI. |
| `evertrace-hook` | 同步 Hook 可执行程序。 / Synchronous capture executable. |
| `evertraced` | daemon 入口、信号与服务接线。 / Daemon entry point, signals and service wiring. |
| `evertrace-cli` | CLI、MCP stdio 和显式 `--web` 分派；旧 TUI 入口待退役。 / CLI, MCP stdio and explicit Web dispatch; the old TUI entry remains pending retirement. |
| `webui/`（Python 包） | 按需管理应用后端、页面读模型、HTTP/会话、模板与静态资源。 / On-demand management backend, page read models, HTTP/sessions, templates and assets. |
| `evertrace-testkit` | 集成测试及必要的测试支持，不是生产控制器。 / Integration tests/support, not a production controller. |

## Web 呈现边界（迁移中） / Web presentation boundary (migration)

`evertrace --web` 显式启动匹配版本的独立 `webui/` Python 包。Python 不只是静态资源服务器：它组织管理页面的读模型、内容分段和导航，经受保护 UDS 调用 Rust 的有限数据读取。HTML/CSS/字体和必要 JavaScript 外置，修改 Python 或页面不要求 Cargo。

Rust 保留正常 Agent 使用所需的摄入、领域计算、权限/来源/删除门、检索、恢复及单 writer。分页字段、内容窗口与资格判定由原数据 owner 提供，Python 不直开 SQLite、LanceDB 或 CAS，也不另建业务真源。

Explicit `evertrace --web` starts the matching independent Python package. Python owns management read models, content navigation, HTTP/sessions and templates/assets, using finite native reads over the protected UDS. Web edits do not require Cargo.

Rust retains the normal Agent core, domain eligibility, authorization, source/deletion gates, recovery and the single writer. Python neither opens native storage nor becomes another authority.

记忆、来源和多类工作/研究记录已接入只读路径。管理写动作、剩余 Rust 页面逻辑和 TUI 退役、完整打包及资源验收仍在进行。

Read-only memory, source and multiple work/research paths are connected. Management writes, remaining Rust presentation/TUI retirement, packaging and resource acceptance are in progress.

不运行 `--web` 时，不启动 Python Web 进程，也不加载页面资源或建立 Web 缓存、监听器和后台任务。核心入口可在没有 Web 组件的情况下运行。完整功能接入后的进程、内存和 CPU 三态测量仍待完成。

Without `--web`, core modes run without Python Web processes, assets, caches, listeners or background tasks. Full before/during/after resource measurements remain pending.

## 持久化与身份 / Persistence and identity

`evertrace.sqlite` 保存权威 journal、current、runtime 和 relations，由单 writer 维护。`evertrace_search.lance/` 保存可重建的检索投影，CAS 保存受保护内容。客户端统一经 daemon 访问。

Embedded SQLite is authoritative: `evertrace.sqlite` holds the sole append-only command/event journal and writer-owned objects/runtime/relations/indexes. `evertrace_search.lance/` contains rebuildable exact/FTS/vector search projections only; CAS holds protected payloads.

Clients access storage through the daemon. No separate database service is required.

Task、Workstream、Atom 等使用 UUIDv7，来源记录按各自的来源身份规则生成 ID。digest 用于内容校验和引用。状态通过 revision 推进，历史保留。

Task, Workstream and Atom use UUIDv7 IDs; source records use their source-identity rules. Digests support content verification and references. Current state advances through revisions while history is retained.

## 记忆、方法与权限 / Memory, methods and authority

来源摘要保存决策、经验、待办和结果，是有价值的记忆，不要求先变成正式 Atom/Procedure。基本来源摘要不需要前台补造 Task/Attempt。方法提议独立生成，后续根据新的相关来源复核；LLM 不能直接自授发布、删除或策略权限。

Source summaries preserve decisions, lessons, open items and results as useful memory without first becoming formal Atom/Procedure assets. Basic source summaries do not require invented Task/Attempt state.

Method proposals are generated independently and reviewed against new relevant sources; the model cannot grant publication, deletion or policy authority to itself.

区分这些结论： / Keep these conclusions separate:

- “已返回”只证明内容经实际出口送达，不证明 agent 采用。 / Returned content is not proof of adoption.
- 行为相似、时间接近或任务成功，不单独证明某个方法导致成功。 / Similar actions, timing or task success do not alone establish causal method effectiveness.
- 未接受的方法作为 evidence 参考，不是正式 APPLY，也不进入成功计数。 / Unaccepted references are not formal APPLY or success counts.
- 原始记录、README、注释、普通指令文件和检索正文不能自授长期规范性权限。 / Source text and retrieved content cannot grant themselves long-term policy authority.
- 删除、撤销、当前版本、信任和 scope 在读取时仍生效；旧摘要不是绕过这些边界的副本。 / Current deletion, revocation, version, trust and scope checks still apply to derived memory.

## 当前状态 / Current status

| 能力 / Capability | 当前边界 / Current boundary |
|---|---|
| 基本来源记忆 / Basic source memory | 有正常生产路径和本地集成测试；实际效果依赖支持的来源、正文许可、归属和模型。 / Production paths and local tests exist; real usefulness depends on sources, permission, scope and model. |
| 五项宿主能力 / Five host capabilities | Capture complete、Recovery complete、active search due、strong normalization、project-policy authority 分开证明；安装不等于全部启用。 / Each needs independent evidence; installation enables none by inference. |
| 主动送达 / Proactive delivery | 缺 cue/绑定/能力门时不可依赖；无普通读取也不保证送达。 / Not guaranteed without qualified cues/binding/gates, or without reads. |
| 完整 AutoFull / Complete AutoFull | 资格编译与首次自动受理消费者未交付，当前来源也不足以证明完整自然使用覆盖；不只是一个待开的开关。 / Qualification and initial automatic acceptance are undelivered, and current sources lack full natural-use coverage; this is not just a disabled switch. |
| 通用实验结果 / General experiment results | 服务级验证不等于任意正常工具输出已经自动接入；解析指标成功不是任务成功。 / Service-level verification is not universal automatic ingestion; metric parsing is not task success. |
| 真实模型与检索质量 / Real model/retrieval quality | 确定性测试不证明自然环境效果；高级检索诊断算子不等于已经验收的生产配置。 / Deterministic tests and diagnostic operators are not real-world quality qualification. |
| Recovery | 仅支持明确目标、合法输入和验证链；未知/部分结果必须保留。 / Only supported selected targets/inputs with verification; unknown/partial outcomes stay explicit. |

当前生产检索走 A 路径；B–E 与 F 效果层尚未完成发布验收。正常使用无需修改宿主源码或逐条手工整理记忆。

Production retrieval uses A. B–E and the F effect layer are not release-qualified. Normal use needs neither host source patches nor per-record memory bookkeeping.

进一步实现定位见 [workspace](../Cargo.toml)、[Engine](../crates/evertrace-engine/src/lib.rs)、[Store](../crates/evertrace-store/src/lib.rs) 和 [MCP schema](../crates/evertrace-protocol/src/mcp.rs)。

Implementation anchors: [workspace](../Cargo.toml), [Engine](../crates/evertrace-engine/src/lib.rs), [Store](../crates/evertrace-store/src/lib.rs), and [MCP schema](../crates/evertrace-protocol/src/mcp.rs).
