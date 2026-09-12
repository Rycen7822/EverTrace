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

## 模块职责 / Component responsibilities

| Crate | 职责 / Responsibility |
|---|---|
| `evertrace-domain` | ID、不可变 revision、配置、领域对象与校验；不承担 I/O。 / IDs, immutable revisions, config, domain types and validation, without I/O. |
| `evertrace-capture` | 内容保护、设备密钥、CAS、framing、durable spool、采集准入。 / Protection, device key, CAS, frames, durable spool and admission. |
| `evertrace-codex` | 宿主格式、能力探测、接线、绑定和来源适配；不是通用权限后门。 / Host formats, probes, wiring, bindings and source adaptation. |
| `evertrace-store` | LanceDB、journal、单 writer、migration、投影、查询和持久化维护。 / Persistence, single-writer serialization, migrations, projections, queries and maintenance. |
| `evertrace-engine` | 业务编排、摄入/归一、后台合成与复核、权限、检索、恢复及治理服务。 / Runtime orchestration, ingestion, background synthesis/review, authorization and services. |
| `evertrace-protocol` | 本地协议 framing、握手、请求/响应、MCP schema 和 DTO。 / Local transport, handshake, envelopes, MCP schema and DTOs. |
| `evertrace-tui` | 终端界面和事件处理；不拥有第二套领域规则。 / Terminal UI, without a second domain implementation. |
| `evertrace-hook` | 同步 Hook 可执行程序。 / Synchronous capture executable. |
| `evertraced` | daemon 入口、信号与服务接线。 / Daemon entry point, signals and service wiring. |
| `evertrace-cli` | `evertrace` 的 CLI、MCP stdio 与 TUI 启动入口。 / CLI, MCP stdio and TUI launcher. |
| `evertrace-testkit` | 集成测试及必要的测试支持，不是生产控制器。 / Integration tests/support, not a production controller. |

## 持久化与身份 / Persistence and identity

LanceDB 是嵌入式数据库；不是 SQLite，也没有另一套 Redis/数据库服务要求。`evertrace_journal` 保存权威追加事件，`evertrace_objects`、`evertrace_relations`、`evertrace_search` 是对应投影/查询表。CAS 保存受保护 payload；journal 和视图引用这些内容。不能宣称跨表原子事务。

LanceDB is embedded, not SQLite or a separate Redis/database service requirement. `evertrace_journal` is authoritative; `evertrace_objects`, `evertrace_relations` and `evertrace_search` are derived/current/query tables. CAS holds protected payloads referenced by events/views. Cross-table atomicity is not claimed.

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
