# EverTrace 长期开发纪律

## 权威与保护边界

- `docs/EverTrace_architecture_baseline/` 是唯一规范性产品真源；原单体 `EverTrace_architecture_baseline.md` 已拆分为该目录中的多个维护文件，不要求继续保留独立单体文件。
- `.work/EverTrace_development_plan.md` 是唯一开发 Program。只有用户在当前任务中明确授权该文件时才能修改；不得为了迁就实现结果反向改写 Program。
- `docs/**` 整体属于受保护的规范与用户资料范围，执行 agent 一律只读，不得在其中创建、修改、移动、重命名或删除文件；Program 的 slice owner、普通开发 prompt 或笼统的“按 Program 开发”均不能授权执行 agent 写入。任何 `docs/**` 维护都必须由用户另行交给编排者处理。
- 执行阶段产生的非规范性实施文档统一写入 `.work/implementation/**`，且只有当前 Program slice 或当前 prompt 精确列出的文件可写；这些记录不能覆盖 baseline 或 Program。`.work/EverTrace_development_plan.md` 与 `.work/orchestrator/**` 仍分别是受保护 Program 和编排者私有状态，不属于该可写范围。
- `.work/orchestrator/frozen/EverTrace_development_plan.2026-08-26.sha256-6e40c7354cd1121b.md` 是永久冻结的 Program 证据副本；任何 agent 都不得修改、覆盖、删除、移动或变更其权限。未来即使用户授权修改工作版 Program，也不包含该冻结副本。
- `docs/EverTrace_handoff_2026-08-17.md` 只提供非规范性背景，`references/**` 只提供证据和参考；二者都不能覆盖 baseline。
- 将 `.work/EverTrace_development_plan.md`、`docs/EverTrace_architecture_baseline/**` 和 `references/**` 视为受保护输入。发现合同冲突时停止实现并报告，不得自行放宽约束。

## 环境与工作状态

- 所有 Python、pip、pytest 和基于 Python 的仓库工具都必须在名为 `test` 的 Conda 环境中运行；非交互命令优先使用 `conda run -n test ...`。
- EverTrace 的精确 Rust 工具链是 `1.97.1`；所有 build、format、check、test 和 Program proof 都必须使用仓库固定工具链，不得改用全局默认或浮动 `stable`。LanceDB 的 Rust `1.91.0` 只是其 workspace MSRV，不是本项目工具链。

## 修改纪律

- 开发前先读取当前 Program slice、其直接依赖和对应 baseline owner；不得把规划路径、合同或 future slice 误报为已实现能力。
- 严格按 slice 的 owner scope 修改；不得提前实现后续 slice、添加平行抽象、第二套协议或未经要求的兼容层。
- 长文档只做窄范围、分段修改；不得大规模重写冻结规范、开发 Program、handoff 或研究资料。
- baseline checker 永远只读；不得在 canonical baseline 中原地重建 metadata。获授权的 baseline 修订必须使用既定 candidate 与事务式发布流程。
- 保留无关改动和用户资产；未经明确要求不得删除或移动参考归档，不得 commit、push、发布或执行外部同步。

## 控制面与证据最小化

- 新增持久化控制文件、控制模块或 digest 前，必须有当前 slice 的明确要求和实际读取该产物的命令或验证器；文件数量、内容规模和“后续可能需要”都不能成为新增控制面的理由。
- 当前 slice 的 owner 只在开始时从 Program 读取一次，用作本次编辑边界。不得为 owner 另建 registry、graph、生成器、重复表、反复扫描或反复 hash；最终 proof 对实际改动路径做一次边界检查即可。
- `program/source-lock.toml`、`program/requirements.toml` 与 `program/slices.toml` 是各自数据的单一持久化真源。Rust 代码只负责解析、验证和执行，不得再硬编码一份完整表格，不得用文件名、标题或关键词启发式生成 requirement owner、negative case 或 slice 合同。
- requirement 的 anchor、implementation owner、negative case 和 proof owner 直接从 Program/baseline 映射录入一次；不得再写代码推断或反复确认。通用占位文本、批量模板以及仅检查字段非空，不构成 requirement coverage 证明。
- 只有存在具名跨边界消费者时才计算或持久化 digest；同一算法与同一字节范围只保留一个 canonical digest，其余产物引用该值。Program 明确要求同时保留 tree hash 与 file-manifest hash 时可以保留二者，但不得在多个表中重复每个文件的同一 hash。
- digest 的算法、路径规范化、包含项、排除项和 pre/post 计算时点必须明确；不得把 digest 本身放入其所声明覆盖的同一闭包，也不得靠反复改常量寻找自洽值。
- `AGENTS.md`、`.gitignore` 与 `.work/orchestrator/**` 是治理或用户状态，不是产品 source correctness identity；可以把路径列为不可越权边界，但不得把其内容 hash 固定进 Source Lock、source-tree freshness 或 slice attestation。
- 大目录的逐文件明细最多只有一个 canonical manifest 表示；其他角色表和 receipt 只引用其 manifest/tree digest。不得因同一文件兼具证据角色而复制路径、大小和 hash 记录。
- Program 明确要求预声明后续 slice 时，只能预声明 manifest 数据；预声明不构成提前实现权限，不得据此创建未来 slice 的控制器、占位 replay/fault/test 或仅为未来扩展服务的代码路径。

## 验证与交付

- 修改后运行与风险匹配的最小验证，并复核受影响的路径、保护边界和最近合同；不得以预检、计划或局部通过冒充完成。
- 必须分别报告本地修改、验证、commit、release 和 publication 状态；没有实际执行的阶段必须明确说明。
