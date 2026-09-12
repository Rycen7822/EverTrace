# 开发与验证 / Development and verification

[文档目录 / Documentation](README.md) · [架构 / Architecture](architecture.md)

## 环境与源码入口 / Environment and source map

Rust 精确固定为 `1.97.1`，workspace edition 为 2024；不要用浮动 stable 或依赖的最低 Rust 版本替代。保留 Cargo.lock，正常 build/check/test 使用 `--locked`。构建依赖见[安装指南](getting-started.md)。

Rust is pinned to `1.97.1`, with workspace edition 2024. Do not substitute floating stable or a dependency's MSRV. Preserve Cargo.lock and use `--locked` for builds/checks/tests. See [build prerequisites](getting-started.md).

源码按[架构职责](architecture.md)分包。改行为前阅读真正决定行为的调用方、实现和直接消费者；搜索只能帮助定位。优先修现有逻辑、复用现有抽象，只增加当前需求必需的局部逻辑。不为提高“完整度”新增 controller、schema、hash registry、配置层或相同逻辑的双轨实现。

Read the deciding caller, implementation and consumer before editing behavior. Search is navigation, not understanding. Prefer a root-cause fix in existing code; add only what a current requirement needs. Do not build controllers, schemas, hash registries, configuration layers or duplicate paths for theoretical completeness.

## 构建与资源 / Build and resource controls

Lance/Arrow 的初次构建、链接和集成测试可能很重。一个终端启动一个 Cargo；不要同时让多个 agent 构建。以下环境变量仅影响本次命令/当前 shell，不改永久系统配置：

Initial Lance/Arrow compilation, linking and integration tests can be expensive. Run one Cargo process group at a time, including across agents. These variables affect the command/current shell rather than permanent system configuration:

```sh
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export RUST_TEST_THREADS=1
cargo +1.97.1 build --locked -p evertrace-cli -p evertraced -p evertrace-hook
```

单 job 不限制单次链接的内存，也不禁止测试内部创建线程/子进程。有用户 systemd 且资源充足时，可在 transient scope 中明确限制一条命令，例如下列**示例上限**；它不是最低配置要求，也不应该原样套用到只有少量 RAM 的机器：

One job does not cap linker memory or prevent internal test threads/children. With user systemd and enough resources, a transient scope can bound a command. The following **example limits** are not minimum requirements and should not be copied to a small-RAM machine without adjustment:

```sh
systemd-run --user --scope -p CPUQuota=400% -p MemoryHigh=12G -p MemoryMax=16G -p MemorySwapMax=4G nice -n 10 env CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 cargo +1.97.1 check --locked --workspace --all-targets
```

预留操作系统和其他任务的资源；碰到 OOM、exit 137 或 WSL 崩溃，先检查实测原因，不自动提高限额。CPU quota 是 CPU 时间配额，不是限制只能创建四个线程。命令 RSS 不代表整个进程组的峰值。无 systemd 时可保留串行策略并使用环境已有的资源约束，不为了跑检查随意改 WSL 全局设置。

Leave headroom for the OS and other work. Investigate OOM/exit 137/WSL crashes before raising limits. CPU quota limits CPU time, not thread count. A command's RSS is not necessarily the process group's peak. Without systemd, retain serial execution and available platform controls; do not casually change global WSL settings.

## 最小充分验证 / Proportionate verification

先跑最近的现有测试；文档改动先核对命令、配置和链接，不需要重新跑完整数据库压测。下面是不同范围的示例，不是每次修改都必须全部执行的清单：

Run the closest existing tests first. For documentation, check commands/configuration/links rather than rerunning storage stress tests. These are examples at different scopes, not a mandatory checklist for every edit:

```sh
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 check --locked -p evertrace-domain --all-targets
cargo +1.97.1 test --locked -p evertrace-testkit --test s01_domain_config
```

跨组件变更或交付前需要更广验证时，串行执行： / For cross-component changes or wider delivery checks, run sequentially:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo +1.97.1 check --locked --workspace --all-targets
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo +1.97.1 clippy --locked --workspace --all-targets --all-features -- -D warnings
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 cargo +1.97.1 test --locked --workspace --all-targets --all-features
```

测试中的故障注入可能刻意启动失败的子进程，包括损坏 Lance manifest 的负例。应同时检查父测试结果、完整 suite 和 Cargo 最终退出码；不能因为历史上某条 FAILED 是预期，就忽略新失败。

Fault-injection tests may deliberately launch failing children, including corrupted Lance-manifest cases. Inspect the parent assertion, complete suite and Cargo exit status. A previously expected FAILED line does not make a new failure acceptable.

不要全局添加 `--ignored`：保留旧 Hook 实物的测试和验收报告 collector 有明确前置条件。缺少旧二进制不能用新编译程序冒充；collector 消费已有验收材料，不是普通使用或编译所必需。公开源码的正常 Cargo 验证不应要求创建私有编排记录。

Do not indiscriminately use `--ignored`. Tests requiring retained old Hook artifacts and the acceptance collector have explicit prerequisites. A newly built binary is not a historical artifact; the collector consumes existing evidence and is not needed for normal use/builds. Public Cargo verification should not require private orchestration records.

## 缓存与运行数据 / Caches versus runtime data

```sh
du -sh target
df -h .
```

只有确认没有 Cargo/测试在用、且服务不引用该 target 中的二进制时，才考虑在当前 checkout 执行 `cargo +1.97.1 clean`。它会删除构建产物，下一次需要重建；不要为省空间删除正在使用的二进制，也不要删用户 data root、备份或 CAS 来清“编译缓存”。不要为相同验证复制多份大型 target。

Only consider `cargo +1.97.1 clean` in this checkout after confirming no builds/tests use it and no installed service points into it. It removes build artifacts and requires rebuilding. Runtime data, backups and CAS are not compiler caches. Avoid duplicate large targets for the same verification.

## 文档、隐私与提交 / Documentation, privacy and changes

公开入口是 `README.md`（英文）、`README.zh-CN.md`（中文）和 `docs/` 使用指南。中英文的能力边界与示例必须一致；长文档分段编辑，不写逐轮开发流水账。

Public entry points are the English and Chinese READMEs and `docs/` guides. Keep capabilities/examples consistent across languages; edit long documents in coherent sections rather than adding development journals.

`docs/baseline/` 保存本地私有设计归档，`.work/` 保存开发记录；二者与 AGENTS/状态文件被忽略，不是 clone 后运行的依赖。维护者的私有规范发布工具不属于公共构建前提；设计归档移动不应靠在公开目录创建影子副本或软链接来掩盖。

`docs/baseline/` contains private design archives and `.work/` development records. These and agent/state files are ignored, not clone-time runtime dependencies. Private design-publishing tools are not public build prerequisites; do not hide archive relocations with duplicate trees or symlinks.

若维护者需要执行仓库的 Python 工具，使用 `conda run -n test ...`；普通用户启动程序不需要创建 Conda 环境。提交前查看实际 diff 和 staged 路径，不强制添加 baseline、凭据、运行数据或个人笔记。保留他人未提交修改，不为了“干净”回滚无关文件。

Maintainers running Python repository tools use `conda run -n test ...`; users running binaries do not need Conda. Review the actual diff and staging before committing. Do not force-add private archives, credentials, runtime data or notes, and preserve unrelated work.

新增测试应证明本次行为回归，优先一个聚焦正例和必要的关键失败路径。测试不能自行创造产品需求，也不应为一个局部行为建立更大的测试框架。报告中分开写本地修改、实际验证和提交/推送/发布状态，不将本地通过冒充真实宿主或模型质量验收。

Add focused regression tests for changed behavior, with critical negatives where needed. Tests must not invent requirements or justify a disproportionate framework. Separate local changes, actual verification, commit/push and release status; local passing tests do not qualify a real host or model quality.
