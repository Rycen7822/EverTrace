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

### Linux 可选链接器：mold / Optional Linux linker: mold

mold 可作为本地 Linux 开发的显式选择，用于缩短链接步骤；它不是编译缓存，也不是 workspace 的默认要求。不要为此提交共享 `.cargo/config.toml`、修改全局 Cargo 配置或改变现有 profile。仍遵守上面的单 Cargo、串行测试和资源预留规则。

mold is an opt-in local Linux development linker, not a compiler cache or a workspace requirement. Do not add shared `.cargo/config.toml`, change global Cargo configuration or alter the profiles for it. Retain the single-Cargo, serial-test and resource-headroom rules above.

可使用发行版的软件包，例如 Debian/Ubuntu 的 `sudo apt-get install mold`；也可从[官方 release](https://github.com/rui314/mold/releases)获取对应架构的预编译包，先核对发布的 SHA-256。发行版版本未必是下面实测的 3.0.0。安装后检查实际 Rust、驱动和链接器版本：

Use your distribution's package, for example `sudo apt-get install mold` on Debian/Ubuntu, or an architecture-matched [official release](https://github.com/rui314/mold/releases), verifying its published SHA-256 before use. Distribution packages may differ from the measured 3.0.0. Check the actual Rust, driver and linker versions:

```sh
rustc +1.97.1 -vV
cc --version
mold --version
command -v ld.mold
```

下面仅用于本机 GNU/Linux 构建，要求 `cc` 是 GCC 12.1 或更新版本，且 `ld.mold` 可从 PATH 找到。旧 GCC、交叉编译或其他驱动需先按[上游说明](https://github.com/rui314/mold/tree/v3.0.0#how-to-use)核对，不直接套用。子 shell 退出即恢复原环境；保留已有 RUSTFLAGS，若设置了优先级更高的 `CARGO_ENCODED_RUSTFLAGS`，先停止并在原配置中正确合并，不清空它来绕过检查：

The example is for native GNU/Linux with `cc` using GCC 12.1 or newer and `ld.mold` on PATH. Consult the [upstream instructions](https://github.com/rui314/mold/tree/v3.0.0#how-to-use) before using older GCC, cross-compilation or other drivers. The subshell restores the environment on exit and preserves existing RUSTFLAGS. If higher-priority `CARGO_ENCODED_RUSTFLAGS` is set, stop and merge the option correctly into that configuration rather than clearing it:

```sh
(
  if [ "${CARGO_ENCODED_RUSTFLAGS+x}" = x ]; then
    printf '%s\n' 'CARGO_ENCODED_RUSTFLAGS is set; merge linker flags there first.' >&2
    exit 1
  fi
  export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1
  export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C linker=cc -C link-arg=-fuse-ld=mold"
  cargo +1.97.1 test --locked -p evertrace-store --test lancedb_compatibility --no-run
)
```

首次更改 RUSTFLAGS 可能让 Cargo 重编依赖，不能拿这一轮与另一链接器的热构建比较。若依赖已准备齐，可加 `--offline`。从 Cargo 的 `Executable` 输出取得实际测试程序路径，再检查 `.comment` 中是否有 mold 标识；只看 `mold --version` 不能证明该程序由它链接：

Changing RUSTFLAGS can rebuild dependencies; do not compare that first build against another linker's warm build. Add `--offline` if dependencies are already available. Take the actual test-executable path from Cargo's `Executable` output and inspect `.comment` for mold's identification; `mold --version` alone does not establish which linker produced a binary:

```sh
readelf -p .comment /absolute/path/to/test-executable
```

**已知证据的范围。** [Issue #3](https://github.com/Rycen7822/EverTrace/issues/3) 报告了 `09589e2`、Linux x86_64、Rust 1.97.1、上述测试和默认 dev/test profile 下的观察，单 job、关闭增量、串行测试，每种链接器三次。以下是该 issue 的中位数，不是本机或当前提交重新测得的结果：

**Evidence boundary.** [Issue #3](https://github.com/Rycen7822/EverTrace/issues/3) reports `09589e2` on Linux x86_64, Rust 1.97.1, this test and the default dev/test profile, with one build job, incremental compilation off, serial tests and three runs per linker. These are the issue's medians, not new measurements on this machine or commit:

| 测量 / Measurement | Bundled LLD 22.1.6 | mold 3.0.0 | 中位数缩短 / Median reduction |
|---|---:|---:|---:|
| 相同对象重链接 / Relink identical objects | 2.538 s | 1.337 s | 47.3% |
| 保留依赖、强制测试源码重编译并链接 / Recompile test source and link, dependencies retained | 3.965 s | 2.648 s | 33.2% |

该实验冷 LLD 构建约 779 秒，最后链接约 2.86 秒；没有完整冷 mold 构建结果，因此不能宣称冷构建提速 33%/47%。全 workspace、release、Windows/MSVC、其他硬件及峰值内存收益均未证明，也不宣称程序运行更快；mold 默认 fork 时只统计父进程 RSS 尤其不完整。复测按 issue 固定 wrapper 路径与 RUSTFLAGS、只切换实际链接器、保留依赖并真实触发源码重编译，交错多次比较，不把 Cargo 无操作耗时当重构建。

The cold LLD build took about 779 seconds, with about 2.86 seconds in the final link. No complete cold mold build was measured, so this is not a 33%/47% cold-build gain. Full workspace, release, Windows/MSVC, other hardware and peak-memory gains remain unproven; no runtime speedup is claimed. Parent-only RSS is especially incomplete with mold's default fork behavior. For comparisons, follow the issue's fixed wrapper path/RUSTFLAGS, switch only the actual linker, retain dependencies, force real source recompilation and interleave repeated runs; no-op Cargo timings are not rebuild measurements.

该 issue 的原始 LLD 及所有重链接测试程序均为 **6 过、1 失败**，失败项是 `corrupt_derived_probe_table_fails_open`，根因未确定；不能称整个目标全绿，也不能跳过或弱化断言来采用链接器。上面的 `--no-run` 只生成测试程序：实际验证时去掉它运行同一命令，检查测试结果和最终退出码。

The issue's original LLD and all relinked test binaries reported **six passed, one failed**: `corrupt_derived_probe_table_fails_open`, with root cause unresolved. This is not a passing target, and adopting a linker must not skip or weaken the assertion. The example's `--no-run` only builds the test executable; remove it to run the same command and inspect the tests and final exit status.

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
