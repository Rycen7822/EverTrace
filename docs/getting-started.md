# 安装与首次使用 / Getting started

[文档目录 / Documentation](README.md) · [配置 / Configuration](configuration.md)

## 1. 环境和预期 / Environment and expectations

当前实现面向 Linux：使用 Unix domain socket、Linux 文件身份与安全文件操作。WSL2 内请使用 Linux 文件系统中的目录，先检查用户服务是否可用。原生 Windows/macOS 未在此指南中承诺支持。不要以 root 身份运行 EverTrace，不要把数据根放在自动同步的云盘、网络挂载或多个进程共享写入的目录。

The current implementation targets Linux: Unix domain sockets and Linux-specific filesystem safety are part of the design. In WSL2 use the Linux filesystem and check user-service availability. Native Windows/macOS support is not claimed here. Run as your normal user; do not place the data root on cloud-sync/network storage or share it between writers.

源码编译需要 Git、Rust 1.97.1、C/C++ 编译工具、`cmake`、`pkg-config`、`protoc`。Lance 的构建脚本需要 Protocol Buffers 编译器；只安装 Rust 不够。Debian/Ubuntu 中对应的常见包名为 `git build-essential cmake pkg-config protobuf-compiler`；按自己的发行版安装。运行已编译的非 Web 核心程序不需要 Conda/Python。旧 Rust Web 已回撤，`--web` 已接入按需 exec；独立 `webui/` Python 包已有开发态只读竖切，且正式入口/隔离组装已验证，完整生命周期/资源验收仍未完成。仅 `--web` 按需使用隔离 Python 环境，不把 Python 变成核心入口依赖，不自动安装 Web 依赖。

A source build needs Git, Rust 1.97.1, a C/C++ toolchain, `cmake`, `pkg-config` and `protoc`. Lance build scripts require the Protocol Buffers compiler. Common Debian/Ubuntu package names are `git build-essential cmake pkg-config protobuf-compiler`; install the equivalents for your distribution. Non-Web core binaries do not require Conda/Python. The old Rust Web has been rolled back; the new `--web` exec launcher and independent Python read-only component have verified isolated assembly; full lifecycle/resource acceptance remains unfinished. Only `--web` will start its isolated Python runtime, without making Python a core-mode dependency or silently installing Web dependencies.

```sh
git --version
cc --version
c++ --version
cmake --version
pkg-config --version
protoc --version
rustup toolchain install 1.97.1 --profile minimal --component rustfmt --component clippy
rustc +1.97.1 --version
```

构建可能消耗较多内存和磁盘。并发设为 1 仍不是内存硬上限；资源紧张或 WSL 曾崩溃时先看[构建资源控制](development.md)。以下步骤不会安装系统依赖，也不会修改宿主源码。

Builds can use substantial RAM and disk. One build job is not a hard memory limit; see [resource controls](development.md) on constrained machines. The steps below do not install system dependencies or modify host source code.

## 2. 编译四个 Rust 核心程序 / Build the four Rust core binaries

```sh
git clone https://github.com/Rycen7822/EverTrace.git
cd EverTrace
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo +1.97.1 build --locked -p evertrace-cli -p evertraced -p evertrace-hook
./target/debug/evertrace --help
```

得到 `evertrace`（统一 CLI）、`evertrace-mcp`（独立 MCP transport）、`evertraced`（daemon）和 `evertrace-hook`（同步采集）。当前示例使用 debug 构建，不等同于经过发布验证的二进制包。安装器从 CLI 所在目录读取另外三个程序，因此四者必须来自同一构建并位于同一目录。

The outputs are `evertrace` (unified CLI), `evertrace-mcp` (dedicated MCP transport), `evertraced` (daemon), and `evertrace-hook` (synchronous capture). This guide uses a debug build, not a qualified release package. The installer resolves the other binaries beside the CLI; keep all four from the same build in one directory.

这四个 Rust 程序的构建不代表可选 Python Web 已装配；新的 Web entry、隔离环境与精确 uv 命令须在迁移实测后提供，不先给出未经验证的安装流程。 / Building these four Rust binaries does not assemble the optional Python Web component. Its entry, isolated environment and exact uv commands are documented after migration verification, not invented in advance.

## 3. 创建安全的试用配置 / Create a safe trial configuration

先检查目标配置是否已经存在；若存在，阅读并复用或选择独立路径，不要覆盖。下面的 `cp -n` 不覆盖已有文件，因此已有配置可能仍启用了模型。

Check for an existing destination first. Inspect/reuse it or choose a separate path; do not overwrite it. `cp -n` preserves an existing file, so an existing configuration might still have LLM processing enabled.

```sh
umask 077
mkdir -p "$HOME/.evertrace"
cp -n docs/examples/evertrace.local.toml "$HOME/.evertrace/config.toml"
./target/debug/evertrace --config "$HOME/.evertrace/config.toml" --config-check
./target/debug/evertrace --config "$HOME/.evertrace/config.toml" --config-show
```

确认 `llm.enabled = false`。试用数据目录是 `~/.local/share/evertrace-trial`；不要与已有实例混用。`--config-check` 只证明配置合法，不测试模型、宿主或后台任务。

Confirm `llm.enabled = false`. The trial data directory is `~/.local/share/evertrace-trial`; do not mix it with an existing instance. `--config-check` validates configuration, not provider availability, host support or job completion.

## 4. 首次前台启动 / Start in the foreground

```sh
./target/debug/evertrace --config "$HOME/.evertrace/config.toml" --daemon
```

另开终端，在仓库根目录执行： / In a second terminal, from the repository root:

```sh
./target/debug/evertrace --config "$HOME/.evertrace/config.toml" --doctor
./target/debug/evertrace --config "$HOME/.evertrace/config.toml" --tui
```

daemon 启动会创建本地运行数据。这一步没有接入宿主，空数据和 `host_canary=not_run` 是正常现象。TUI 的 `q` 只退出界面；在 daemon 所在终端按 Ctrl-C 才会请求关闭服务。不要同时为同一数据目录启动第二个 daemon。

Starting the daemon creates local runtime data. Host integration has not happened yet: an empty instance and `host_canary=not_run` are expected. `q` closes the TUI, not the daemon; Ctrl-C in the daemon terminal requests shutdown. Never start a second writer on the same data directory.

Web 是可选组件，须先显式完成[同包隔离组装](development.md#独立-web-工程迁移中--independent-web-component-migration)，再运行以下入口。仅 Cargo build 不会安装 Python Web；缺组件会明确失败，不影响非 Web 模式。

Explicitly assemble the optional same-package Python component before this entry. Cargo build alone does not install it; missing Web does not affect core modes:

```sh
./target/debug/evertrace --config "$HOME/.evertrace/config.toml" --web
```

使用打印的一次性本机链接，不要分享该凭据。此版本 Python 网页只读接入当前版本元数据列表、原生种类/Atom 状态轴筛选、录入顺序分页/计数、原生 Task/Repository/Worktree 目录与关联范围选择（global 显式包含）、语义正文、原修订语义值分段和连接状态；计数不等于可读正文数量。分段按钮按需读取，每段至多 8 KiB 并复验当前权限。来源页、修订历史、固定修订比较、完整范围/来源/时间段过滤、搜索、原始来源/制品区间及其余页面仍待闭合；没有后台模型也能读取已有记忆。入口、安全边界和会话期限见[使用方法](usage.md#本机网页--local-webui)。

Use the printed one-time local link and keep it private. The Python WebUI exposes current-only metadata browsing with native kind/Atom-axis filters, recording-order paging/counts, semantic details, original-revision semantic ranges and status. Counts do not promise readable bodies. Range buttons fetch at most 8 KiB and recheck current access; they do not automatically load the whole value. Source/history/exact comparison, full scope/source/time filtering, search, original-source/artifact ranges and other pages remain incomplete. Existing memory can be read with LLM processing off. See [Usage](usage.md#本机网页--local-webui) for access and session limits.

## 5. 启用后台模型 / Enable background model processing

先按[配置说明](configuration.md)选择服务地址、模型、凭据环境变量和预算。保持现有其他配置，仅修改 `[llm]`；不要把 API key 写进仓库。前台启动 daemon 时，其进程必须能读到所配置的密钥环境变量。

Follow [Configuration](configuration.md) to set the endpoint, model, credential environment variable and budgets. Preserve unrelated settings. Never commit an API key. The daemon process must inherit the configured key variable.

关闭 LLM 可以验证采集和本地读取，但不会生成新的 LLM 摘要/方法提议。LLM 是后台处理者；不要求前台 agent 为每条记忆主动写入。

LLM-off mode can exercise capture and local reads, but creates no new LLM summaries or method proposals. The model works in the background; the foreground agent need not explicitly save every memory.

## 6. 接入宿主 / Integrate the host

这一步会改动配置：安装器合并 `$CODEX_HOME/config.toml`（默认 `~/.codex/config.toml`）中的受管 Hook/MCP 项，发布 Hook 运行资产，并在用户 systemd 可用时创建/启用 `evertraced.service`。它保留非受管配置，并报告备份和失败；**不修改宿主源码，也不替你启用宿主明确关闭的 Hook 或放宽信任策略**。

This step changes configuration: managed Hook/MCP entries are merged into `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`), Hook assets are published, and `evertraced.service` is created/enabled when user systemd is available. Unmanaged configuration is preserved and backups/failures are reported. **Host source is not patched; disabled hooks and trust policy are not overridden.**

先停止第 4 步的手动 daemon。确认四个程序位于稳定目录；如果以后清理 `target/`，不要让已安装服务仍引用其中的程序。可自行将同一构建的四个程序放到自己的长期安装目录后，再从那里调用 CLI。以下示例中的路径必须替换为你的真实绝对路径。

Stop the foreground daemon first. Use a stable directory for all four binaries; an installed service must not point into a `target/` directory you later clean. You may copy the four binaries from the same build into a persistent user-owned directory and invoke that CLI. Replace the placeholder absolute paths below.

仅首次安装且目标目录尚未用于现有安装时，可以这样准备；已安装实例应走[升级流程](operations.md)，不要原地覆盖正在运行的二进制：

For a first installation only, when this directory is not already an installation, you can prepare it as follows. Existing installations should use the [upgrade workflow](operations.md), not overwrite running binaries:

```sh
mkdir -p "$HOME/.local/lib/evertrace"
install -m 755 target/debug/evertrace target/debug/evertrace-mcp \
  target/debug/evertraced target/debug/evertrace-hook "$HOME/.local/lib/evertrace/"
export PATH="$HOME/.local/lib/evertrace:$PATH"
```

这个 PATH 设置只作用于当前 shell；其他终端可使用绝对路径，或自行将该目录加入用户 PATH。下面的 `/absolute/evertrace-bin/evertrace` 对应你刚准备的 CLI。宿主路径必须是实际可执行普通文件；若命令发现结果是 symlink，先定位其真实安装文件，不要用伪造 wrapper 绕过类型校验。

This PATH change affects the current shell; use absolute paths in other terminals or add the directory to your user PATH. `/absolute/evertrace-bin/evertrace` below means the CLI you just prepared. The host executable must be an actual executable regular file; resolve symlinks to the real installed file rather than fabricating wrappers to bypass checks.

```sh
/absolute/evertrace-bin/evertrace --config "$HOME/.evertrace/config.toml" --install /absolute/path/to/codex
```

无用户 systemd 时，按安装输出的手动 daemon 命令启动。若使用用户服务，先按[配置指南](configuration.md)将模型密钥提供给服务进程；shell 中的 `export` 不代表服务也收到了密钥。不要手工复制带占位符的 Hook 模板来绕过安装器。

Without user systemd, use the manual daemon command printed by the installer. For a user service, provision its credentials as described in [Configuration](configuration.md); a shell export does not prove the service received the key. Do not bypass installation by pasting placeholder Hook templates.

普通安装不执行真实模型 canary。需要真实接入验证时显式执行： / Installation does not run a live model canary by default. To request it explicitly:

```sh
/absolute/evertrace-bin/evertrace --config "$HOME/.evertrace/config.toml" --doctor --refresh-host /absolute/path/to/codex
```

**费用与副作用：** live canary 使用宿主正常的配置、认证、模型和信任设置，可能产生模型费用；现有第三方 Hook、notify 或 MCP 的副作用不能保证不存在。探测成功也不等于五项能力门全部通过，必须阅读每项结果。`--install ... --live-canary` 具有同类影响。

**Cost and side effects:** a live canary uses normal host configuration, authentication, model and trust. Model charges and existing third-party Hook/notify/MCP effects are possible. Success does not automatically qualify all five capability gates; inspect each result. `--install ... --live-canary` has the same considerations.

## 7. 验证第一条记忆 / Verify one real memory

1. 在一个非敏感、已按宿主正常流程信任的测试仓库中开启新会话，确认 EverTrace MCP 工具被发现。 / Start a new session in a non-sensitive repository trusted through the normal host workflow; confirm the EverTrace MCP tool is discovered.
2. 正常讨论一个具体决策或失败经验，不需要额外 add/organize 记账。 / Discuss a concrete decision or lesson normally; no extra add/organize bookkeeping is required.
3. 在 TUI Explorer/System 检查实际采集记录、会话正文许可和后台任务。来源格式、权限和归属不满足时，不会凭空生成摘要。 / Inspect captured records, body permission and jobs in Explorer/System. Unsupported, unauthorized or unscoped sources do not magically become summaries.
4. 若需导入历史会话，按[使用指南](usage.md)选择实际会话，而不是猜造 ID。 / If historical import is needed, select the actual session as described in [Usage](usage.md), rather than inventing an ID.
5. 允许预算内后台任务完成，再在同仓库的新会话中检索该经验，检查返回内容及来源。 / Allow eligible background jobs to complete, then query the lesson in a new session in the same repository and inspect the source references.

摘要不会保证即时出现；没有新证据或预算不足时可能暂不运行。没有检索发生，也不保证主动送达。若失败，按[故障排查](troubleshooting.md)定位是哪一段没有完成，不要反复重装或放宽权限。

Summaries are not guaranteed to appear immediately; jobs depend on new evidence and budget. Without a read request, proactive delivery is not guaranteed. Diagnose the missing stage using [Troubleshooting](troubleshooting.md), rather than repeatedly reinstalling or weakening permissions.
