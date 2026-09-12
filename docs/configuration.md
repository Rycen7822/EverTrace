# 配置 / Configuration

[文档目录 / Documentation](README.md) · [首次启动 / Getting started](getting-started.md)

## 配置文件与路径 / Configuration file and paths

CLI 和 daemon 使用同一选择顺序：显式 `--config PATH` → `EVERTRACE_CONFIG` 环境变量 → `~/.evertrace/config.toml`。默认配置不使用 `XDG_CONFIG_HOME`，也不自动回退到旧目录。CLI 的 `--config` 必须放在子命令之前。使用自定义配置时，每个入口都应指向同一文件。systemd 用户 unit 仍使用标准用户服务目录，和 EverTrace 配置目录分开。

Both CLI and daemon choose: explicit `--config PATH` → `EVERTRACE_CONFIG` → `~/.evertrace/config.toml`. The default ignores `XDG_CONFIG_HOME` and does not fall back to the former directory. Put the CLI's `--config` before the command and point every entry point at the same file. The systemd user unit remains in the standard user-service directory, separate from EverTrace configuration.

```sh
evertrace --config /absolute/config.toml config check
evertrace --config /absolute/config.toml config show --effective
```

`config_version = 1` 必须显式提供。未指定的配置段/字段使用默认值；未知字段、错型、不合法范围或字段关系会被拒绝。`show --effective` 输出的是文件合并默认值后的结果，**不是 daemon 当前活动配置的查询**；重载失败时二者可能不同。

`config_version = 1` is required. Omitted sections/fields use defaults. Unknown fields, wrong types, invalid ranges and invalid relationships are rejected. `show --effective` prints the file plus defaults, **not the daemon's currently active configuration**; they may differ after a rejected reload.

`runtime.data_dir` 可用绝对路径、`~/...`、以 `$NAME` 或 `${NAME}` 开头的路径；环境变量基路径必须为非空绝对路径。不接受任意 shell 表达式，不执行命令替换；相对路径和 `..` 等不合法路径会被拒绝。数据根需要当前用户拥有的私有本地目录，不要用 symlink 绕过校验。

`runtime.data_dir` accepts absolute paths, `~/...`, and supported `$NAME`/`${NAME}` prefixes whose environment base is a nonempty absolute path. It is not a shell expression: no command substitution or arbitrary expansion. Relative/invalid paths are rejected. Use a private local directory owned by the current user, not a symlink workaround.

## 已安装实例迁移 / Existing installations

旧安装不会自动搬迁配置。先停止服务，确认 `~/.evertrace/` 中没有需要保留的冲突文件，再将原配置和 `provider.env` 移入该目录，保持目录 `0700`、文件 `0600`。保留 `runtime.data_dir`，不要把配置迁移当成数据库迁移。同步修改 EverTrace MCP 的 `--config` 参数、用户 unit 的 `ExecStart --config` 和凭据 drop-in 的 `EnvironmentFile`，不覆盖 Codex 的其他配置；执行 `systemctl --user daemon-reload` 并校验后再启动。确认新路径生效后，仅移除已空的旧配置目录，不建立自动回退或目录镜像。

Existing installations are not automatically migrated. Stop the service, check for destination conflicts, then move the configuration and `provider.env` into `~/.evertrace/` with directory mode `0700` and file mode `0600`. Preserve `runtime.data_dir`; this is not a database migration. Update the EverTrace MCP `--config` argument, user-unit `ExecStart --config`, and credential drop-in `EnvironmentFile`, preserving unrelated Codex settings. Run `systemctl --user daemon-reload`, validate, then start. Remove only the empty former configuration directory after verifying the new paths; do not create a fallback or mirror.

## 配置段速查 / Section reference

完整字段和默认值见[完整配置示例](../config/evertrace.example.toml)；首次试用见[关闭 LLM 的示例](examples/evertrace.local.toml)。下表解释作用，不建立第二份默认值表。

See the [full example](../config/evertrace.example.toml) for fields/defaults and the [LLM-off example](examples/evertrace.local.toml) for first use. This table explains responsibilities rather than duplicating all defaults.

| 配置段 / Section | 作用和注意事项 / Purpose and cautions |
|---|---|
| `runtime` | 数据目录、日志级别、后台 worker；目录和 worker 数变更需重启。 / Data location, log level and background workers; location/worker changes require restart. |
| `dreaming` | 空闲维护与复核预算；不是每个周期必然生成新记忆。 / Idle maintenance/review budgets, not a promise of new memory every cycle. |
| `procedure` | 方法候选与晋升设置；`auto_publish_full=true` 不代表完整 AutoFull 已可运行。 / Proposal/promotion settings; the flag does not make full AutoFull operational. |
| `global_promotion` | 各资产进入全局范围的策略；仓库来源不自动变成全局权限。 / Global promotion policy; repository evidence is not global authority. |
| `search` | search/get 的输出预算；不是模型质量分数。 / Search/get output budgets, not quality scores. |
| `session_import` | 历史元数据回填、正文导入并发和每轮大小；元数据存在不代表正文已获准导入。 / Metadata backfill and body-import limits; metadata is not body permission. |
| `capture` | 预览、inline payload 大小；有界采集可能产生明确的部分状态。 / Preview and inline size limits; bounded capture can be partial. |
| `recovery` | 捕获超时和恢复包大小；不是任意文件/命令都可完整恢复的保证。 / Capture timeouts and bundle limits, not universal recovery guarantees. |
| `llm` | 提供方、模型、凭据变量、并发、日预算与语义丰富策略。 / Provider, model, credential variable, concurrency, daily budgets and enrichment. |

## 后台模型 / Background model

当前提供方实现为 `openai_compatible`：在 `base_url` 后追加 `/chat/completions`，发送非流式、`response_format=json_object` 的请求。提供方必须兼容实际请求和结构化响应要求；“兼容”名称不保证所有模型都能工作。把 `base_url` 设置到 API 根，例如以 `/v1` 结尾，而不是完整的 `/chat/completions` 路径。

The implemented provider is `openai_compatible`: it appends `/chat/completions` to `base_url` and sends non-streaming requests with `response_format=json_object`. The provider/model must support the actual request and structured response contract. Use the API base, such as a `/v1` endpoint, not the full completion URL.

下面只展示需要修改的 `[llm]` 段，不是含密钥的完整配置。保留原有 `config_version` 和其他段，替换占位地址与模型名后再校验。

The following is an `[llm]` section to merge into your existing configuration, not a complete credential file. Preserve `config_version` and unrelated sections; replace the placeholders and validate.

```toml
[llm]
enabled = true
provider = "openai_compatible"
base_url = "https://your-provider.example/v1"
model = "your-model-name"
api_key_env = "EVERTRACE_LLM_API_KEY"
timeout = "90s"
max_concurrency = 1
daily_input_token_budget = 50000
daily_output_token_budget = 10000
daily_call_budget = 20
daily_wall_time_budget = "15m"
unlimited_token_budget = false
```

远程地址要求 HTTPS；HTTP 仅允许 loopback。URL 不允许带 userinfo/密码或 fragment。不要把凭据塞进 URL 的 query。密钥从 `api_key_env` 指定的进程环境变量读取；即使本地兼容服务不用认证，这个客户端仍要求该变量非空，应按你所管理服务的要求设置。配置文件只写变量名，不写 API key。

Remote endpoints require HTTPS; HTTP is allowed only on loopback. Userinfo/passwords and fragments are rejected. Do not put credentials in URL query parameters. The client reads a nonempty environment variable named by `api_key_env`, even for a local compatible service; supply it according to that service's requirements. Store only the variable name in TOML, not the API key.

预算限制不是精确账单上限：超时、远端计费和使用量报告可能不同。首次使用小预算、单并发，观察真实请求结果后再调整。输入预算不足可能让大记录的任务等待或被拒绝；不要将反复重试作为常规操作。

Budgets are not exact billing caps: timeouts, remote billing and usage reporting can differ. Start with a small budget and one request at a time. Large inputs can be deferred/rejected when budget is insufficient; repeated retries are not a normal workflow.

## 密钥与用户服务 / Credentials and user services

前台 daemon 从启动它的 shell 继承环境。systemd 用户服务有自己的环境，终端中的 `export` 不会自动传给已经运行的服务。可通过受保护的环境文件向服务提供凭据：在 `~/.evertrace/provider.env` 中用编辑器写入 `EVERTRACE_LLM_API_KEY=你的密钥`，设为权限 `0600`，不要提交、截图或粘贴到 issue。

A foreground daemon inherits its launching shell's environment. A systemd user service has a separate environment. One option is a private `~/.evertrace/provider.env` containing `EVERTRACE_LLM_API_KEY=your-key`, created with an editor and mode `0600`. Never commit it, screenshot it or attach it to an issue.

在已安装的用户服务上执行 `systemctl --user edit evertraced.service`，添加 drop-in，而不是覆盖受管 unit： / For an installed user service, use `systemctl --user edit evertraced.service` and add a drop-in instead of replacing the managed unit:

```ini
[Service]
EnvironmentFile=%h/.evertrace/provider.env
```

```sh
systemctl --user daemon-reload
systemctl --user restart evertraced.service
```

这是你明确进行的服务配置修改。密钥文件和 drop-in 需自行维护；EverTrace 卸载不代表这些自建文件会删除。宿主自己的认证与后台模型密钥是两件事，live canary 还可能使用宿主配置的模型。

This is an explicit service configuration change. You own the credential file and drop-in; uninstalling EverTrace does not imply their removal. Host authentication and the background model key are separate; live canaries may use the host's model.

## 重载与重启 / Reload and restart

```sh
evertrace --config /absolute/config.toml config check
evertrace --config /absolute/config.toml config reload
evertrace --config /absolute/config.toml doctor
```

daemon 会监测配置文件，也提供显式 reload；关注 `Applied`、`Rejected`、`RestartRequired` 及 active/pending 信息，而不仅是进程退出码。无效配置不会替换最后可用配置。`runtime.data_dir`、`runtime.background_workers` 需要重启；**改数据目录不是数据迁移**。环境变量值改变也需要让 daemon 获取新的进程环境，通常需重启。

The daemon watches the file and supports explicit reload. Inspect `Applied`, `Rejected`, `RestartRequired` and active/pending values, not just exit status. Invalid configuration does not replace last-good state. `runtime.data_dir` and `runtime.background_workers` require restart; **changing the directory does not migrate data**. Changed environment values must also reach the process, usually through restart.

如果编辑了 data_dir 导致 CLI 找错 socket，可用 `config reload --socket /absolute/old-data-root/runtime/evertraced-v1.sock` 联系原 daemon。不要删除原 socket 或锁文件强行启动新 writer。详见[运维](operations.md)。

If editing data_dir makes the CLI locate the wrong socket, use `config reload --socket /absolute/old-data-root/runtime/evertraced-v1.sock` to reach the existing daemon. Do not delete its socket/lock to force another writer. See [Operations](operations.md).
