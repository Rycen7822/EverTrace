# 故障排查 / Troubleshooting

[文档目录 / Documentation](README.md) · [配置](configuration.md) · [运维 / Operations](operations.md)

## 先分清哪一层失败 / Identify the failing layer first

配置合法 → daemon 可连接 → 宿主接线/来源准入 → 持久化采集/导入 → 后台任务 → 检索返回。这些不是一个状态。先运行以下只读检查；普通 doctor 不修复、不主动运行模型探测：

Configuration validity → daemon connectivity → host wiring/source admission → durable capture/import → background jobs → retrieval. These are distinct. Start with the following checks; ordinary doctor does not repair state or initiate live model probing:

```sh
evertrace --help
evertrace --config /absolute/config.toml config check
evertrace --config /absolute/config.toml config show --effective
evertrace --config /absolute/config.toml doctor
```

`show --effective` 读取磁盘配置，doctor 的 health/current diagnostics 来自 daemon；留意 active/pending、mode、配置 hash 和各项独立原因。doctor 的目录元数据正常不代表 CAS/数据库内容已经完整验证。

Effective-config output reads disk; doctor health/current diagnostics come from the daemon. Inspect active/pending state, mode, config hash and each reason. Healthy directory metadata does not prove full CAS/database integrity.

## 常见情况 / Common cases

| 现象 / Symptom | 检查与处理 / Check and action |
|---|---|
| `evertrace: command not found` | 构建后用 `./target/debug/evertrace`，或使用已安装的绝对路径；编译不会自动添加 PATH。 / Use the built relative path or installed absolute path; building does not install into PATH. |
| 配置不存在 / Missing config | 核对 `--config`、`EVERTRACE_CONFIG`、XDG/HOME。CLI 的 `--config` 放在子命令前。 / Check precedence and argument order. |
| `configuration invalid` | 检查 `config_version=1`、未知字段、单位、范围和字段关系；不要删除校验或改依赖。 / Check version, fields, units, ranges and relationships; do not weaken validation. |
| daemon unavailable / socket 失败 | 核对同一配置/data_dir、服务状态和运行用户；先看日志，不删 socket/lock。 / Check config/data root, service and user; inspect logs before touching socket/lock. |
| writer lock busy | 查清原 daemon/维护任务是否仍在运行；正常关闭后再试。 / Identify the current daemon/maintenance writer and stop it normally. |
| owner/type/symlink/permission 错误 | 使用真实私有本地目录，检查精确报错路径；不要 root 启动或递归放开权限。 / Inspect the exact path and use private local files; no root or broad permission workaround. |
| `wired_unobserved` / `host_canary=not_run` | 只完成了接线，尚无当前真实观测；不是自动成功也不是必然故障。 / Wiring exists without current live observation; neither proof of success nor inherent failure. |
| 宿主禁用 Hook / Disabled hooks | 按宿主正常信任/设置流程核实；EverTrace 不会替你绕过。 / Review normal host trust/settings; EverTrace does not override them. |
| 五个 gate 有关闭项 / Disabled gates | 分别阅读原因；一次成功探测不保证全开启，不用配置布尔值伪造 Active。 / Read each reason; do not fabricate Active with a flag. |
| 缺 Task/binding 或 `@due` 不可用 | 普通读取尝试合法的 repo/worktree ID 或 `path_hint:/absolute/path`；仍需来源和信任准入。 / Try a lawful explicit read scope; access/trust still apply. |
| 没有摘要 / No summaries | 检查 LLM 是否开启、来源正文是否获准/已导入、是否受支持且有归属、新增证据是否足够、job 状态和预算。 / Check model, body permission/import, supported scoped sources, new evidence, jobs and budgets. |
| 模型报错 / Provider errors | 占位地址/模型不能工作；确认 `/v1` API base、JSON 响应支持和 daemon 的非空密钥环境变量。 / Replace placeholders and check API base, JSON support and daemon credentials. |
| shell 可用但服务缺密钥 / Service missing key | shell export 不等于服务环境；按配置指南设置 private env file/drop-in 并重启服务。 / Provision the service environment and restart. |
| queued 后看不到结果 / Queued without result | 在 System 查该 job 的最终状态；不要将 exit 0 当完成或立刻重复提交。 / Inspect the actual job; queued/exit 0 is not completion. |
| 检索为空 / Empty search | 检查实际 source、scope、删除/撤销、当前版本和任务；全新实例为空正常。 / Check sources, scope, deletion/revocation, current revision and jobs; new instances are empty. |
| TUI revision/frontier 冲突 | `r` 刷新，重新选对象并核对操作；不反复提交旧 revision。 / Refresh, reselect and reassess; do not loop stale writes. |
| `RestartRequired` | data_dir/worker 数需重启；改变 data_dir 不会搬迁原数据。 / Restart for location/worker changes; a new path does not migrate data. |
| restore 返回 `historical_only` | 未满足当前激活/删除账本边界；保留历史结果，不冒充已恢复。 / Activation/deletion-ledger requirements are unmet; historical data is not an activated restore. |

## 编译、内存与磁盘 / Builds, RAM and disk

找不到 `protoc`：安装 Protocol Buffers 编译器并确保 Cargo 能在 PATH 找到；不要仅因此更新 LanceDB 或 Cargo.lock。编译器/linker 被 kill 或 WSL 崩溃时，先看系统 OOM 记录和可用资源，再用单 job、禁用 incremental 和串行测试。不能把“再试一次”当成资源修复。

For missing `protoc`, install the compiler and ensure Cargo can locate it; do not update LanceDB/Cargo.lock as a workaround. If compilation/linking is killed or WSL crashes, inspect OOM/resource evidence first, then use one build job, no incremental compilation and serial tests. A retry alone is not a resource fix.

```sh
free -h
df -h .
du -sh target
```

`du` 对大 target 也需要时间。不要运行第二个 Cargo 来“加速”第一个，不创建多份大型 target/数据备份；清理前检查安装服务是否引用待删二进制。具体命令见[开发指南](development.md)。数据根损坏时不要用 `cargo clean` 或删除 Lance manifest 试图修数据库。

Even `du` can take time on a large target. Do not run a second Cargo to accelerate the first or duplicate large targets/backups. Check installed binary references before cleanup. See [Development](development.md). Neither `cargo clean` nor deleting Lance manifests repairs a damaged database.

## 如何提交问题 / Reporting an issue

提供：Git commit、系统/WSL 情况、Rust 版本（构建问题）、精确命令、退出码、脱敏错误、是否使用用户服务、问题发生在哪个阶段。模型问题可提供 provider 类型和 model 名，不提供 key。注明来自真实环境还是测试环境。

Include the commit, OS/WSL, Rust version for builds, exact command, exit code, sanitized error, service mode and failing stage. For model issues include provider type/model name, never the key. Distinguish real use from tests.

不要上传 `.work/`、原始 session/transcript、CAS、数据库、完整备份、凭据环境或未经检查的 exports。若一条错误中的路径/正文敏感，先脱敏；不要为了复现自动开启真实 canary、扩大模型预算或放宽信任。

Do not upload private work records, raw sessions/transcripts, CAS, databases, backups, credential environments or unchecked exports. Sanitize paths/content. Do not automatically launch a live canary, expand model spend or weaken trust just to reproduce a report.
