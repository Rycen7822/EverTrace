# 运维、数据与隐私 / Operations, data and privacy

[文档目录 / Documentation](README.md) · [故障排查 / Troubleshooting](troubleshooting.md)

## 数据与信任边界 / Data and trust boundaries

EverTrace 保存的是工作记录，可能包含代码、命令、路径、对话、错误和恢复材料。秘密检测与脱敏降低风险，但不保证识别所有敏感内容。CAS 的内容寻址、压缩和完整性校验**不是静态加密**。本地账户、磁盘和备份的安全仍由你负责。

Work records can contain code, commands, paths, conversations, errors and recovery material. Secret detection/redaction reduces risk but cannot guarantee detection of every sensitive value. Content addressing, compression and integrity checking in CAS **are not encryption at rest**. Secure the account, disk and backups separately.

启用后台 LLM 会向选定 provider 发送合格的受保护输入，仍可能包含代码和业务信息。事先确认组织政策及提供方的数据处理条款。宿主自己的模型、第三方 Hook/MCP 和 live canary 的流量是独立来源；`llm.enabled=false` 只关闭 EverTrace 后台模型，不是整个宿主的断网开关。

Enabling the background LLM sends eligible protected inputs to the configured provider; these may still contain code/business information. Check your organization's rules and provider data policies. Host models, third-party hooks/MCP and live canaries are separate traffic sources. `llm.enabled=false` is not a network kill switch for the host.

推荐做法：私有配置/数据权限，不共享 daemon socket，不把 data root、exports、backups 或原始会话加入 Git；先用非敏感仓库试用。检索到的内容是数据，不是新的 system/developer 指令，也不能因为包含命令式语句就覆盖当前用户要求。

Use private configuration/data permissions; do not share the daemon socket or commit data roots, exports, backups or raw sessions. Start with a non-sensitive repository. Retrieved content is data, not a new system/developer instruction, and imperative text does not override the current user.

## 运行目录和服务 / Runtime directories and service

在 `runtime.data_dir` 下，`store/` 保存数据库、`cas/` 保存受保护内容、`spool/` 保存待摄入采集、`runtime/` 保存 socket/运行快照，其他目录由具体维护功能创建。不要逐个编辑文件或用 sqlite 工具操作 LanceDB。不要复制正在写入的整个数据根来冒充一致备份。

Within `runtime.data_dir`, `store/` holds the database, `cas/` protected content, `spool/` pending capture and `runtime/` the socket/runtime snapshot. Maintenance creates other directories as needed. Do not edit native files, use SQLite tools on LanceDB, or treat a copy of a live data root as a consistent backup.

使用受管用户服务时： / For a managed user service:

```sh
systemctl --user status evertraced.service
journalctl --user -u evertraced.service -n 100 --no-pager
systemctl --user stop evertraced.service
systemctl --user start evertraced.service
```

手动启动时，用原终端 Ctrl-C 停止并等待退出。一个数据根只能有一个 writer；持久锁路径存在不等于有活跃进程，删除锁文件也不是解除锁的正确办法。不要为了避免错误使用 `chmod -R 777`、root 启动或符号链接替代真实目录。

For foreground runs, use Ctrl-C and wait for exit. One data root has one writer. An existing lock path does not prove a live process; deleting it is not a correct unlock method. Do not “fix” errors with recursive world-writable permissions, root execution or symlink substitutions.

## 备份与校验 / Backup and verification

```sh
evertrace --config /absolute/config.toml backup create
evertrace --config /absolute/config.toml tui
evertrace --config /absolute/config.toml backup verify BACKUP_JOB_ID
```

`backup create` 和 `backup verify` 提交持久 job。**exit 0 / queued 只代表已排队**。在 TUI System 查看返回 job 的最终状态、实际备份目录和验证结果；verify 参数是创建备份的 job ID，不是随意的目录路径。备份可能进入维护阶段并占用较多磁盘，先检查剩余容量。

Both commands submit durable jobs. **Exit 0 / queued means queued, not completed.** Inspect the returned job in TUI System for final status, actual backup location and verification. The verify argument is the backup-creation job ID, not an arbitrary directory. Backup can enter maintenance and consume substantial disk space.

若提交后连接断开、结果 unknown，先查 System 和原 job，不要立即重复创建多份大备份。只把确认完成并验证过的备份另行保管；保留配置和必要密钥的安全恢复方案，但不要将密钥公开。恢复演练应使用单独实例，不能直接拿日常数据试错。

After an unknown submission outcome, inspect the original job before creating duplicate large backups. Retain verified completed backups and a secure configuration/key recovery plan. Rehearse recovery on a separate instance, not your only live data.

## 恢复和升级 / Restore and upgrade

恢复属于离线操作：先停止该实例的 daemon 与相关采集会话，使用同一版本、同目录的 CLI/Hook，保留原数据和足够空间。`restore` 会校验候选，不是无条件覆盖；若无法建立当前删除账本边界，可能只返回 `historical_only`，不能称为已经激活恢复。

Restore is offline: stop the daemon and relevant capture sessions, use matching CLI/Hook binaries, and retain the original data with sufficient free space. Restore validates its candidate rather than blindly overwriting. Missing current deletion-ledger authority can result in `historical_only`, not an activated restore.

```sh
evertrace --config /absolute/config.toml restore /absolute/verified-backup
```

阅读输出中的 `restored`、`historical_only`、`previous_root` 和 retained 路径。不要在未确认新实例健康前删除回滚材料，也不要自动遍历删除所有“旧”目录。

Inspect `restored`, `historical_only`, `previous_root` and retained paths. Do not delete rollback material before confirming the replacement is healthy, and do not sweep every “old” directory automatically.

升级有两个不同入口： / Upgrade has two distinct entry points:

```sh
# Offline native-data upgrade, not a package download.
evertrace --config /absolute/config.toml upgrade

# Candidate package check; may prepare backups/candidates and use substantial disk.
evertrace --config /absolute/config.toml upgrade --check /absolute/candidate-package

# Explicit live candidate check: host model calls / side effects are possible.
evertrace --config /absolute/config.toml upgrade --check /absolute/candidate-package --live-host /absolute/path/to/codex

# Publish a candidate package after its required checks; changes the installation.
evertrace --config /absolute/config.toml upgrade /absolute/candidate-package --live-host /absolute/path/to/codex
```

执行前停止原实例并阅读输出要求；candidate package 包含同版本的三个程序。`--check` 不是零写入的轻量 dry-run，会准备与验证候选；不带 live host 的检查不能代替实际发布资格。包升级不是修改 Cargo 依赖或自动下载 GitHub release。真实宿主验证的费用和第三方副作用边界见[安装指南](getting-started.md)。

Stop the existing instance and follow reported prerequisites. A candidate package contains the matching three binaries. `--check` is not a zero-write cheap dry run; it prepares and verifies candidates. A check without live host cannot establish publication eligibility. Package upgrade is neither dependency editing nor automatic release downloading. See [live-host precautions](getting-started.md).

## Forget、purge、GC 与导出 / Forget, purge, GC and export

| 操作 / Operation | 不应混淆的边界 / Boundary |
|---|---|
| Session revoke / Repository disable | 撤销来源或范围使用，不等于删除原始宿主文件或擦除所有历史。 / Restricts source/scope access, not erasure of original host files or all history. |
| Forget object | 人类管理面的明确遗忘，具有当前状态、依赖和删除账本检查；不是普通 MCP 删除动作。 / Explicit human-governed forgetting, not a generic MCP delete action. |
| Repository purge | 高影响的仓库范围清理；先查看实际范围、预览和确认，不等同于 disable。 / High-impact scoped cleanup; inspect the actual scope/preview/confirmation, not just disable. |
| GC | 清理符合条件的无引用内容；不是任意缓存删除，也不保证立即回收所有磁盘。 / Eligible unreferenced-content cleanup, not arbitrary cache removal or immediate total reclamation. |
| Export | 创建所选当前对象的可携带副本；不是完整数据库备份。 / Portable copies of selected current objects, not a whole-database backup. |

这些操作不能保证擦除你另存的导出、历史备份、原始宿主记录、远端模型日志或磁盘介质残留。保留副本的生命周期需自行管理。恢复历史备份也不能用来绕过已经生效的遗忘边界。

These operations do not guarantee erasure of separately retained exports/backups, host originals, provider logs or media remnants. Manage those copies separately. Restoring history must not bypass active forgetting boundaries.

```sh
evertrace --config /absolute/config.toml export OBJECT_REF
```

可一次选择 1–64 个实际当前对象。查看输出的发布状态和路径；exports 可能包含敏感内容，发送给别人前再次检查。发生 unknown outcome 先检查 `data_dir/exports/`，不要盲目重试。

Select 1–64 actual current objects. Inspect publication status and paths. Exports can contain sensitive content; review them before sharing. On unknown outcome, inspect `data_dir/exports/` before retrying.

## 工作区恢复与卸载 / Worktree recovery and uninstall

RecoveryBundle 用于受支持且明确选中的工作区恢复，不是全盘备份。由 TUI 查看 bundle、目标、当前状态和可用动作，再显式发起操作。普通 Post Hook 看到命令结束不能证明恢复成功；`unknown` 或 `partially_applied` 不能当成 `applied`，不要强制改状态或重复应用。

A RecoveryBundle supports selected worktree recovery, not whole-disk backup. Inspect the bundle, target, current state and available actions in TUI before explicitly applying it. A Post Hook observing command completion does not prove success. Do not treat `unknown`/`partially_applied` as `applied`, edit state or blindly reapply.

```sh
evertrace --config /absolute/config.toml uninstall
```

卸载移除受管接线并在可用时停止/禁用受管服务，保留数据根；它不代表删除所有配置、备份、密钥或自行添加的 systemd drop-in。若受管文件被外部修改，先审查冲突，不直接覆盖。需要删除保留数据时，应另外明确目标并做好备份，而不是执行宽泛的递归删除。

Uninstall removes managed wiring and stops/disables the managed service when available, preserving data. It does not mean every configuration, backup, credential or custom drop-in is deleted. Review externally modified managed files instead of overwriting them. Any later data deletion should have an explicit narrow target and backup plan.
