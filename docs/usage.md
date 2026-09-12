# 使用方法 / Usage

[文档目录 / Documentation](README.md) · [安装与接入 / Setup](getting-started.md)

## 基本使用流程 / Everyday workflow

正常工作 → 获准采集/导入的记录 → 后台摘要；方法提议和后续复核是独立流程。需要回忆时通过 MCP 检索，在结果中查看来源、适用范围和未验证警告。基本记忆无需前台 agent 每次调用 add/organize，也无需你逐条接受摘要。

Normal work → permitted capture/import → background summaries. Method proposals and later review are separate flows. Read memory through MCP when needed, checking source, scope and uncertainty. Basic memory requires neither an add/organize call after each task nor manual acceptance of every summary.

摘要只来自受支持且有正文许可的记录。记录存在、导入已排队、摘要完成、检索返回和“方法确实有效”是不同状态；不要互相替代。后台整理需要新来源证据和预算，不会靠反复启动自动补出缺失事实。

Summaries require supported records with body permission. Record existence, queued import, completed summary, returned content and proven method effectiveness are different states. Review requires new source evidence and budget; restarting does not supply missing facts.

## CLI 与 MCP 的区别 / CLI versus MCP

`evertrace --help` 是当前 CLI 参数真源。CLI 提供配置、诊断、安装、管理、备份和 TUI 等入口；**没有 `evertrace search` 或 `evertrace get` 子命令**。search/get 是 MCP 工具的 action。

Use `evertrace --help` for CLI arguments. The CLI handles configuration, diagnostics, installation, administration, backup and TUI. **There are no `evertrace search` or `evertrace get` CLI subcommands**; these are actions on the MCP tool.

宿主启动 `evertrace ... mcp` 作为 stdio MCP 服务；该进程通过本地 UDS 联系 daemon，不监听公开 TCP。直接运行后等待输入是正常行为，不是一个聊天提示符。优先使用安装器生成的宿主接线，不手工伪造绑定标识或 claim。

The host launches `evertrace ... mcp` as a stdio MCP server. It connects to the daemon over local UDS, not a public TCP listener. Waiting for input when launched manually is normal; it is not a chat prompt. Prefer installer-generated wiring; never fabricate binding tokens or claims.

## MCP 输入与示例 / MCP input and examples

工具名为 `evertrace`（宿主可能显示为带 MCP server 前缀的名称）。它只有 `search`、`get`、`add`、`organize` 四个 action。参数为必需的 `action`、`workspace`、`input` 和可选 `refs`；`input` 是字符串，不是任意 JSON 对象。额外顶层字段会被拒绝。

The tool is named `evertrace` (a host may show a server-prefixed name). Its four actions are `search`, `get`, `add`, `organize`. Required fields are `action`, `workspace`, `input`; `refs` is optional. `input` is a string, not an arbitrary JSON object. Extra top-level fields are rejected.

`input` 最多 4096 UTF-8 bytes；workspace 最多 4096 bytes；最多 32 个 refs、每个最多 512 bytes。长中文输入不能简单按字符数计算。示例是工具参数，不是终端命令。

`input` is limited to 4096 UTF-8 bytes, workspace to 4096 bytes, and refs to 32 entries of at most 512 bytes each. Multibyte text is not counted by character count. The following are tool arguments, not shell commands.

有可解析的当前上下文时搜索： / Search with a resolvable current context:

```json
{"action":"search","workspace":"@active","input":"Why did the previous database migration fail?"}
```

没有可靠当前绑定时，可用实际仓库/worktree ID，或已知可信仓库的显式路径提示。路径提示不是创建身份或绕过权限的命令，不接受裸相对路径：

Without a reliable current binding, use an actual repository/worktree ID or an explicit path hint for a known trusted repository. A path hint does not create identity or bypass authorization; bare relative paths are not accepted:

```json
{"action":"search","workspace":"path_hint:/absolute/path/to/project","input":"Lessons from the last migration"}
```

读取搜索返回的真实 object ref，将下面占位值替换成返回值，不手工拼造 ID： / Read an actual object ref returned by search; replace the placeholder rather than inventing an ID:

```json
{"action":"get","workspace":"path_hint:/absolute/path/to/project","input":"<object_ref returned by search>"}
```

`@due` 是保留的主动召回输入，仅在宿主提供相应 cue 且独立能力门、绑定和权限都满足时使用；不要用它测试普通关键词搜索。无可靠绑定时，显式范围普通读取仍需满足对应来源/信任条件，并非全库搜索后门。

`@due` is reserved for active recall when a host cue and the independent gate/binding/permissions allow it. Do not use it as a general search test. Explicit-scope reads still require source access and trust; they are not a full-database bypass.

`add`/`organize` 用于支持的显式声明或整理，不是“让记忆正常工作”所必需的日常动作。它们的内部载荷是受限格式；不要让 agent 自行发明 task、接受状态、效果证明或权限字段。人工治理优先在 TUI 查看当前对象和可用操作。

`add`/`organize` serve supported explicit declarations or organization, not mandatory daily bookkeeping. Their payloads are closed formats; do not invent task identities, acceptance states, effectiveness evidence or authority fields. Prefer TUI actions for human governance of current objects.

## 如何理解返回结果 / Interpret results

| 返回内容 / Content | 意义 / Meaning |
|---|---|
| 来源证据、摘要 / Source evidence, digest | 可追溯的事实或派生记忆；不是执行许可。 / Traceable facts or derived memory, not execution permission. |
| 未接受的方法提议 / Unaccepted method proposal | Pending/Validating 的本地参考，效果未验证；不等于正式 Procedure APPLY。 / A local reference with unverified effectiveness, not an accepted Procedure APPLY. |
| 正式方法 / Accepted procedure | 仍有适用范围、版本、状态和使用条件；返回不证明使用成功。 / Still constrained by scope, version, state and use conditions; returned does not mean successfully used. |
| 规范性约束 / Normative constraint | 需要独立策略来源和权限验证；普通文本不能自授此身份。 / Requires separately verified policy source and authority. |
| Warning/partial/unavailable | 阅读警告和来源缺项；不把缺证当成反证，也不忽略降级继续执行危险操作。 / Inspect missing evidence and warnings; absence is not proof, and degraded results are not permission for risky actions. |

## 终端界面 / Terminal UI

```sh
evertrace --config /absolute/config.toml tui
```

三个主要页面：Inbox 查看待治理的提议；Explorer 浏览来源和对象、详情与关联；System 查看 daemon、配置、后台 job、备份和诊断。显示为空时先刷新，再检查来源许可和任务状态，不猜造对象。

The three main pages are Inbox (proposals), Explorer (sources, objects, details and relations), and System (daemon/configuration/jobs/backups/diagnostics). Refresh and check access/job state before interpreting an empty view.

| 按键 / Key | 操作 / Action |
|---|---|
| `1` / `2` / `3` | Inbox / Explorer / System |
| `j` / `k` | 下一项 / 上一项；next / previous |
| `Enter` | 打开所选详情；open selected detail |
| `r` | 刷新；refresh |
| `n` / `b` | 下一页 / 首页；next / first page |
| `q` | 退出 TUI；quit TUI |
| System 中 `C` | 编辑配置；edit configuration |
| System 中 `B` / `V` | 创建备份 / 验证所选备份；create / verify selected backup |

以页面底部提示和当前对象支持的操作为准；编辑/确认模式下按键含义可能不同。写操作依赖当前 revision/frontier，发生冲突应刷新并重新判断，不循环提交旧版本。Recovery/Forget/Accept 等动作必须先看详情和确认提示。

Use the footer and actions supported by the selected object; keys differ in edit/confirmation modes. Writes depend on current revisions/frontiers. On conflict, refresh and reassess instead of repeatedly submitting stale state. Inspect details before Recovery, Forget or Accept actions.

## 会话导入和范围管理 / Import and scope administration

元数据回填不等于所有历史正文都会自动上传或导入。先在 System/Explorer 找到实际会话及来源许可；需要手动补导入或撤销时，可使用：

Metadata backfill is not automatic permission to import/upload every historical body. Find the actual session and source access state in System/Explorer. For explicit import/revocation:

```sh
evertrace --config /absolute/config.toml admin session queue SESSION_ID
evertrace --config /absolute/config.toml admin session revoke SESSION_ID
```

请求仍受来源、路径、信任和并发/大小限制；queue 是提交，不是完成。revoke 不是删除原始宿主会话文件。查看 System 的最终 job 和诊断。

Requests remain subject to source/path/trust/concurrency/size checks. Queueing is not completion; revocation does not delete the original host session file. Inspect the final System job/diagnostic.

仓库管理命令的 ID、revision、worktree 和可选 inventory job 必须来自当前状态： / Repository administration requires IDs, revisions, worktrees and optional inventory jobs from current state:

```sh
evertrace --config /absolute/config.toml admin repository disable REPOSITORY_ID REVISION
evertrace --config /absolute/config.toml admin repository enable REPOSITORY_ID REVISION WORKTREE_ID
evertrace --config /absolute/config.toml admin repository rescan REPOSITORY_ID REVISION WORKTREE_ID INVENTORY_JOB_ID
```

disable/enable/rescan 不等于 Forget 或物理 purge，也不自动授予宿主未给出的信任。删除、导出和维护的区别见[运维与隐私](operations.md)。

Disable/enable/rescan are not Forget or physical purge, and do not manufacture host trust. See [Operations and privacy](operations.md) for deletion, export and maintenance distinctions.
