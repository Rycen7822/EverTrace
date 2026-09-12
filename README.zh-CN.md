# EverTrace

面向 coding agent 和研究型 agent 的本地优先记忆系统。当前宿主适配器面向 Codex。

[English](README.md) | 简体中文

EverTrace 将获准采集的活动保存为可追溯的证据，在后台生成摘要，让后续会话能够检索以前的决策、失败经验和方法。基本记忆不要求前台 agent 另外维护记忆文件，也不要求每次任务后调用写入工具记账。

**当前状态：适合受控本地试用的源码预览版，不是已经完成真实环境验证的开箱即用正式版。** 本地实现已有自动化测试，但你的实际宿主兼容性和所选模型的记忆质量仍需试用确认。

## 能做什么

- 采集受支持的宿主事件，导入获准读取的会话记录，保存在本地。
- 使用配置好的后台 LLM，从来源记录生成摘要记忆。
- 独立提议、复核可复用的方法；合格的未接受方法可作为明确标注“效果未验证”的参考被检索。
- 通过 MCP 工具读取记忆，在终端 UI 中查看证据、提议和系统状态。
- 按仓库、worktree、来源权限和删除状态限制访问，并在保存内容前进行秘密检测与保护。
- 提供备份、恢复、导出，以及受约束的工作区恢复操作。

“本地优先”不等于启用 LLM 后仍完全离线：选中的受保护来源内容会发送给你配置的模型提供方。首次检查本地环境可以使用关闭 LLM 的试用配置。

## 文档导航

以下指南使用中英双语说明，命令示例共用。

| 文档 | 内容 |
|---|---|
| [安装与首次使用](docs/getting-started.md) | 环境要求、编译、首次启动、宿主接入 |
| [配置说明](docs/configuration.md) | 路径、模型凭据、预算、热重载 |
| [使用方法](docs/usage.md) | 记忆流程、MCP 示例、TUI、会话导入 |
| [运维与隐私](docs/operations.md) | 数据处理、备份、恢复、升级、卸载 |
| [故障排查](docs/troubleshooting.md) | 没有记忆、能力关闭、服务和编译错误 |
| [架构与能力边界](docs/architecture.md) | 模块职责、证据含义与未交付能力 |
| [开发指南](docs/development.md) | 资源可控的编译、验证和贡献方式 |

## 快速开始

当前实现以 Linux 为目标，也可在满足条件的 WSL2 Linux 环境中试用。精确 Rust 工具链为 **1.97.1**。原生编译依赖和 systemd 注意事项见[安装指南](docs/getting-started.md)。

在仓库根目录执行：

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo +1.97.1 build --locked -p evertrace-cli -p evertraced -p evertrace-hook
./target/debug/evertrace --help
./target/debug/evertrace --config docs/examples/evertrace.local.toml config check
```

将 [LLM 关闭版试用配置](docs/examples/evertrace.local.toml) 复制到自己的配置目录，再启动 daemon。不要覆盖已有配置；该示例使用独立的 `evertrace-trial` 数据目录。

```sh
umask 077
mkdir -p "$HOME/.config/evertrace"
cp -n docs/examples/evertrace.local.toml "$HOME/.config/evertrace/config.toml"
./target/debug/evertrace --config "$HOME/.config/evertrace/config.toml" config show --effective
```

确认 LLM 已关闭；已有文件不会被替换。然后启动 daemon：

```sh
./target/debug/evertraced --config "$HOME/.config/evertrace/config.toml"
```

另开终端执行 `./target/debug/evertrace --config "$HOME/.config/evertrace/config.toml" doctor` 或 `tui`。空安装没有记忆是正常的；需要继续完成[宿主接入和第一条记忆的验证](docs/getting-started.md)，才能使用自动采集和后台摘要。

不要以 root 身份运行安装命令。安装会修改受管宿主配置，并可能启用用户服务；它是单独的一步，不包含在上述命令中。

## “可用”不意味着所有能力都已验证

后台摘要本身就是可使用的记忆。方法提议与摘要独立：以证据形式返回的方法，不等于正式接受的指令、不等于已经证明有效，更不代表执行许可。

- 新的 LLM 摘要和方法建议需要启用模型；并非所有本地存储和读取都需要模型。
- 普通来源记忆读取不要求修改宿主源码，但必须满足信任和来源访问条件。
- 没有读取请求时，不保证记忆主动送达。
- 采集完整性、恢复资格、主动召回、强跨来源归一和项目策略权限分别有独立的宿主能力门；安装成功或一次探测成功不能全部开启它们。
- **完整 AutoFull 资格判定与首次自动受理尚未交付。** `procedure.auto_publish_full = true` 只是配置意图，不代表完整自动发布已经可用。
- 通用实验结果验证已有服务级实现，但尚未验证任意正常工具结果都能自动接入。
- 本地测试不能替代真实认证宿主验收、模型质量、自然使用中的方法有效性和高级检索效果评测。

请先用非敏感测试项目试用。不要把 RecoveryBundle 当成唯一备份，也不要把模型生成的记忆当成规范性策略。详见[能力边界](docs/architecture.md)和[隐私注意事项](docs/operations.md)。

## 开发与仓库结构

`crates/` 是 Rust workspace；`config/` 提供完整配置示例；`packaging/` 包含受管接入模板；`fixtures/` 是测试输入；`docs/` 是公开的使用与开发指南。

`docs/baseline/` 下的本地设计归档、`.work/` 下的编排记录以及 agent 指令和状态文件有意被 Git 忽略。使用公开指南不依赖这些文件；不要强制添加私有笔记、模型凭据或运行数据。

验证命令与资源控制见[开发指南](docs/development.md)。反馈问题时提供提交版本、平台、复现命令和脱敏错误，不要附原始会话归档或凭据。

Workspace 包元数据声明为 `Apache-2.0`，见 [Cargo.toml](Cargo.toml)；依赖及外部采集内容的权利需分别处理。
