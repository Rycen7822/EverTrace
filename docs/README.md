# 使用文档 / User documentation

[English README](../README.md) · [中文 README](../README.zh-CN.md)

这里是面向使用者和贡献者的公开指南，不是开发进度日志。各页使用中英双语说明，代码块共用；以当前 checkout 的源码和 `evertrace --help` 核对具体参数。

These are public user and contributor guides, not development journals. Each guide includes Chinese and English explanations with shared command blocks. Command details must match the current checkout and `evertrace --help`.

| 指南 / Guide | 适用问题 / Questions answered |
|---|---|
| [安装与首次使用 / Getting started](getting-started.md) | 如何编译、启动、接入宿主并验证第一条记忆？ / How do I build, start, integrate and test one memory? |
| [配置 / Configuration](configuration.md) | 配置在哪里？如何设置模型、密钥和预算？ / Where are settings, credentials and budgets? |
| [使用方法 / Usage](usage.md) | 如何检索、查看、导入和理解返回结果？ / How do I read, inspect and import memory? |
| [运维与隐私 / Operations and privacy](operations.md) | 如何备份、恢复、升级、卸载和保护数据？ / How do I maintain and protect data? |
| [故障排查 / Troubleshooting](troubleshooting.md) | 没有记忆、服务连接失败、模型不工作怎么办？ / How do I diagnose missing memory and failures? |
| [架构与限制 / Architecture and limitations](architecture.md) | 各模块负责什么？哪些能力仍有限制？ / What owns each behavior and what is not delivered? |
| [开发 / Development](development.md) | 如何验证改动、避免高内存构建和提交私有文件？ / How do I test changes and avoid resource or privacy mistakes? |

## 建议阅读顺序 / Suggested order

首次使用：安装 → 配置 → 使用方法。接入真实项目之前阅读隐私与能力限制；维护已有实例时先阅读运维。编译失败再查故障排查与开发指南，不要先升级锁定依赖。

First use: getting started → configuration → usage. Read privacy and capability limitations before connecting a real project. For an existing instance, read operations before changing it. Investigate build failures before changing locked dependencies.

## 配置样例 / Examples

- [首次离线试用 / LLM-off local trial](examples/evertrace.local.toml)：关闭后台模型、使用独立试用数据目录。 / Disables background model calls and uses a separate trial data directory.
- [完整配置 / Full configuration](../config/evertrace.example.toml)：包含各配置段；LLM 默认开启且地址和模型名是占位值，不能原样当成可工作的模型配置。 / Includes every section; LLM is enabled with placeholder endpoint/model values, not a working provider setup.

公开文档不依赖被忽略的 `docs/baseline/` 和开发记录；不要为了运行 EverTrace 创建这些私有文件。 / Public guides do not depend on ignored `docs/baseline/` archives or development records; do not create private artifacts just to run EverTrace.
