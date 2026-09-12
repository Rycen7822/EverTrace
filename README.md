# EverTrace

Local-first memory for coding and research agents. The current host adapter targets Codex.

English | [简体中文](README.zh-CN.md)

EverTrace retains permitted activity as traceable evidence, produces background summaries, and makes earlier decisions, mistakes and methods available to later sessions. Basic memory does not require the foreground agent to maintain a separate memory file or call a write tool after every task.

**Status: source-build preview for controlled local trials, not a fully validated turnkey release.** The local implementation has automated test coverage; compatibility with your actual host and the quality of your chosen model must still be checked.

## What it does

- Capture supported host events and import permitted session records into local storage.
- Produce source-backed summaries with a configured background LLM.
- Independently propose and review reusable methods; expose eligible unaccepted methods as explicitly unverified references.
- Read memory through an MCP tool; inspect evidence, proposals and system state in a terminal UI.
- Apply repository/worktree scope, source permissions, secret protection and deletion checks.
- Provide backup, restore, export and guarded recovery operations.

Local-first does **not** mean network-free when LLM processing is enabled. Selected protected source content is sent to your configured provider. Start with the LLM-off example if you want to inspect the local setup first.

## Documentation

The guides are bilingual; command blocks are shared between Chinese and English explanations.

| Guide | Contents |
|---|---|
| [Getting started](docs/getting-started.md) | Requirements, build, first launch, host integration |
| [Configuration](docs/configuration.md) | Paths, model credentials, budgets, reload |
| [Usage](docs/usage.md) | Memory workflow, MCP examples, TUI, session import |
| [Operations and privacy](docs/operations.md) | Data handling, backup, restore, upgrade, uninstall |
| [Troubleshooting](docs/troubleshooting.md) | Missing memory, disabled gates, service and build failures |
| [Architecture and limitations](docs/architecture.md) | Component responsibilities and actual capability boundaries |
| [Development](docs/development.md) | Resource-conscious builds, checks and contribution guidance |

## Quick start

The current implementation targets Linux, including suitable WSL2 Linux environments. Use the exact Rust toolchain **1.97.1**. Native build prerequisites and systemd caveats are in [Getting started](docs/getting-started.md).

From the repository root:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo +1.97.1 build --locked -p evertrace-cli -p evertraced -p evertrace-hook
./target/debug/evertrace --help
./target/debug/evertrace --config docs/examples/evertrace.local.toml config check
```

Copy the [LLM-off trial configuration](docs/examples/evertrace.local.toml) to your own configuration directory before starting a daemon. Do not overwrite an existing configuration. That example uses a separate `evertrace-trial` data directory.

```sh
umask 077
mkdir -p "$HOME/.config/evertrace"
cp -n docs/examples/evertrace.local.toml "$HOME/.config/evertrace/config.toml"
./target/debug/evertrace --config "$HOME/.config/evertrace/config.toml" config show --effective
```

Check that LLM processing is disabled; an existing file was not replaced. Then start the daemon:

```sh
./target/debug/evertraced --config "$HOME/.config/evertrace/config.toml"
```

In a second terminal, run `./target/debug/evertrace --config "$HOME/.config/evertrace/config.toml" doctor` or `tui`. An empty installation has no memories yet. Follow the [host setup and first-memory walkthrough](docs/getting-started.md) before expecting automatic collection and summaries.

Do not run the installer as root. Installation changes managed host configuration and may enable a user service; it is a separate step, not part of the commands above.

## What “available” does and does not mean

Background summaries are useful memory in their own right. Method proposals are separate: a proposal returned as evidence is not an accepted instruction, a proven effective method, or permission to execute anything.

- Enabling an LLM is necessary for new LLM-generated summaries and method suggestions; it is not necessary for all local storage and read operations.
- Ordinary source-backed reads do not require modifying host source code. Trust and source access still apply.
- Without a read request, proactive delivery is not guaranteed.
- Capture completeness, recovery qualification, active recall, strong cross-source normalization and project-policy authority have independent host gates. Installation or one successful probe does not enable all of them.
- **Complete AutoFull qualification and initial automatic acceptance are not delivered.** `procedure.auto_publish_full = true` is configuration intent, not a working full-auto guarantee.
- General experiment-result verification has service-level implementation, not a verified autonomous path for every normal tool result.
- Real authenticated-host acceptance, model quality, natural method effectiveness and advanced retrieval-quality evaluation are not established by the local test suite.

Use a non-sensitive test project first. Do not treat recovery bundles as your only backup or model-generated memory as authoritative policy. See [limitations](docs/architecture.md) and [privacy precautions](docs/operations.md).

## Development and repository layout

`crates/` contains the Rust workspace; `config/` contains the full configuration example; `packaging/` contains managed integration templates; `fixtures/` contains test inputs; `docs/` contains public user and contributor guides.

Local design archives under `docs/baseline/`, orchestration records under `.work/`, and agent instruction/state files are intentionally ignored. They are not prerequisites for following these public guides. Do not force-add private notes, model credentials or runtime data.

See [Development](docs/development.md) for checks and resource limits. Report reproducible failures with the commit, platform, command and sanitized error; never attach raw session archives or credentials.

The workspace package metadata declares `Apache-2.0`; see [Cargo.toml](Cargo.toml). Dependency and externally collected content rights remain separate.
