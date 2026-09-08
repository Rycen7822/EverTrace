//! Deterministic destructive classification, capture, and supervised recovery.

use evertrace_domain::repository::{RecoveryOmission, WorktreeSnapshot};
use evertrace_store::StoreError;
use thiserror::Error;

pub const RECOVERY_ALGORITHM_REVISION: &str = "s16_recovery_v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostCanaryDiagnostic {
    pub scope: HostCanaryScope,
    pub status: HostCanaryStatus,
    pub native_delivery_observed: bool,
    pub mcp_claim_consumed: bool,
    pub capture_receipt_observed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostCanaryScope {
    Installed,
    Candidate { check_id: String, generation: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCanaryStatus {
    NotRun,
    Running,
    Unavailable,
    BudgetExceeded,
    EvidenceMissing,
    TimedOut,
    IdentityChanged,
    Interrupted,
    Observed,
}
pub struct HostCanaryRequest {
    pub host_executable: String,
    pub host_config: String,
}

/// One process-local installed-path probe. Its result is diagnostic only: it
/// cannot construct a capability manifest or modify a runtime snapshot.
#[derive(Clone)]
pub struct HostCanaryService {
    candidate: Option<(String, u64, std::path::PathBuf)>,
    candidate_assets: Vec<(std::path::PathBuf, [u64; 7])>,
    writer: crate::WriterHandle,
    data_root: std::path::PathBuf,
    config_path: std::path::PathBuf,
    config_hash: [u8; 32],
    bindings: crate::McpBindingAuthority,
    running: std::sync::Arc<tokio::sync::Mutex<()>>,
    current: std::sync::Arc<std::sync::Mutex<Option<CurrentCanary>>>,
}

struct CurrentCanary {
    identity: Option<CanaryIdentity>,
    diagnostic: HostCanaryDiagnostic,
}

struct CanaryEvidence {
    processed: std::collections::BTreeSet<evertrace_domain::ids::SourceReceiptId>,
    remaining: (u64, u64),
    pre: std::collections::BTreeMap<String, String>,
    post: std::collections::BTreeMap<String, String>,
    session: Option<String>,
    conflicted: bool,
}

impl Default for CanaryEvidence {
    fn default() -> Self {
        Self {
            processed: Default::default(),
            remaining: (8 << 20, 8 << 20),
            pre: Default::default(),
            post: Default::default(),
            session: None,
            conflicted: false,
        }
    }
}

impl CanaryEvidence {
    // Called only after typed adapter/observation qualification. Unobserved
    // receipts remain in the authoritative snapshot and are retried next tick.
    fn read_once(
        &mut self,
        cas: &evertrace_capture::CasStore,
        id: evertrace_domain::ids::SourceReceiptId,
        reference: &str,
        length: u64,
    ) -> Result<Option<Vec<u8>>, HostCanaryStatus> {
        if self.processed.contains(&id) {
            return Ok(None);
        }
        if self.processed.len() >= 64 || length > self.remaining.1 {
            return Err(HostCanaryStatus::BudgetExceeded);
        }
        self.processed.insert(id);
        let Ok(digest) = evertrace_capture::CasStore::parse_digest(reference) else {
            return Ok(None);
        };
        let (payload, encoded) = match cas.read_bounded(&digest, self.remaining.0, self.remaining.1)
        {
            Ok(value) => value,
            Err(evertrace_capture::CasError::ReadBudgetExceeded) => {
                return Err(HostCanaryStatus::BudgetExceeded);
            }
            // An unsuccessful read may already have used the remaining
            // decode budget. Do not retry other blobs without that cost.
            Err(_) => return Err(HostCanaryStatus::Unavailable),
        };
        self.remaining.0 -= encoded;
        self.remaining.1 -= payload.len() as u64;
        Ok((payload.len() as u64 == length).then_some(payload))
    }
}

#[cfg(test)]
mod canary_evidence_tests {
    use super::*;

    #[test]
    fn repeated_frontiers_do_not_reread_receipts_or_recharge_cas_budget() {
        use evertrace_capture::{CasStore, DeviceKeyStore, protect};
        use evertrace_domain::{ids::SourceReceiptId, revision::RevisionId};
        use std::os::unix::fs::DirBuilderExt;
        let root =
            std::env::temp_dir().join(format!("evertrace-canary-cas-{}", RevisionId::new_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let key = DeviceKeyStore::new(root.join("keys"))
            .load_or_create()
            .unwrap();
        let payload = protect(b"bounded canary payload", &key).unwrap();
        let cas = CasStore::open(root.join("cas")).unwrap();
        let digest = cas.put(&payload).unwrap();
        let id = SourceReceiptId::from_digest([1; 32]);
        let mut state = CanaryEvidence::default();
        let length = payload.protected_bytes().len() as u64;
        assert_eq!(
            state
                .read_once(&cas, id, &digest.as_hex(), length)
                .unwrap()
                .unwrap(),
            payload.protected_bytes()
        );
        let remaining = state.remaining;
        // A later unrelated journal frontier presents the same authority rows.
        for _ in 0..20 {
            assert!(
                state
                    .read_once(&cas, id, &digest.as_hex(), length)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(state.remaining, remaining);
        }
        state.remaining.1 = length - 1;
        assert_eq!(
            state.read_once(
                &cas,
                SourceReceiptId::from_digest([2; 32]),
                &digest.as_hex(),
                length
            ),
            Err(HostCanaryStatus::BudgetExceeded)
        );
        assert_eq!(state.processed.len(), 1);
        state.remaining = remaining;
        std::fs::write(cas.blob_path(&digest), b"invalid envelope").unwrap();
        assert_eq!(
            state.read_once(
                &cas,
                SourceReceiptId::from_digest([3; 32]),
                &digest.as_hex(),
                length
            ),
            Err(HostCanaryStatus::Unavailable),
        );
        drop(cas);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[derive(Clone)]
struct CanaryIdentity {
    files: Vec<(std::path::PathBuf, [u64; 7])>,
    directories: Vec<(std::path::PathBuf, u64, u64)>,
    generation: u64,
}

fn canary_file_identity(path: &std::path::Path) -> Option<[u64; 7]> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return None;
    }
    for parent in path.parent()?.ancestors() {
        let metadata = std::fs::symlink_metadata(parent).ok()?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return None;
        }
    }
    let file = evertrace_capture::open_regular_nofollow(path).ok()?;
    let value = file.metadata().ok()?;
    Some([
        value.dev(),
        value.ino(),
        value.len(),
        value.mtime() as u64,
        value.mtime_nsec() as u64,
        value.ctime() as u64,
        value.ctime_nsec() as u64,
    ])
}

impl CanaryIdentity {
    fn capture(
        data: &std::path::Path,
        config: &std::path::Path,
        request: &HostCanaryRequest,
        deadline: std::time::Instant,
        candidate_package: Option<&std::path::Path>,
    ) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let cli = if let Some(package) = candidate_package {
            package.join("evertrace")
        } else {
            evertrace_codex::install::validate_installed_wiring(
                data,
                config,
                std::path::Path::new(&request.host_config),
            )
            .ok()?
        };
        let snapshot =
            evertrace_codex::install::StableLauncher::freeze_current_snapshot(data, deadline)
                .ok()?;
        let generation = snapshot.generation;
        let mut directories = snapshot
            .files
            .iter()
            .flat_map(|file| file.directories.clone())
            .collect::<Vec<_>>();
        let mut paths = snapshot
            .files
            .into_iter()
            .map(|file| file.source)
            .collect::<Vec<_>>();
        if paths.len() > 16 {
            return None;
        }
        paths.extend([
            cli,
            config.to_owned(),
            std::path::PathBuf::from(&request.host_config),
            std::path::PathBuf::from(&request.host_executable),
            evertrace_capture::RuntimeSnapshot::snapshot_path(data),
        ]);
        if let Some(package) = candidate_package {
            paths.extend([package.join("evertraced"), package.join("evertrace-hook")]);
        }
        for path in &paths {
            let parent = path.parent()?;
            let metadata = std::fs::symlink_metadata(parent).ok()?;
            directories.push((parent.to_owned(), metadata.dev(), metadata.ino()));
        }
        directories.sort();
        directories.dedup();
        if directories.len() > 64 {
            return None;
        }
        let files = paths
            .into_iter()
            .map(|path| Some((path.clone(), canary_file_identity(&path)?)))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            files,
            directories,
            generation,
        })
    }
    fn valid(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        self.files
            .iter()
            .all(|(path, expected)| canary_file_identity(path).as_ref() == Some(expected))
            && self.directories.iter().all(|(path, device, inode)| {
                std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && metadata.dev() == *device
                        && metadata.ino() == *inode
                })
            })
    }
}

fn canary_diagnostic(status: HostCanaryStatus) -> HostCanaryDiagnostic {
    HostCanaryDiagnostic {
        scope: HostCanaryScope::Installed,
        status,
        native_delivery_observed: false,
        mcp_claim_consumed: false,
        capture_receipt_observed: false,
    }
}

struct CanaryRun {
    service: HostCanaryService,
    nonce: String,
    directory: std::path::PathBuf,
    directory_identity: (u64, u64),
    child: Option<std::process::Child>,
    completed: bool,
}

impl CanaryRun {
    fn finish_child(&mut self, force: bool) -> Result<Option<std::process::ExitStatus>, ()> {
        finish_owned_child(&mut self.child, force)
    }
}

pub(crate) fn finish_owned_child(
    owned: &mut Option<std::process::Child>,
    force: bool,
) -> Result<Option<std::process::ExitStatus>, ()> {
    use rustix::{
        io::Errno,
        process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
    };
    let Some(child) = owned.as_mut() else {
        return Ok(None);
    };
    let pid = Pid::from_child(child);
    let observed = loop {
        match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Err(Errno::INTR) => continue,
            Err(Errno::CHILD) => {
                // Custody was lost: never signal a potentially reused PGID.
                *owned = None;
                return Err(());
            }
            Err(_) => return Err(()),
            Ok(value) => break value,
        }
    };
    if observed.is_none() && !force {
        return Ok(None);
    }
    // NOWAIT leaves the leader unreaped until the whole owned group has
    // been signalled, including descendants surviving a natural exit.
    let signalled = loop {
        match kill_process_group(pid, Signal::KILL) {
            Err(Errno::INTR) => continue,
            Ok(()) | Err(Errno::SRCH) => break true,
            Err(_) => break false,
        }
    };
    // Also terminate our direct child if it changed its own process group.
    // Its unreaped identity remains owned even when the old group is gone.
    let directly_stopped = loop {
        match child.kill() {
            Ok(()) => break true,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => break error.raw_os_error() == Some(Errno::SRCH.raw_os_error()),
        }
    };
    let status = child.wait().map_err(|_| ());
    *owned = None;
    if !signalled || !directly_stopped {
        return Err(());
    }
    status.map(Some)
}

impl Drop for CanaryRun {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if self.finish_child(true).is_err() {
            tracing::warn!("canary process-group cleanup failed");
        }
        self.service.bindings.end_canary(&self.nonce);
        if !self.completed
            && let Ok(mut current) = self.service.current.lock()
            && let Some(current) = current.as_mut()
        {
            current.diagnostic = canary_diagnostic(HostCanaryStatus::Interrupted);
        }
        if std::fs::symlink_metadata(&self.directory).is_ok_and(|value| {
            value.is_dir()
                && !value.file_type().is_symlink()
                && (value.dev(), value.ino()) == self.directory_identity
        }) && let Err(error) = std::fs::remove_dir_all(&self.directory)
        {
            tracing::warn!(path = %self.directory.display(), %error, "canary workspace cleanup failed");
        }
    }
}

impl HostCanaryService {
    pub fn new(
        writer: crate::WriterHandle,
        data_root: std::path::PathBuf,
        config_path: std::path::PathBuf,
        config_hash: [u8; 32],
        bindings: crate::McpBindingAuthority,
    ) -> Self {
        Self {
            candidate: None,
            candidate_assets: Vec::new(),
            writer,
            data_root,
            config_path,
            config_hash,
            bindings,
            running: Default::default(),
            current: Default::default(),
        }
    }

    /// Keep the shared probe/result identity while fixing this operation's config.
    pub fn for_config(&self, config: &evertrace_domain::config::EffectiveConfig) -> Self {
        let mut operation = self.clone();
        operation.config_hash = config.hash();
        operation
    }

    /// Only the explicit disposable candidate daemon startup uses this mode.
    pub fn with_candidate(
        mut self,
        check_id: String,
        generation: u64,
        package: std::path::PathBuf,
    ) -> Result<Self, &'static str> {
        if check_id.parse::<evertrace_domain::ids::JobId>().is_err() || generation == 0 {
            return Err("invalid candidate identity");
        }
        evertrace_capture::ConfinedRoot::open_owned_private(&self.data_root)
            .map_err(|_| "invalid candidate root")?;
        for name in ["evertrace", "evertrace-hook", "evertraced"] {
            let path = package.join(name);
            let identity = canary_file_identity(&path).ok_or("invalid candidate package")?;
            self.candidate_assets.push((path, identity));
        }
        let runtime = evertrace_capture::RuntimeSnapshot::load(
            &evertrace_capture::RuntimeSnapshot::snapshot_path(&self.data_root),
        )
        .map_err(|_| "invalid candidate runtime")?;
        evertrace_codex::install::prepare_probe_generation(
            &self.data_root,
            &package.join("evertrace-hook"),
            generation,
            |path| {
                runtime
                    .publish(path)
                    .map_err(|_| evertrace_codex::install::InstallError::Io)
            },
        )
        .map_err(|_| "candidate generation unavailable")?;
        let snapshot = evertrace_codex::install::StableLauncher::freeze_current_snapshot(
            &self.data_root,
            std::time::Instant::now() + std::time::Duration::from_secs(3),
        )
        .map_err(|_| "candidate snapshot unavailable")?;
        for path in snapshot.files.into_iter().map(|file| file.source).chain([
            self.config_path.clone(),
            evertrace_capture::RuntimeSnapshot::snapshot_path(&self.data_root),
        ]) {
            let identity = canary_file_identity(&path).ok_or("invalid candidate asset")?;
            self.candidate_assets.push((path, identity));
        }
        self.candidate = Some((check_id, generation, package));
        Ok(self)
    }

    fn scoped(&self, mut result: HostCanaryDiagnostic) -> HostCanaryDiagnostic {
        if let Some((check_id, generation, _)) = &self.candidate {
            result.scope = HostCanaryScope::Candidate {
                check_id: check_id.clone(),
                generation: *generation,
            };
        }
        result
    }

    pub fn current(&self) -> Option<HostCanaryDiagnostic> {
        if self.candidate.is_some() {
            return None;
        }
        let mut current = self.current.lock().ok()?;
        let current = current.as_mut()?;
        if current
            .identity
            .as_ref()
            .is_some_and(|identity| !identity.valid())
        {
            current.diagnostic = canary_diagnostic(HostCanaryStatus::IdentityChanged);
        }
        Some(current.diagnostic.clone())
    }

    pub async fn run(&self, request: HostCanaryRequest) -> HostCanaryDiagnostic {
        let Ok(_permit) = self.running.try_lock() else {
            return self.scoped(canary_diagnostic(HostCanaryStatus::Running));
        };
        let budget = std::time::Duration::from_secs(30);
        let deadline = std::time::Instant::now() + budget;
        let result = self.scoped(
            tokio::time::timeout(budget, self.run_inner(request, deadline))
                .await
                .unwrap_or_else(|_| canary_diagnostic(HostCanaryStatus::TimedOut)),
        );
        if self.candidate.is_some() {
            return result;
        }
        if let Ok(mut current) = self.current.lock() {
            if let Some(stored) = current.as_mut() {
                stored.diagnostic = result.clone();
            } else {
                // A failed preflight is still the current attempt, not NotRun.
                *current = Some(CurrentCanary {
                    identity: None,
                    diagnostic: result.clone(),
                });
            }
        }
        result
    }

    async fn run_inner(
        &self,
        request: HostCanaryRequest,
        deadline: std::time::Instant,
    ) -> HostCanaryDiagnostic {
        use HostCanaryStatus as Status;
        use std::{
            io::{Read, Write},
            os::unix::{
                fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
                process::CommandExt,
            },
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        if self.candidate.is_none()
            && let Ok(mut current) = self.current.lock()
        {
            *current = None;
        }
        let host_config = std::path::Path::new(&request.host_config);
        if !std::path::Path::new(&request.host_executable).is_absolute()
            || request.host_executable.len() > 4096
            || request.host_config.len() > 4096
            || !host_config.is_absolute()
            || host_config
                .file_name()
                .is_none_or(|name| name != "config.toml")
        {
            return canary_diagnostic(Status::Unavailable);
        }
        if !evertrace_codex::probe::probe_install_host(
            std::path::Path::new(&request.host_executable),
            host_config.parent().unwrap(),
        )
        .is_ok_and(|probe| probe.hooks_enabled)
        {
            return canary_diagnostic(Status::Unavailable);
        }
        let Some(identity) = CanaryIdentity::capture(
            &self.data_root,
            &self.config_path,
            &request,
            deadline,
            self.candidate
                .as_ref()
                .map(|(_, _, package)| package.as_path()),
        ) else {
            return canary_diagnostic(Status::Unavailable);
        };
        if self
            .candidate
            .as_ref()
            .is_some_and(|(_, generation, _)| *generation != identity.generation)
        {
            return canary_diagnostic(Status::IdentityChanged);
        }
        let config_current = (|| {
            let file = evertrace_capture::open_regular_nofollow(&self.config_path).ok()?;
            let mut source = String::new();
            file.take(1024 * 1024 + 1)
                .read_to_string(&mut source)
                .ok()?;
            if source.len() > 1024 * 1024 {
                return None;
            }
            let config = evertrace_domain::config::EffectiveConfig::parse_toml(&source).ok()?;
            let runtime = evertrace_capture::RuntimeSnapshot::load(
                &evertrace_capture::RuntimeSnapshot::snapshot_path(&self.data_root),
            )
            .ok()?;
            Some(
                config.hash() == self.config_hash
                    && runtime.effective_config_hash == self.config_hash,
            )
        })()
        .unwrap_or(false);
        if !config_current || !identity.valid() {
            return canary_diagnostic(Status::IdentityChanged);
        }
        if self
            .candidate_assets
            .iter()
            .any(|(path, expected)| canary_file_identity(path).as_ref() != Some(expected))
        {
            return canary_diagnostic(Status::IdentityChanged);
        }
        let Ok(snapshot) = self.writer.project().await else {
            return canary_diagnostic(Status::Unavailable);
        };
        let frontier = snapshot.frontier;
        drop(snapshot);
        let frontier_watch = self.writer.subscribe_background_frontier();
        let mut checked_frontier = frontier;
        let mut evidence = CanaryEvidence::default();
        let nonce = evertrace_domain::revision::RevisionId::new_v7().to_string();
        let directory = self
            .data_root
            .join("runtime")
            .join(format!("canary-{nonce}"));
        if std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .is_err()
        {
            return canary_diagnostic(Status::Unavailable);
        }
        let Ok(metadata) = std::fs::symlink_metadata(&directory) else {
            return canary_diagnostic(Status::Unavailable);
        };
        let mut run = CanaryRun {
            service: self.clone(),
            nonce: nonce.clone(),
            directory: directory.clone(),
            directory_identity: (metadata.dev(), metadata.ino()),
            child: None,
            completed: false,
        };
        let workspace = format!("path_hint:{}", directory.display());
        if !self.bindings.begin_canary(&nonce, &workspace, deadline) {
            return canary_diagnostic(Status::Running);
        }
        if self.candidate.is_none()
            && let Ok(mut current) = self.current.lock()
        {
            *current = Some(CurrentCanary {
                identity: Some(identity.clone()),
                diagnostic: canary_diagnostic(Status::Running),
            });
        }
        // Git initialization is local only; no user repository or credentials are copied.
        let initialized = Command::new("/usr/bin/git")
            .env_clear()
            .args(["init", "--quiet", "--template="])
            .arg(&directory)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(child) = initialized else {
            return canary_diagnostic(Status::Unavailable);
        };
        run.child = Some(child);
        loop {
            match run.finish_child(false) {
                Ok(Some(status)) => {
                    if status.success() {
                        break;
                    }
                    return canary_diagnostic(Status::Unavailable);
                }
                Err(()) => return canary_diagnostic(Status::Unavailable),
                Ok(None) if Instant::now() >= deadline => {
                    return canary_diagnostic(Status::TimedOut);
                }
                Ok(None) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let filename = format!("evertrace-canary-{nonce}.txt");
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(&filename))
            .and_then(|mut file| file.write_all(nonce.as_bytes()));
        if created.is_err() {
            return canary_diagnostic(Status::Unavailable);
        }
        let command = format!("cat {filename}");
        let prompt = format!(
            "EverTrace read-only installation diagnostic. In this disposable workspace only, run exactly this shell command once: {command}. Then call the evertrace MCP tool with action search, workspace {workspace}, input {nonce}, and empty refs. Do not change files, configuration, trust, permissions or repository. Do not use other tools or delegate. Finish after these calls."
        );
        let Ok((mut output, child_output)) = std::os::unix::net::UnixStream::pair() else {
            return canary_diagnostic(Status::Unavailable);
        };
        if output.set_nonblocking(true).is_err() {
            return canary_diagnostic(Status::Unavailable);
        }
        let descriptor: std::os::fd::OwnedFd = child_output.into();
        let mut host_command = Command::new(&request.host_executable);
        if let Some((_, _, package)) = &self.candidate {
            for argument in evertrace_codex::install::candidate_host_arguments() {
                host_command.arg("-c").arg(argument);
            }
            host_command
                .env("EVERTRACE_CANDIDATE_ROOT", &self.data_root)
                .env("EVERTRACE_CANDIDATE_CONFIG", &self.config_path)
                .env("EVERTRACE_CANDIDATE_PACKAGE", package);
        }
        let spawned = host_command
            .args(["exec", "--sandbox", "read-only", "--cd"])
            .arg(&directory)
            .arg(prompt)
            .env("CODEX_HOME", host_config.parent().unwrap())
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::from(descriptor))
            .stderr(Stdio::null())
            .spawn();
        let Ok(child) = spawned else {
            return canary_diagnostic(Status::Unavailable);
        };
        run.child = Some(child);
        let mut output_bytes = 0usize;
        let mut host_finished = false;
        let result = loop {
            let mut buffer = [0u8; 4096];
            for _ in 0..17 {
                match output.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(length) => output_bytes += length,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        output_bytes = 64 * 1024 + 1;
                        break;
                    }
                }
                if output_bytes > 64 * 1024 {
                    break;
                }
            }
            if output_bytes > 64 * 1024 {
                break canary_diagnostic(Status::Unavailable);
            }
            if !identity.valid() {
                break canary_diagnostic(Status::IdentityChanged);
            }
            if Instant::now() >= deadline {
                break canary_diagnostic(Status::TimedOut);
            }
            let exited = match run.finish_child(false) {
                Ok(status) => status,
                Err(()) => break canary_diagnostic(Status::Unavailable),
            };
            if let Some(status) = exited {
                if !status.success() {
                    break canary_diagnostic(Status::Unavailable);
                }
                host_finished = true;
            }
            let observed_frontier = *frontier_watch.borrow();
            if host_finished && observed_frontier > checked_frontier {
                checked_frontier = observed_frontier;
                let mut result = self
                    .collect_canary(
                        frontier,
                        &nonce,
                        &directory,
                        &command,
                        identity.generation,
                        &mut evidence,
                    )
                    .await;
                if !identity.valid() {
                    result = canary_diagnostic(Status::IdentityChanged);
                }
                if result.status != Status::EvidenceMissing {
                    break result;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        if self.candidate.is_none()
            && let Ok(mut current) = self.current.lock()
        {
            *current = Some(CurrentCanary {
                identity: Some(identity),
                diagnostic: result.clone(),
            });
        }
        run.completed = true;
        result
    }

    async fn collect_canary(
        &self,
        frontier: u64,
        nonce: &str,
        directory: &std::path::Path,
        command: &str,
        generation: u64,
        evidence: &mut CanaryEvidence,
    ) -> HostCanaryDiagnostic {
        use HostCanaryStatus as Status;
        let mut result = canary_diagnostic(Status::EvidenceMissing);
        let binding_session = self.bindings.canary_session(nonce);
        let Ok(snapshot) = self.writer.project().await else {
            return result;
        };
        let Ok(cas) = evertrace_capture::CasStore::open_existing(self.data_root.join("cas")) else {
            return result;
        };
        let mut context = evertrace_codex::ProbeContext::unobserved_codex();
        context.adapter_revision = format!("native-hook-v1-generation-{generation}");
        let Ok(report) = evertrace_codex::HostProbeReport::evaluate(
            &context,
            &evertrace_codex::ProbeEvidence::empty(),
        ) else {
            return result;
        };
        let mut observations = std::collections::BTreeSet::new();
        let mut receipts = Vec::new();
        let mut capture_receipts = Vec::new();
        let mut examined = 0usize;
        for row in snapshot
            .data_rows()
            .filter(|row| row.source_event_seq > frontier)
        {
            examined += 1;
            if examined > 4096 {
                return canary_diagnostic(Status::BudgetExceeded);
            }
            let Some(payload) = row.payload_json.as_deref() else {
                continue;
            };
            match serde_json::from_str::<evertrace_store::JournalPayload>(payload) {
                Ok(evertrace_store::JournalPayload::SourceObservationRecorded(value)) => {
                    observations.insert(value.source_receipt_ref);
                }
                Ok(evertrace_store::JournalPayload::SourceReceiptRecorded(value)) => {
                    if receipts.len() >= 64 {
                        return canary_diagnostic(Status::BudgetExceeded);
                    }
                    receipts.push(value);
                }
                Ok(evertrace_store::JournalPayload::CaptureReceiptRecorded(value)) => {
                    if capture_receipts.len() >= 64 {
                        return canary_diagnostic(Status::BudgetExceeded);
                    }
                    capture_receipts.push(value);
                }
                _ => {}
            }
        }
        let mut live_refs = std::collections::BTreeSet::new();
        for receipt in receipts {
            if !observations.contains(&receipt.source_receipt_id)
                || receipt.adapter_manifest_ref != report.manifest().adapter_manifest_id
            {
                continue;
            }
            let source_ref = format!(
                "{}@{}",
                receipt.source_instance_id.as_str(),
                receipt.source_revision.as_str()
            );
            live_refs.insert(source_ref.clone());
            let payload = match evidence.read_once(
                &cas,
                receipt.source_receipt_id,
                &receipt.cas_ref,
                receipt.protected_length,
            ) {
                Ok(Some(payload)) => payload,
                Ok(None) => continue,
                Err(status) => return canary_diagnostic(status),
            };
            let Ok(native) =
                evertrace_codex::binding::NativeToolUse::<serde_json::Value>::from_json(&payload)
            else {
                continue;
            };
            if native.session_id.len() > 1024
                || native.tool_use_id.len() > 1024
                || native.session_id != receipt.source_session_ref
                || std::path::Path::new(&native.cwd) != directory
                || !["command", "cmd"].iter().any(|field| {
                    native
                        .tool_input
                        .get(field)
                        .and_then(|value| value.as_str())
                        == Some(command)
                })
            {
                continue;
            }
            if evidence
                .session
                .as_ref()
                .is_some_and(|session| *session != native.session_id)
            {
                evidence.conflicted = true;
                continue;
            }
            evidence.session = Some(native.session_id);
            match native.hook_event_name {
                evertrace_codex::binding::NativeToolUseEvent::PreToolUse => {
                    evidence.pre.insert(native.tool_use_id, source_ref);
                }
                evertrace_codex::binding::NativeToolUseEvent::PostToolUse => {
                    evidence.post.insert(native.tool_use_id, source_ref);
                }
            }
        }
        if evidence.conflicted {
            return result;
        }
        result.mcp_claim_consumed =
            evidence.session.is_some() && evidence.session == binding_session;
        for (tool, before) in &evidence.pre {
            if live_refs.contains(before)
                && let Some(after) = evidence.post.get(tool)
                && live_refs.contains(after)
            {
                result.native_delivery_observed = true;
                result.capture_receipt_observed |= capture_receipts.iter().any(|receipt| {
                    receipt
                        .adapter_manifest_ids
                        .contains(&report.manifest().adapter_manifest_id)
                        && receipt.source_revision_refs.contains(before)
                        && receipt.source_revision_refs.contains(after)
                });
            }
        }
        if result.native_delivery_observed && result.mcp_claim_consumed {
            result.status = Status::Observed;
        }
        // These one-record weak sources do not establish CaptureReceipt or any
        // stable host sequence, normalization, recovery, policy or @due gate.
        result
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRuntimeSettings {
    pub generation: u64,
    pub effective_config_hash: [u8; 32],
    pub gate: evertrace_capture::RecoveryGateMode,
    pub adapter_manifest_id: Option<String>,
    pub classifier_revision: u32,
    pub capture_timeout_ms: u32,
    pub max_bundle_bytes: u64,
    pub max_untracked_file_bytes: u64,
    pub max_untracked_total_bytes: u64,
    pub recall_cue_gate: evertrace_capture::RecallCueGateMode,
    pub recall_cue_adapter_manifest_id: Option<String>,
}

impl RecoveryRuntimeSettings {
    pub fn compile(
        config: &evertrace_domain::config::EffectiveConfig,
        report: Option<&evertrace_codex::HostProbeReport>,
        generation: u64,
    ) -> Result<Self, RecoveryError> {
        let recovery = &config.config().recovery;
        let capture_timeout_ms = recovery
            .capture_timeout
            .seconds()
            .checked_mul(1_000)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(RecoveryError::InvalidInput)?;
        let mib = |value: u32| {
            u64::from(value)
                .checked_mul(1 << 20)
                .ok_or(RecoveryError::InvalidInput)
        };
        let active_manifest = report
            .filter(|value| {
                value.recovery_barrier_active()
                    && value.recovery().adapter_manifest_revision()
                        == value.manifest().adapter_manifest_id
                    && value.manifest().validate().is_ok()
            })
            .map(|value| value.manifest().adapter_manifest_id.clone());
        let recall_cue_manifest = report
            .filter(|value| {
                let receipt = value.active_search_due();
                receipt.gate_kind() == evertrace_codex::GateKind::ActiveSearchDue
                    && receipt.result() == evertrace_codex::GateResult::Enabled
                    && receipt.reason() == evertrace_codex::GateReason::RequirementsSatisfied
                    && receipt.adapter_manifest_revision() == value.manifest().adapter_manifest_id
                    && value.manifest().validate().is_ok()
            })
            .map(|value| value.manifest().adapter_manifest_id.clone());
        Ok(Self {
            generation,
            effective_config_hash: config.hash(),
            gate: if active_manifest.is_some() {
                evertrace_capture::RecoveryGateMode::Active
            } else {
                evertrace_capture::RecoveryGateMode::Disabled
            },
            adapter_manifest_id: active_manifest,
            classifier_revision: evertrace_codex::recovery::RECOVERY_CLASSIFIER_REVISION,
            capture_timeout_ms,
            max_bundle_bytes: mib(recovery.max_bundle_mib)?,
            max_untracked_file_bytes: mib(recovery.max_untracked_file_mib)?,
            max_untracked_total_bytes: mib(recovery.max_untracked_total_mib)?,
            recall_cue_gate: if recall_cue_manifest.is_some() {
                evertrace_capture::RecallCueGateMode::Active
            } else {
                evertrace_capture::RecallCueGateMode::Disabled
            },
            recall_cue_adapter_manifest_id: recall_cue_manifest,
        })
    }
}

pub fn publish_recovery_runtime(
    data_dir: &std::path::Path,
    config: &evertrace_domain::config::EffectiveConfig,
    report: Option<&evertrace_codex::HostProbeReport>,
) -> Result<evertrace_capture::RuntimeSnapshot, RecoveryError> {
    let snapshot = prepare_recovery_runtime(data_dir, config, report)?;
    snapshot
        .publish(&evertrace_capture::RuntimeSnapshot::snapshot_path(data_dir))
        .map_err(|_| RecoveryError::InvalidInput)?;
    Ok(snapshot)
}

pub(crate) fn prepare_recovery_runtime(
    data_dir: &std::path::Path,
    config: &evertrace_domain::config::EffectiveConfig,
    report: Option<&evertrace_codex::HostProbeReport>,
) -> Result<evertrace_capture::RuntimeSnapshot, RecoveryError> {
    evertrace_capture::DeviceKeyStore::new(data_dir.join("keys"))
        .load_or_create()
        .map_err(|_| RecoveryError::Protection)?;
    let path = evertrace_capture::RuntimeSnapshot::snapshot_path(data_dir);
    let (generation, spool_limits) = match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let current = evertrace_capture::RuntimeSnapshot::load(&path)
                .map_err(|_| RecoveryError::InvalidInput)?;
            (
                current
                    .generation
                    .checked_add(1)
                    .ok_or(RecoveryError::InvalidInput)?,
                current
                    .spool_limits()
                    .map_err(|_| RecoveryError::InvalidInput)?,
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            1,
            evertrace_capture::SpoolLimits {
                high_watermark_bytes: 64 << 20,
                low_watermark_bytes: 48 << 20,
                max_main_files: 64,
                emergency_slots: 8,
            },
        ),
        Err(_) => return Err(RecoveryError::InvalidInput),
    };
    let settings = RecoveryRuntimeSettings::compile(config, report, generation)?;
    let snapshot = evertrace_capture::RuntimeSnapshot::for_data_dir(
        data_dir,
        settings.generation,
        spool_limits,
        evertrace_capture::RecoverySnapshotSettings {
            gate: settings.gate,
            preflight_timeout_ms: settings.capture_timeout_ms,
            effective_config_hash: settings.effective_config_hash,
            adapter_manifest_id: settings.adapter_manifest_id,
            classifier_revision: settings.classifier_revision,
            max_bundle_bytes: settings.max_bundle_bytes,
            max_untracked_file_bytes: settings.max_untracked_file_bytes,
            max_untracked_total_bytes: settings.max_untracked_total_bytes,
            recall_cue_gate: settings.recall_cue_gate,
            recall_cue_adapter_manifest_id: settings.recall_cue_adapter_manifest_id,
        },
    )
    .map_err(|_| RecoveryError::InvalidInput)?;
    Ok(snapshot)
}

/// Called only after the daemon has acquired its writer. Existing spool state
/// stays read-only here; repair/gap handling remains with the ordinary ingestor.
pub fn initialize_runtime_spool(
    snapshot: &evertrace_capture::RuntimeSnapshot,
) -> Result<(), RecoveryError> {
    let limits = snapshot
        .spool_limits()
        .map_err(|_| RecoveryError::InvalidInput)?;
    match std::fs::symlink_metadata(&snapshot.spool_dir) {
        Ok(_) => {
            evertrace_capture::DurableSpool::open_read_only(snapshot.spool_dir.clone(), limits)
                .map(|_| ())
                .map_err(|_| RecoveryError::InvalidInput)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (_, recovery) =
                evertrace_capture::DurableSpool::open(snapshot.spool_dir.clone(), limits)
                    .map_err(|_| RecoveryError::InvalidInput)?;
            if recovery.repaired_tail_bytes != 0 || !recovery.gaps.is_empty() {
                return Err(RecoveryError::InvalidInput);
            }
            Ok(())
        }
        Err(_) => Err(RecoveryError::InvalidInput),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryItemKind {
    TrackedDiff,
    TrackedFile,
    IndexState,
    UntrackedFile,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryCaptureItem {
    pub item_ref: String,
    pub kind: RecoveryItemKind,
    pub bytes: Vec<u8>,
    pub relative_path: Option<Vec<u8>>,
    pub critical: bool,
    pub metadata_only: bool,
}

impl std::fmt::Debug for RecoveryCaptureItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryCaptureItem")
            .field("item_ref", &self.item_ref)
            .field("kind", &self.kind)
            .field("byte_length", &self.bytes.len())
            .field("has_protected_relative_path", &self.relative_path.is_some())
            .field("critical", &self.critical)
            .field("metadata_only", &self.metadata_only)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCaptureFacts {
    pub snapshot: WorktreeSnapshot,
    pub request_id: evertrace_domain::ids::RecoveryCaptureRequestId,
    pub adapter_manifest_id: String,
    pub mutation_manifest_version: u32,
    pub before_fingerprint: Option<String>,
    pub after_fingerprint: Option<String>,
    pub items: Vec<RecoveryCaptureItem>,
    pub omissions: Vec<RecoveryOmission>,
    pub artifact_refs: Vec<String>,
    pub metadata_artifact_refs: Vec<String>,
    pub config_and_run_refs: Vec<String>,
    pub attempt_anchor_ids: Vec<evertrace_domain::ids::AttemptId>,
    pub captured_at_us: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryBudget {
    pub max_item_bytes: u64,
    pub max_untracked_item_bytes: u64,
    pub max_bundle_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryError {
    #[error("recovery input is invalid")]
    InvalidInput,
    #[error("recovery current view is stale or missing")]
    StaleCurrent,
    #[error("recovery revision successor is invalid")]
    InvalidSuccessor,
    #[error("recovery protection failed")]
    Protection,
    #[error("recovery CAS write failed")]
    Cas,
    #[error("recovery budget was exceeded")]
    Budget,
    #[error("recovery bundle is invalid")]
    InvalidBundle,
    #[error("recovery journal command is invalid")]
    Store,
    #[error("recovery gate is inactive")]
    GateInactive,
    #[error("durable recovery pending intent is unavailable")]
    PendingUnavailable,
    #[error("durable recovery pending intent was not authoritatively admitted")]
    NotAdmitted,
    #[error("recovery spool lookup failed")]
    Spool,
    #[error("worktree mutation fence is busy")]
    FenceBusy,
    #[error("bounded recovery probe failed")]
    Probe,
    #[error("recovery capture deadline expired")]
    Deadline,
}

impl From<StoreError> for RecoveryError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

mod action;
mod application;
mod barrier;
mod bundle;
mod capture;
mod patch;

pub use action::{
    RecoveryActionOutcome, RecoveryActionService, RecoveryRequest, RecoveryUnsupportedReason,
};
pub use application::{
    RECOVERY_APPLICATION_TICKET_VERSION, RecoveryApplicationTicket,
    RecoveryApplicationTicketClaims, RecoveryTicketIssueRequest, RecoveryTicketService,
};
pub use barrier::{RecoveryBarrierLocator, RecoveryBarrierService, RecoveryTerminalAck};
pub use bundle::{capture_recovery_bundle, pending_request_command, terminal_capture_command};
