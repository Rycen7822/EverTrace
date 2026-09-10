//! The fixed native Host's direct managed MCP child is the sole process carrier.
//! Process handles and environment observations remain ephemeral, never journal facts.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Weak;
use std::time::{Duration, Instant};

const OBSERVATION_BUDGET: Duration = Duration::from_millis(250);
const OBSERVATION_BYTES: usize = 128 * 1024;
const MAX_ARGUMENTS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHostPeer {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for FileIdentity {
    fn from(value: Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            size: value.len(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}

struct ReadBudget {
    deadline: Instant,
    remaining: usize,
}

impl ReadBudget {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + OBSERVATION_BUDGET,
            remaining: OBSERVATION_BYTES,
        }
    }

    fn check(&self) -> Option<()> {
        (Instant::now() < self.deadline).then_some(())
    }

    fn read(&mut self, path: &Path) -> Option<Vec<u8>> {
        self.check()?;
        let mut bytes = Vec::new();
        File::open(path)
            .ok()?
            .take(self.remaining as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        self.remaining = self.remaining.checked_sub(bytes.len())?;
        self.check()?;
        Some(bytes)
    }
}

struct NativeProcess {
    directory: File,
    pid: u32,
    owner: (u32, u32),
    parent: u32,
    start_time: u64,
    executable: FileIdentity,
    namespaces: [PathBuf; 3],
}

impl NativeProcess {
    fn open(pid: u32, budget: &mut ReadBudget) -> Option<Self> {
        budget.check()?;
        let directory = File::open(format!("/proc/{pid}")).ok()?;
        let metadata = directory.metadata().ok()?;
        let base = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let (parent, start_time) = process_time(&budget.read(&base.join("stat"))?)?;
        let executable = File::open(base.join("exe")).ok()?.metadata().ok()?.into();
        let namespaces =
            ["pid", "user", "mnt"].map(|kind| fs::read_link(base.join("ns").join(kind)));
        let [pid_ns, user_ns, mount_ns] = namespaces;
        Some(Self {
            directory,
            pid,
            owner: (metadata.uid(), metadata.gid()),
            parent,
            start_time,
            executable,
            namespaces: [pid_ns.ok()?, user_ns.ok()?, mount_ns.ok()?],
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{name}",
            self.directory.as_raw_fd()
        ))
    }

    fn revalidate(&self, budget: &mut ReadBudget) -> Option<()> {
        // Check both the pinned directory and its current numeric locator. A
        // reused PID, exited task, changed executable or reparent is not a retry.
        let current = Self::open(self.pid, budget)?;
        let metadata = self.directory.metadata().ok()?;
        let current_metadata = current.directory.metadata().ok()?;
        if metadata.dev() != current_metadata.dev()
            || metadata.ino() != current_metadata.ino()
            || current.owner != self.owner
            || current.parent != self.parent
            || current.start_time != self.start_time
            || current.executable != self.executable
            || current.namespaces != self.namespaces
            || process_time(&budget.read(&self.path("stat"))?)? != (self.parent, self.start_time)
        {
            return None;
        }
        budget.check()
    }
}

/// Only source-affecting selections survive process inspection. Neither the
/// command line nor unrelated environment values are retained in this value.
pub(crate) struct NativeHostContext {
    connection: Weak<()>,
    child: NativeProcess,
    host: NativeProcess,
    cli_path: PathBuf,
    host_path: PathBuf,
    config_path: PathBuf,
    config_identity: FileIdentity,
    pub(crate) home: PathBuf,
    pub(crate) cwd: PathBuf,
    pub(crate) config_root: PathBuf,
    pub(crate) profile: Option<String>,
    pub(crate) selections_observed: bool,
}

impl NativeHostContext {
    pub(crate) fn observe(
        peer: NativeHostPeer,
        connection: Weak<()>,
        data_root: &Path,
    ) -> Option<Self> {
        let mut budget = ReadBudget::new();
        let child = NativeProcess::open(peer.pid, &mut budget)?;
        if child.owner != (peer.uid, peer.gid) {
            return None;
        }
        let argv = budget.read(&child.path("cmdline"))?;
        let args = arguments(&argv)?;
        let [
            _,
            "--config",
            config,
            "mcp",
            "--host-executable",
            host_locator,
            "--host-config",
            host_config,
        ] = args.as_slice()
        else {
            return None;
        };
        let config_path = absolute(host_config)?;
        let (cli_path, host_path) = evertrace_codex::install::inventory_wiring_locators(
            data_root,
            &absolute(config)?,
            &config_path,
        )
        .ok()?;
        if host_path != absolute(host_locator)? {
            return None;
        }
        let host = NativeProcess::open(child.parent, &mut budget)?;
        let own = NativeProcess::open(std::process::id(), &mut budget)?;
        if host.owner != child.owner
            || host.namespaces != child.namespaces
            || host.namespaces != own.namespaces
            || file_identity(&cli_path)? != child.executable
            || file_identity(&host_path)? != host.executable
        {
            return None;
        }
        let executable = File::open(host.path("exe")).ok()?;
        if FileIdentity::from(executable.metadata().ok()?) != host.executable
            || !evertrace_codex::probe::inventory_profile_version(
                &PathBuf::from(format!("/proc/self/fd/{}", executable.as_raw_fd())),
                budget.deadline,
            )
        {
            return None;
        }
        let config_identity = file_identity(&config_path)?;
        let cwd = fs::read_link(child.path("cwd")).ok()?;
        absolute(cwd.to_str()?)?;
        let environment = budget.read(&host.path("environ"))?;
        let home = environment_path(&environment, b"HOME=")?;
        let config_root = if environment
            .split(|byte| *byte == 0)
            .any(|entry| entry.starts_with(b"CODEX_HOME="))
        {
            environment_path(&environment, b"CODEX_HOME=")?
        } else {
            home.join(".codex")
        };
        if config_root.join("config.toml") != config_path {
            return None;
        }
        let host_arguments = budget.read(&host.path("cmdline"))?;
        let (requested_profile, mut selections_observed) =
            source_selections(&arguments(&host_arguments)?);
        let config = budget.read(&config_path)?;
        let profile = match evertrace_codex::inventory::selected_profile(
            &config,
            requested_profile.as_deref(),
        ) {
            Ok(profile) => profile,
            Err(_) => {
                selections_observed = false;
                requested_profile
            }
        };
        let result = Self {
            connection,
            child,
            host,
            cli_path,
            host_path,
            config_path,
            config_identity,
            home,
            cwd,
            config_root,
            profile,
            selections_observed,
        };
        result.revalidate_before(&mut budget)?;
        Some(result)
    }

    pub(crate) fn current(&self) -> bool {
        self.revalidate_before(&mut ReadBudget::new()).is_some()
    }

    pub(crate) fn current_before(&self, deadline: Instant) -> bool {
        let mut budget = ReadBudget::new();
        budget.deadline = budget.deadline.min(deadline);
        self.revalidate_before(&mut budget).is_some()
    }

    fn revalidate_before(&self, budget: &mut ReadBudget) -> Option<()> {
        let _connection = self.connection.upgrade()?;
        self.child.revalidate(budget)?;
        self.host.revalidate(budget)?;
        if file_identity(&self.cli_path)? != self.child.executable
            || file_identity(&self.host_path)? != self.host.executable
            || file_identity(&self.config_path)? != self.config_identity
            || fs::read_link(self.child.path("cwd")).ok()? != self.cwd
        {
            return None;
        }
        budget.check()
    }
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let file = File::open(path).ok()?;
    let opened: FileIdentity = file.metadata().ok()?.into();
    (opened == metadata.into()).then_some(opened)
}

fn process_time(bytes: &[u8]) -> Option<(u32, u64)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let fields = text
        .get(text.rfind(')')? + 2..)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    Some((fields.get(1)?.parse().ok()?, fields.get(19)?.parse().ok()?))
}

fn arguments(bytes: &[u8]) -> Option<Vec<&str>> {
    if bytes.last() != Some(&0) {
        return None;
    }
    let args = bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (args.len() <= MAX_ARGUMENTS).then_some(args)
}

fn absolute(value: &str) -> Option<PathBuf> {
    evertrace_codex::binding::valid_lexical_absolute_path(value).then(|| PathBuf::from(value))
}

impl PartialEq for NativeHostContext {
    fn eq(&self, other: &Self) -> bool {
        self.connection.ptr_eq(&other.connection)
            && self.child.pid == other.child.pid
            && self.child.start_time == other.child.start_time
            && self.host.pid == other.host.pid
            && self.host.start_time == other.host.start_time
            && self.config_identity == other.config_identity
            && self.home == other.home
            && self.config_root == other.config_root
            && self.cwd == other.cwd
            && self.profile == other.profile
            && self.selections_observed == other.selections_observed
    }
}

impl Eq for NativeHostContext {}

fn environment_path(bytes: &[u8], key: &[u8]) -> Option<PathBuf> {
    let mut values = bytes
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.strip_prefix(key));
    let path = absolute(std::str::from_utf8(values.next()?).ok()?)?;
    values.next().is_none().then_some(path)
}

fn source_selections(args: &[&str]) -> (Option<String>, bool) {
    let mut profile = None;
    let mut observed = true;
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        match *arg {
            "-p" | "--profile" => match args.next() {
                Some(value) if !value.is_empty() && value.len() <= 128 && profile.is_none() => {
                    profile = Some((*value).to_owned());
                    // The pinned CLI selects <name>.config.toml, not the
                    // legacy [profiles.<name>] table. An unobserved layer
                    // cannot certify the base config's asset selections.
                    observed = false;
                }
                _ => observed = false,
            },
            "-c" | "--config" | "--enable" | "--disable" => {
                observed = false;
                let _ = args.next();
            }
            "--ignore-user-config" => observed = false,
            value
                if value.starts_with("--profile")
                    || value.starts_with("--config")
                    || value.starts_with("--enable=")
                    || value.starts_with("--disable=")
                    || (value.starts_with("-c") || value.starts_with("-p")) && value.len() > 2 =>
            {
                observed = false
            }
            _ => {}
        }
    }
    (profile, observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_process_is_pinned_and_plain_peer_is_not_a_managed_host() {
        let mut budget = ReadBudget::new();
        let process = NativeProcess::open(std::process::id(), &mut budget).unwrap();
        assert!(process.revalidate(&mut budget).is_some());
        let connection = std::sync::Arc::new(());
        let peer = NativeHostPeer {
            pid: process.pid,
            uid: process.owner.0,
            gid: process.owner.1,
        };
        assert!(
            NativeHostContext::observe(
                peer,
                std::sync::Arc::downgrade(&connection),
                Path::new("/not-an-installation")
            )
            .is_none()
        );
    }

    #[test]
    fn native_source_selectors_do_not_copy_prompt_or_secret_overrides() {
        let args = ["/native", "exec", "--profile", "work", "private prompt"];
        assert_eq!(source_selections(&args), (Some("work".into()), false));
        assert_eq!(
            source_selections(&["/native", "exec", "ordinary prompt"]),
            (None, true)
        );
        assert_eq!(
            source_selections(&["/native", "exec", "--ignore-user-config"]),
            (None, false)
        );
        assert_eq!(
            source_selections(&["/native", "-c", "api_key=private"]),
            (None, false)
        );
        assert_eq!(source_selections(&["/native", "-pother"]), (None, false));
        assert_eq!(
            source_selections(&["/native", "--profile-v2", "other"]),
            (None, false)
        );
        assert!(arguments(&[0; MAX_ARGUMENTS + 2]).is_none());
        assert!(environment_path(b"HOME=/a\0HOME=/b\0", b"HOME=").is_none());
        assert_eq!(
            environment_path(b"SECRET=private\0HOME=/actual\0", b"HOME="),
            Some(PathBuf::from("/actual"))
        );
    }
}
