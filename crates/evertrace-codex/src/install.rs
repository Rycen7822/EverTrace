use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability::HookDiagnostic;

const REGISTRY_VERSION: u16 = 1;
const REGISTRY_NAME: &str = "registry-v1.json";
const HOOKS_DIRECTORY: &str = "hooks";
const GENERATIONS_DIRECTORY: &str = "generations";
const PINS_DIRECTORY: &str = "pins";
const REGISTRY_LOCK_NAME: &str = "registry.lock";
const GENERATION_EXECUTABLE_NAME: &str = "evertrace-hook";
const GENERATION_RUNTIME_NAME: &str = "hook-runtime-v1.json";
const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;
const MAX_PIN_BYTES: u64 = 64;

const MAX_HOOK_SNAPSHOT_FILES: usize = 4096;

pub const fn shadow_canary_diagnostic(durable_frame_observed: bool) -> Option<HookDiagnostic> {
    if durable_frame_observed {
        None
    } else {
        Some(HookDiagnostic::WiredUnobserved)
    }
}

/// Explicit local paths supplied by the offline CLI, never discovered from PATH.
pub struct ManagedInstallPaths {
    pub data_root: PathBuf,
    pub host_config: PathBuf,
    pub unit: PathBuf,
    pub config: PathBuf,
    pub cli: PathBuf,
    pub hook: PathBuf,
    pub daemon: PathBuf,
    pub systemctl: PathBuf,
    pub host_executable: PathBuf,
}

#[derive(Debug)]
pub struct ManagedInstallResult {
    pub service_available: bool,
    pub backups: Vec<PathBuf>,
    pub manual_command: String,
    pub host_hooks_enabled: Option<bool>,
}

#[derive(Debug, Error)]
#[error("managed installation failed during {stage}: {cause}; preserved paths: {preserved:?}")]
pub struct ManagedInstallError {
    pub stage: &'static str,
    pub cause: InstallError,
    pub preserved: Vec<PathBuf>,
}

const OWNED_BEGIN: &str = "# BEGIN EverTrace managed wiring v1\n";
const OWNED_END: &str = "# END EverTrace managed wiring v1\n";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

fn install_nonce() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

struct InstallFile {
    path: PathBuf,
    parent: File,
    original: Option<(HookFileIdentity, Vec<u8>)>,
    published: Option<HookFileIdentity>,
    desired: Option<Vec<u8>>,
    backup: Option<PathBuf>,
    backup_identity: Option<HookFileIdentity>,
    temporary: Option<PathBuf>,
    changed: bool,
}

impl InstallFile {
    fn read(path: &Path) -> Result<Self, InstallError> {
        let parent_path = path.parent().ok_or(InstallError::InvalidType)?;
        for ancestor in parent_path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor).map_err(map_io)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(InstallError::InvalidType);
            }
        }
        let parent = File::open(parent_path).map_err(map_io)?;
        let metadata = parent.metadata().map_err(map_io)?;
        if metadata.uid() != current_uid()? || metadata.mode() & 0o022 != 0 {
            return Err(InstallError::InvalidPermissions);
        }
        let original = match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != current_uid()?
                    || metadata.mode() & 0o022 != 0
                    || metadata.len() > MAX_CONFIG_BYTES
                {
                    return Err(InstallError::InvalidType);
                }
                let bytes = fs::read(path).map_err(map_io)?;
                let identity = hook_file_identity(&metadata);
                if hook_file_identity(&fs::symlink_metadata(path).map_err(map_io)?) != identity
                    || bytes.len() as u64 != metadata.len()
                {
                    return Err(InstallError::InvalidType);
                }
                Some((identity, bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(map_io(error)),
        };
        Ok(Self {
            path: path.to_owned(),
            parent,
            original,
            published: None,
            desired: None,
            backup: None,
            backup_identity: None,
            temporary: None,
            changed: false,
        })
    }

    fn revalidate(&self, expected: Option<&HookFileIdentity>) -> Result<(), InstallError> {
        let current_parent =
            fs::symlink_metadata(self.path.parent().ok_or(InstallError::InvalidType)?)
                .map_err(map_io)?;
        let held = self.parent.metadata().map_err(map_io)?;
        if !current_parent.is_dir()
            || current_parent.file_type().is_symlink()
            || (held.dev(), held.ino()) != (current_parent.dev(), current_parent.ino())
        {
            return Err(InstallError::InvalidType);
        }
        match (fs::symlink_metadata(&self.path), expected) {
            (Ok(metadata), Some(expected))
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && hook_file_identity(&metadata) == *expected =>
            {
                Ok(())
            }
            (Err(error), None) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(InstallError::InvalidType),
        }
    }

    fn publish(&mut self) -> Result<(), InstallError> {
        self.revalidate(self.original.as_ref().map(|(id, _)| id))?;
        if self.original.as_ref().map(|(_, bytes)| bytes) == self.desired.as_ref() {
            return Ok(());
        }
        if let Some((_, bytes)) = &self.original {
            let backup = self
                .path
                .with_file_name(format!(".evertrace-backup-{}", install_nonce()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&backup)
                .map_err(map_io)?;
            self.backup = Some(backup);
            file.write_all(bytes).map_err(map_io)?;
            file.sync_all().map_err(map_io)?;
            self.backup_identity = Some(hook_file_identity(&file.metadata().map_err(map_io)?));
            self.parent.sync_all().map_err(map_io)?;
        }
        self.revalidate(self.original.as_ref().map(|(id, _)| id))?;
        if let Some(bytes) = self.desired.clone() {
            // Keep the staging handle: a rename-success/post-sync failure must
            // still retain the exact published identity for conditional rollback.
            let temporary = self
                .path
                .with_file_name(format!(".evertrace-install-{}", install_nonce()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(map_io)?;
            self.temporary = Some(temporary.clone());
            let result = (|| {
                file.write_all(&bytes).map_err(map_io)?;
                file.sync_all().map_err(map_io)?;
                self.revalidate(self.original.as_ref().map(|(id, _)| id))?;
                fs::rename(&temporary, &self.path).map_err(map_io)?;
                self.changed = true;
                self.temporary = None;
                self.published = Some(hook_file_identity(&file.metadata().map_err(map_io)?));
                self.parent.sync_all().map_err(map_io)
            })();
            if self.temporary.is_some()
                && file
                    .metadata()
                    .ok()
                    .zip(fs::symlink_metadata(&temporary).ok())
                    .is_some_and(|(held, actual)| {
                        actual.is_file()
                            && !actual.file_type().is_symlink()
                            && hook_file_identity(&held) == hook_file_identity(&actual)
                    })
                && fs::remove_file(&temporary).is_ok()
            {
                self.temporary = None;
            }
            result
        } else {
            fs::remove_file(&self.path).map_err(map_io)?;
            self.changed = true;
            self.parent.sync_all().map_err(map_io)
        }
    }

    fn rollback(&self) -> Result<(), InstallError> {
        if self.original.as_ref().map(|(_, bytes)| bytes) == self.desired.as_ref() {
            return self.revalidate(self.original.as_ref().map(|(id, _)| id));
        }
        if !self.changed {
            return self.revalidate(self.original.as_ref().map(|(id, _)| id));
        }
        self.revalidate(self.published.as_ref())?;
        if let Some((_, original)) = &self.original {
            let backup = self.backup.as_ref().ok_or(InstallError::Io)?;
            if Some(private_file_identity(backup, 0o600)?) != self.backup_identity {
                return Err(InstallError::InvalidType);
            }
            if fs::read(backup).map_err(map_io)? != *original {
                return Err(InstallError::InvalidType);
            }
            fs::rename(backup, &self.path).map_err(map_io)?;
        } else if self.published.is_some() {
            fs::remove_file(&self.path).map_err(map_io)?;
        }
        self.parent.sync_all().map_err(map_io)
    }
}

fn shell_path(path: &Path) -> Result<String, InstallError> {
    let text = path.to_str().ok_or(InstallError::InvalidType)?;
    if !path.is_absolute() || text.chars().any(char::is_control) {
        return Err(InstallError::InvalidType);
    }
    Ok(format!("'{}'", text.replace('\'', "'\\''")))
}

fn wiring(data_root: &Path, cli: &Path, config: &Path) -> Result<Vec<u8>, InstallError> {
    let command = format!(
        "{} --launcher-root {}",
        shell_path(&data_root.join("hook-v1"))?,
        shell_path(data_root)?
    );
    let mut mcp: toml::Value = toml::from_str(include_str!(
        "../../../packaging/codex/mcp.v1.template.toml"
    ))
    .map_err(|_| InstallError::InvalidType)?;
    mcp["mcp_servers"]["evertrace"]["command"] =
        toml::Value::String(cli.to_str().ok_or(InstallError::InvalidType)?.into());
    mcp["mcp_servers"]["evertrace"]["args"][1] =
        toml::Value::String(config.to_str().ok_or(InstallError::InvalidType)?.into());
    let mut hooks: serde_json::Value = serde_json::from_str(include_str!(
        "../../../packaging/codex/hooks.v1.template.json"
    ))
    .map_err(|_| InstallError::InvalidType)?;
    for event in ["PreToolUse", "PostToolUse", "UserPromptSubmit"] {
        hooks["hooks"][event][0]["hooks"][0]["command"] = command.clone().into();
    }
    mcp.as_table_mut().ok_or(InstallError::InvalidType)?.insert(
        "hooks".into(),
        toml::Value::try_from(&hooks["hooks"]).map_err(|_| InstallError::InvalidType)?,
    );
    Ok(format!(
        "{OWNED_BEGIN}{}{OWNED_END}",
        toml::to_string(&mcp).map_err(|_| InstallError::InvalidType)?
    )
    .into_bytes())
}

fn wiring_markers(
    text: &str,
) -> Result<(std::ops::Range<usize>, std::ops::Range<usize>), InstallError> {
    let start = text.find(OWNED_BEGIN).ok_or(InstallError::InvalidType)?;
    let end = text[start..]
        .find(OWNED_END)
        .map(|end| start + end + OWNED_END.len())
        .ok_or(InstallError::InvalidType)?;
    if text[..start].contains(OWNED_END)
        || text[start + OWNED_BEGIN.len()..end].contains(OWNED_BEGIN)
        || text[end..].contains(OWNED_BEGIN)
        || text[end..].contains(OWNED_END)
    {
        return Err(InstallError::InvalidType);
    }
    Ok((start..start + OWNED_BEGIN.len(), end - OWNED_END.len()..end))
}

type LocatedFields = BTreeMap<toml::Spanned<String>, toml::Spanned<toml::Value>>;

#[derive(Deserialize)]
struct WiringLocations {
    hooks: HookLocations,
    mcp_servers: BTreeMap<String, toml::Spanned<LocatedFields>>,
}

#[derive(Default, Deserialize)]
struct HookLocations {
    #[serde(default, rename = "PreToolUse")]
    pre: Vec<toml::Spanned<LocatedHook>>,
    #[serde(default, rename = "PostToolUse")]
    post: Vec<toml::Spanned<LocatedHook>>,
    #[serde(default, rename = "UserPromptSubmit")]
    submit: Vec<toml::Spanned<LocatedHook>>,
}

#[derive(Deserialize)]
struct LocatedHook {
    matcher: Option<toml::Spanned<String>>,
    hooks: Vec<toml::Spanned<LocatedFields>>,
}

struct WiringDeclarations {
    canonical: Vec<u8>,
    unowned: toml::Value,
    // Values can change in place without moving arrays or Host state.
    values: BTreeMap<String, (std::ops::Range<usize>, toml::Value)>,
    removals: Vec<std::ops::Range<usize>>,
    end: usize,
}

fn validate_mcp_approval_state(value: &toml::Value) -> Result<(), InstallError> {
    let tools = value.as_table().ok_or(InstallError::InvalidType)?;
    let tool = tools
        .get("evertrace")
        .and_then(toml::Value::as_table)
        .ok_or(InstallError::InvalidType)?;
    if tools.len() != 1
        || tool.len() != 1
        || tool
            .get("approval_mode")
            .and_then(toml::Value::as_str)
            .is_none()
    {
        return Err(InstallError::InvalidType);
    }
    Ok(())
}

fn trim_empty_wiring_tables(value: &mut toml::Value) {
    if let Some(servers) = value
        .get_mut("mcp_servers")
        .and_then(toml::Value::as_table_mut)
        && servers
            .get("evertrace")
            .and_then(toml::Value::as_table)
            .is_some_and(|v| v.is_empty())
    {
        servers.remove("evertrace");
    }
    for key in ["hooks", "mcp_servers"] {
        if value
            .get(key)
            .and_then(toml::Value::as_table)
            .is_some_and(|v| v.is_empty())
        {
            value.as_table_mut().expect("TOML document").remove(key);
        }
    }
}

fn wiring_declarations(bytes: &[u8]) -> Result<WiringDeclarations, InstallError> {
    let text = std::str::from_utf8(bytes).map_err(|_| InstallError::InvalidType)?;
    let (begin, end) = wiring_markers(text)?;
    let within = |span: &std::ops::Range<usize>| span.start >= begin.end && span.end <= end.start;
    let locations: WiringLocations = toml::from_str(text).map_err(|_| InstallError::InvalidType)?;
    let mut unowned: toml::Value = toml::from_str(text).map_err(|_| InstallError::InvalidType)?;
    let mut projected = toml::Table::new();
    let mut hooks = toml::Table::new();
    let mut values = BTreeMap::new();
    let mut removals = vec![begin.clone(), end.clone()];
    for (event, entries) in [
        ("PreToolUse", locations.hooks.pre),
        ("PostToolUse", locations.hooks.post),
        ("UserPromptSubmit", locations.hooks.submit),
    ] {
        let selected: Vec<_> = entries
            .iter()
            .enumerate()
            .filter(|(_, item)| within(&item.span()))
            .collect();
        if selected.is_empty() && event == "UserPromptSubmit" {
            continue;
        }
        let [(index, entry)] = selected.as_slice() else {
            return Err(InstallError::InvalidType);
        };
        let actual = unowned["hooks"][event]
            .as_array_mut()
            .ok_or(InstallError::InvalidType)?
            .remove(*index);
        if unowned["hooks"][event]
            .as_array()
            .is_some_and(|v| v.is_empty())
        {
            unowned["hooks"]
                .as_table_mut()
                .ok_or(InstallError::InvalidType)?
                .remove(event);
        }
        hooks.insert(event.into(), toml::Value::Array(vec![actual]));
        removals.push(entry.span());
        if let Some(matcher) = &entry.get_ref().matcher {
            let span = matcher.span();
            let start = text[..span.start].rfind('\n').map_or(0, |i| i + 1);
            if text[start..span.start].trim() != "matcher =" {
                return Err(InstallError::InvalidType);
            }
            removals.push(start..span.end);
            values.insert(
                format!("{event}.matcher"),
                (span, toml::Value::String(matcher.get_ref().clone())),
            );
        }
        let [command] = entry.get_ref().hooks.as_slice() else {
            return Err(InstallError::InvalidType);
        };
        removals.push(command.span());
        for (key, value) in command.get_ref() {
            removals.push(key.span().start..value.span().end);
            values.insert(
                format!("{event}.{}", key.get_ref()),
                (value.span(), value.get_ref().clone()),
            );
        }
    }
    projected.insert("hooks".into(), toml::Value::Table(hooks));
    let server = locations
        .mcp_servers
        .get("evertrace")
        .ok_or(InstallError::InvalidType)?;
    if !within(&server.span()) {
        return Err(InstallError::InvalidType);
    }
    removals.push(server.span());
    let mut mcp = toml::Table::new();
    for (key, value) in server.get_ref() {
        if key.get_ref() == "tools" {
            validate_mcp_approval_state(value.get_ref())?;
            continue;
        }
        if !["command", "args", "enabled_tools"].contains(&key.get_ref().as_str()) {
            return Err(InstallError::InvalidType);
        }
        mcp.insert(key.get_ref().clone(), value.get_ref().clone());
        removals.push(key.span().start..value.span().end);
        values.insert(
            format!("mcp.{}", key.get_ref()),
            (value.span(), value.get_ref().clone()),
        );
        unowned["mcp_servers"]["evertrace"]
            .as_table_mut()
            .ok_or(InstallError::InvalidType)?
            .remove(key.get_ref());
    }
    projected.insert(
        "mcp_servers".into(),
        toml::Value::Table(toml::Table::from_iter([(
            "evertrace".into(),
            toml::Value::Table(mcp),
        )])),
    );
    if removals.iter().skip(2).any(|span| !within(span)) {
        return Err(InstallError::InvalidType);
    }
    trim_empty_wiring_tables(&mut unowned);
    let canonical = format!(
        "{OWNED_BEGIN}{}{OWNED_END}",
        toml::to_string(&projected).map_err(|_| InstallError::InvalidType)?
    )
    .into_bytes();
    Ok(WiringDeclarations {
        canonical,
        unowned,
        values,
        removals,
        end: end.start,
    })
}

fn owned_wiring(bytes: &[u8]) -> Result<Vec<u8>, InstallError> {
    Ok(wiring_declarations(bytes)?.canonical)
}

fn merge_wiring(original: &[u8], owned: &[u8], uninstall: bool) -> Result<Vec<u8>, InstallError> {
    replace_wiring(original, owned, (!uninstall).then_some(owned))
}

fn replace_wiring(
    original: &[u8],
    expected: &[u8],
    replacement: Option<&[u8]>,
) -> Result<Vec<u8>, InstallError> {
    let text = std::str::from_utf8(original).map_err(|_| InstallError::InvalidType)?;
    let mut parsed: toml::Value = toml::from_str(text).map_err(|_| InstallError::InvalidType)?;
    let expected = wiring_declarations(expected)?;
    let mut edits = Vec::new();
    let unowned;
    if text.contains(OWNED_BEGIN) {
        let actual = wiring_declarations(original)?;
        let old = previous_tool_wiring(
            std::str::from_utf8(&expected.canonical).map_err(|_| InstallError::InvalidType)?,
        )?;
        if actual.canonical != expected.canonical && actual.canonical != old.as_bytes() {
            return Err(InstallError::InvalidType);
        }
        unowned = actual.unowned;
        if let Some(replacement) = replacement {
            let target = wiring_declarations(replacement)?;
            for (key, (range, value)) in &actual.values {
                let (_, desired) = target.values.get(key).ok_or(InstallError::InvalidType)?;
                if value != desired {
                    edits.push((range.clone(), desired.to_string()));
                }
            }
            if !actual.values.contains_key("UserPromptSubmit.command") {
                let value: toml::Value = toml::from_str(
                    std::str::from_utf8(&target.canonical)
                        .map_err(|_| InstallError::InvalidType)?,
                )
                .map_err(|_| InstallError::InvalidType)?;
                let mut extra = toml::Table::new();
                extra.insert(
                    "hooks".into(),
                    toml::Value::Table(toml::Table::from_iter([(
                        "UserPromptSubmit".into(),
                        value["hooks"]["UserPromptSubmit"].clone(),
                    )])),
                );
                edits.push((
                    actual.end..actual.end,
                    toml::to_string(&extra).map_err(|_| InstallError::InvalidType)?,
                ));
            }
        } else {
            edits.extend(
                actual
                    .removals
                    .into_iter()
                    .map(|range| (range, String::new())),
            );
        }
    } else {
        if text.contains(OWNED_END) {
            return Err(InstallError::InvalidType);
        }
        if let Some(server) = parsed.get("mcp_servers").and_then(|v| v.get("evertrace")) {
            let table = server.as_table().ok_or(InstallError::InvalidType)?;
            if table.len() != 1 {
                return Err(InstallError::InvalidType);
            }
            validate_mcp_approval_state(table.get("tools").ok_or(InstallError::InvalidType)?)?;
        }
        trim_empty_wiring_tables(&mut parsed);
        unowned = parsed;
        if let Some(replacement) = replacement {
            edits.push((
                text.len()..text.len(),
                format!(
                    "\n{}",
                    std::str::from_utf8(replacement).map_err(|_| InstallError::InvalidType)?
                ),
            ));
        }
    }
    edits.sort_by_key(|(span, _)| span.start);
    if edits.windows(2).any(|pair| pair[0].0.end > pair[1].0.start) {
        return Err(InstallError::InvalidType);
    }
    let mut result = text.to_owned();
    for (span, replacement) in edits.into_iter().rev() {
        result.replace_range(span, &replacement);
    }
    if result.len() as u64 > MAX_CONFIG_BYTES {
        return Err(InstallError::ResourceExhausted);
    }
    let remaining = if let Some(replacement) = replacement {
        let after = wiring_declarations(result.as_bytes())?;
        if after.canonical != owned_wiring(replacement)? {
            return Err(InstallError::InvalidType);
        }
        after.unowned
    } else {
        let mut after: toml::Value =
            toml::from_str(&result).map_err(|_| InstallError::InvalidType)?;
        trim_empty_wiring_tables(&mut after);
        after
    };
    if remaining != unowned {
        return Err(InstallError::InvalidType);
    }
    Ok(result.into_bytes())
}

// The predecessor declaration set emitted before submission coverage. This is
// only a write/uninstall compatibility check, not current coverage or permission
// to accept changed execution fields.
fn previous_tool_wiring(owned: &str) -> Result<String, InstallError> {
    let body = owned
        .strip_prefix(OWNED_BEGIN)
        .and_then(|value| value.strip_suffix(OWNED_END))
        .ok_or(InstallError::InvalidType)?;
    let mut value: toml::Value = toml::from_str(body).map_err(|_| InstallError::InvalidType)?;
    value
        .get_mut("hooks")
        .and_then(toml::Value::as_table_mut)
        .ok_or(InstallError::InvalidType)?
        .remove("UserPromptSubmit")
        .ok_or(InstallError::InvalidType)?;
    Ok(format!(
        "{OWNED_BEGIN}{}{OWNED_END}",
        toml::to_string(&value).map_err(|_| InstallError::InvalidType)?
    ))
}

/// Read-only canary preflight uses exactly the installer-owned fragment, not a
/// second interpretation of host wiring or an existence-based activation claim.
pub fn validate_installed_wiring(
    data_root: &Path,
    config: &Path,
    host_config: &Path,
) -> Result<PathBuf, InstallError> {
    validated_installed_wiring(data_root, config, host_config).map(|(cli, _)| cli)
}

/// Digest only normalized verified declarations, never Host state or user TOML.
pub fn installed_wiring_hash(
    data_root: &Path,
    config: &Path,
    host_config: &Path,
) -> Result<(PathBuf, String), InstallError> {
    use sha2::{Digest, Sha256};
    let (cli, file) = validated_installed_wiring(data_root, config, host_config)?;
    let (_, bytes) = file.original.as_ref().ok_or(InstallError::InvalidType)?;
    Ok((cli, format!("{:x}", Sha256::digest(owned_wiring(bytes)?))))
}

fn validated_installed_wiring(
    data_root: &Path,
    config: &Path,
    host_config: &Path,
) -> Result<(PathBuf, InstallFile), InstallError> {
    let file = InstallFile::read(host_config)?;
    let (_, bytes) = file.original.as_ref().ok_or(InstallError::InvalidType)?;
    let text = std::str::from_utf8(bytes).map_err(|_| InstallError::InvalidType)?;
    if !text.contains(OWNED_BEGIN) {
        return Err(InstallError::InvalidType);
    }
    let parsed: toml::Value = toml::from_str(text).map_err(|_| InstallError::InvalidType)?;
    let cli = parsed
        .get("mcp_servers")
        .and_then(|value| value.get("evertrace"))
        .and_then(|value| value.get("command"))
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
        .ok_or(InstallError::InvalidType)?;
    package_metadata(&cli)?;
    if merge_wiring(bytes, &wiring(data_root, &cli, config)?, false)? != *bytes {
        return Err(InstallError::InvalidType);
    }
    file.revalidate(file.original.as_ref().map(|(identity, _)| identity))?;
    Ok((cli, file))
}

fn ensure_install_parent(path: &Path) -> Result<(), InstallError> {
    let mut missing = Vec::new();
    for parent in path.ancestors() {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => break,
            Ok(_) => return Err(InstallError::InvalidType),
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(parent),
            Err(error) => return Err(map_io(error)),
        }
    }
    for directory in missing.into_iter().rev() {
        DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(map_io)?;
    }
    Ok(())
}

fn package_metadata(path: &Path) -> Result<fs::Metadata, InstallError> {
    for parent in path.parent().ok_or(InstallError::InvalidType)?.ancestors() {
        let metadata = fs::symlink_metadata(parent).map_err(map_io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(InstallError::InvalidType);
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || ![0, current_uid()?].contains(&metadata.uid())
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(InstallError::InvalidType);
    }
    let parent = fs::metadata(path.parent().ok_or(InstallError::InvalidType)?).map_err(map_io)?;
    if ![0, current_uid()?].contains(&parent.uid()) || parent.mode() & 0o022 != 0 {
        return Err(InstallError::InvalidPermissions);
    }
    Ok(metadata)
}

fn package_bytes(path: &Path) -> Result<Vec<u8>, InstallError> {
    let metadata = package_metadata(path)?;
    if metadata.len() > 256 * 1024 * 1024 {
        return Err(InstallError::ResourceExhausted);
    }
    let mut file = File::open(path).map_err(map_io)?;
    let identity = hook_file_identity(&metadata);
    if hook_file_identity(&file.metadata().map_err(map_io)?) != identity {
        return Err(InstallError::InvalidType);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() as u64 != metadata.len()
        || hook_file_identity(&file.metadata().map_err(map_io)?) != identity
        || hook_file_identity(&fs::symlink_metadata(path).map_err(map_io)?) != identity
    {
        return Err(InstallError::InvalidType);
    }
    Ok(bytes)
}

fn unit_bytes(daemon: &Path, config: &Path) -> Result<Vec<u8>, InstallError> {
    let quote = |path: &Path| -> Result<String, InstallError> {
        let value = path.to_str().ok_or(InstallError::InvalidType)?;
        if !path.is_absolute() || value.chars().any(char::is_control) {
            return Err(InstallError::InvalidType);
        }
        Ok(format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('%', "%%")
                .replace('$', "$$")
        ))
    };
    Ok(
        include_str!("../../../packaging/systemd/evertraced.service.in")
            .replace("@DAEMON@", &quote(daemon)?)
            .replace("@CONFIG@", &quote(config)?)
            .into_bytes(),
    )
}

/// Fixed systemctl operations, bounded output and wall time. Nonblocking socket
/// output avoids waiting on a descendant that inherited a pipe after timeout.
pub(crate) fn bounded_install_command(
    executable: &Path,
    arguments: &[&str],
    host_home: Option<&Path>,
) -> Result<(i32, String), InstallError> {
    use std::{
        os::fd::OwnedFd,
        os::unix::net::UnixStream,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let (mut reader, output) = UnixStream::pair().map_err(map_io)?;
    reader.set_nonblocking(true).map_err(map_io)?;
    let descriptor: OwnedFd = output.into();
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(descriptor))
        .stderr(Stdio::null());
    if let Some(home) = host_home {
        command.env("CODEX_HOME", home);
    }
    let mut child = command.spawn().map_err(map_io)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        match reader.read(&mut buffer) {
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(InstallError::Io);
            }
        }
        if bytes.len() > 16 * 1024 || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(InstallError::ResourceExhausted);
        }
        if let Some(status) = child.try_wait().map_err(map_io)? {
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        bytes.extend_from_slice(&buffer[..count]);
                        if bytes.len() > 16 * 1024 {
                            return Err(InstallError::ResourceExhausted);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => return Err(InstallError::Io),
                }
            }
            return Ok((
                status.code().unwrap_or(-1),
                String::from_utf8(bytes).map_err(|_| InstallError::InvalidType)?,
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn user_service(executable: &Path, arguments: &[&str]) -> Result<(i32, String), InstallError> {
    let mut args = vec!["--user"];
    args.extend_from_slice(arguments);
    bounded_install_command(executable, &args, None)
}

fn require_service(executable: &Path, arguments: &[&str]) -> Result<(), InstallError> {
    match user_service(executable, arguments)?.0 {
        0 => Ok(()),
        code => Err(InstallError::ServiceExit(code)),
    }
}

pub fn managed_install(
    paths: &ManagedInstallPaths,
    config_bytes: &[u8],
    uninstall: bool,
    prepare_runtime: impl FnOnce(u64, &Path) -> Result<(), InstallError>,
) -> Result<ManagedInstallResult, ManagedInstallError> {
    let mut edits: Vec<InstallFile> = Vec::new();
    let mut new_assets: Vec<PathBuf> = Vec::new();
    let mut new_files = Vec::new();
    let mut new_directory = None;
    let mut service_started = false;
    let mut service_attempted = false;
    let mut previous_service = None;
    let mut stage = "host probe";
    let result = (|| {
        if paths.unit.file_name().and_then(|name| name.to_str()) != Some("evertraced.service") {
            return Err(InstallError::InvalidType);
        }
        let host_hooks_enabled = if uninstall {
            None
        } else {
            package_metadata(&paths.host_executable)?;
            Some(
                crate::probe::probe_install_host(
                    &paths.host_executable,
                    paths
                        .host_config
                        .parent()
                        .ok_or(InstallError::InvalidType)?,
                )?
                .hooks_enabled,
            )
        };
        for path in [&paths.host_config, &paths.unit, &paths.config] {
            ensure_install_parent(path.parent().ok_or(InstallError::InvalidType)?)?;
        }
        stage = "host wiring";
        let mut host = InstallFile::read(&paths.host_config)?;
        let original_host = host
            .original
            .as_ref()
            .map_or(&[][..], |(_, bytes)| bytes.as_slice());
        let merged = merge_wiring(
            original_host,
            &wiring(&paths.data_root, &paths.cli, &paths.config)?,
            uninstall,
        )?;
        host.desired = if host.original.is_none() && uninstall {
            None
        } else {
            Some(merged)
        };
        stage = "unit ownership";
        let mut unit = InstallFile::read(&paths.unit)?;
        let expected_unit = unit_bytes(&paths.daemon, &paths.config)?;
        if unit
            .original
            .as_ref()
            .is_some_and(|(_, original)| *original != expected_unit)
        {
            return Err(InstallError::InvalidType);
        }
        let unit_exists = unit.original.is_some();
        unit.desired = (!uninstall).then_some(expected_unit);
        let mut config = InstallFile::read(&paths.config)?;
        if let Some((_, bytes)) = &config.original
            && bytes != config_bytes
        {
            return Err(InstallError::InvalidType);
        }
        config.desired = config
            .original
            .as_ref()
            .map(|(_, bytes)| bytes.clone())
            .or_else(|| (!uninstall).then(|| config_bytes.to_vec()));
        edits.extend([config, host, unit]);
        stage = "service probe";
        let service_available = match fs::symlink_metadata(&paths.systemctl) {
            Ok(_) => {
                package_metadata(&paths.systemctl)?;
                let (success, fragment) = user_service(
                    &paths.systemctl,
                    &[
                        "show",
                        "evertraced.service",
                        "--property=FragmentPath",
                        "--value",
                    ],
                )?;
                if success == 0
                    && !fragment.trim().is_empty()
                    && (!unit_exists
                        || fragment.trim()
                            != paths.unit.to_str().ok_or(InstallError::InvalidType)?)
                {
                    return Err(InstallError::InvalidType);
                }
                if success == 0 && unit_exists {
                    let enabled =
                        user_service(&paths.systemctl, &["is-enabled", "evertraced.service"])?;
                    let active =
                        user_service(&paths.systemctl, &["is-active", "evertraced.service"])?;
                    if !matches!(enabled.1.trim(), "enabled" | "disabled")
                        || !matches!(active.1.trim(), "active" | "inactive" | "failed")
                    {
                        return Err(InstallError::InvalidType);
                    }
                    previous_service =
                        Some((enabled.1.trim() == "enabled", active.1.trim() == "active"));
                }
                success == 0
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(map_io(error)),
        };
        if !uninstall {
            stage = "package assets";
            package_metadata(&paths.cli)?;
            package_metadata(&paths.daemon)?;
            let bytes = package_bytes(&paths.hook)?;
            ensure_install_parent(&paths.data_root)?;
            let launcher = StableLauncher::open(&paths.data_root)?;
            if launcher.registry_path().try_exists().map_err(map_io)? {
                let registry = launcher.with_lock(|| launcher.read_registry())?;
                let current = registry
                    .generations
                    .iter()
                    .find(|item| item.generation == registry.current_generation)
                    .ok_or(InstallError::InvalidRegistry)?;
                if package_bytes(&current.executable)? != bytes
                    || package_bytes(&launcher.launcher_path())? != bytes
                {
                    return Err(InstallError::GenerationUnavailable);
                }
            } else {
                if launcher.launcher_path().try_exists().map_err(map_io)? {
                    return Err(InstallError::InvalidType);
                }
                let directory = paths
                    .data_root
                    .join(generation_relative(1, GENERATION_EXECUTABLE_NAME))
                    .parent()
                    .ok_or(InstallError::InvalidType)?
                    .to_owned();
                DirBuilder::new()
                    .mode(0o700)
                    .create(&directory)
                    .map_err(map_io)?;
                new_directory = Some((directory.clone(), File::open(&directory).map_err(map_io)?));
                new_assets.push(directory.clone());
                stage = "runtime preparation";
                let runtime = directory.join(GENERATION_RUNTIME_NAME);
                prepare_runtime(1, &runtime)?;
                new_files.push((runtime.clone(), private_file_identity(&runtime, 0o600)?));
                atomic_write(&directory.join(GENERATION_EXECUTABLE_NAME), &bytes, 0o700)?;
                new_files.push((
                    directory.join(GENERATION_EXECUTABLE_NAME),
                    private_file_identity(&directory.join(GENERATION_EXECUTABLE_NAME), 0o700)?,
                ));
                atomic_write(&launcher.launcher_path(), &bytes, 0o700)?;
                new_files.push((
                    launcher.launcher_path(),
                    private_file_identity(&launcher.launcher_path(), 0o700)?,
                ));
                new_assets.push(launcher.launcher_path());
                launcher.publish_generation(HookGeneration {
                    generation: 1,
                    protocol_version: 1,
                    executable: directory.join(GENERATION_EXECUTABLE_NAME),
                    runtime_snapshot: runtime,
                    compatible: true,
                })?;
                new_assets.push(launcher.registry_path());
                new_files.push((
                    launcher.registry_path(),
                    private_file_identity(&launcher.registry_path(), 0o600)?,
                ));
            }
        }
        if service_available && uninstall && unit_exists {
            stage = "service removal";
            for edit in &edits {
                edit.revalidate(edit.original.as_ref().map(|(id, _)| id))?;
            }
            service_attempted = true;
            require_service(
                &paths.systemctl,
                &["disable", "--now", "evertraced.service"],
            )?;
        }
        stage = "configuration publication";
        for edit in &mut edits {
            edit.publish()?;
        }
        stage = "service publication";
        if service_available && (uninstall && unit_exists || !uninstall && !unit_exists) {
            for edit in &edits {
                let expected =
                    if edit.original.as_ref().map(|(_, bytes)| bytes) == edit.desired.as_ref() {
                        edit.original.as_ref().map(|(id, _)| id)
                    } else {
                        edit.published.as_ref()
                    };
                edit.revalidate(expected)?;
            }
            service_attempted = true;
            require_service(&paths.systemctl, &["daemon-reload"])?;
            if !uninstall {
                service_started = true;
                require_service(&paths.systemctl, &["enable", "--now", "evertraced.service"])?;
            }
        }
        Ok(ManagedInstallResult {
            service_available,
            backups: edits
                .iter()
                .filter_map(|edit| edit.backup.clone())
                .collect(),
            manual_command: format!(
                "{} --config {}",
                shell_path(&paths.daemon)?,
                shell_path(&paths.config)?
            ),
            host_hooks_enabled,
        })
    })();
    result.map_err(|cause| {
        let mut preserved = Vec::new();
        let unit_owned = edits.get(2).is_some_and(|edit| {
            edit.revalidate(if edit.changed {
                edit.published.as_ref()
            } else {
                edit.original.as_ref().map(|(id, _)| id)
            })
            .is_ok()
        });
        let mut rollback_complete = !service_started
            || unit_owned
                && require_service(
                    &paths.systemctl,
                    &["disable", "--now", "evertraced.service"],
                )
                .is_ok();
        if !rollback_complete {
            preserved.push(paths.unit.clone());
        }
        for edit in edits.iter().rev() {
            if edit.rollback().is_err() {
                rollback_complete = false;
                preserved.push(edit.path.clone());
            }
            preserved.extend(edit.temporary.clone());
            if let Some(backup) = &edit.backup
                && backup.exists()
            {
                preserved.push(backup.clone());
            }
        }
        if service_attempted && unit_owned && rollback_complete {
            if require_service(&paths.systemctl, &["daemon-reload"]).is_err() {
                preserved.push(paths.unit.clone());
            }
            if let Some((enabled, active)) = previous_service {
                for action in [
                    if enabled { "enable" } else { "disable" },
                    if active { "start" } else { "stop" },
                ] {
                    if require_service(&paths.systemctl, &[action, "evertraced.service"]).is_err() {
                        preserved.push(paths.unit.clone());
                    }
                }
            }
        } else if service_attempted {
            preserved.push(paths.unit.clone());
        }
        if let Some((directory, custody)) = new_directory {
            let cleanup = (|| {
                if !rollback_complete {
                    return Err(InstallError::InvalidType);
                }
                let launcher = StableLauncher::open(&paths.data_root)?;
                launcher.with_lock(|| {
                    if !read_pins(
                        &paths.data_root.join(HOOKS_DIRECTORY).join(PINS_DIRECTORY),
                        false,
                    )?
                    .is_empty()
                    {
                        return Err(InstallError::InvalidType);
                    }
                    let current = fs::symlink_metadata(&directory).map_err(map_io)?;
                    let held = custody.metadata().map_err(map_io)?;
                    if !current.is_dir()
                        || current.file_type().is_symlink()
                        || (held.dev(), held.ino()) != (current.dev(), current.ino())
                    {
                        return Err(InstallError::InvalidType);
                    }
                    for path in [launcher.launcher_path(), launcher.registry_path()] {
                        if path.try_exists().map_err(map_io)?
                            && !new_files.iter().any(|(owned, _)| *owned == path)
                        {
                            return Err(InstallError::InvalidType);
                        }
                    }
                    for entry in fs::read_dir(&directory).map_err(map_io)?.take(3) {
                        let path = entry.map_err(map_io)?.path();
                        if !new_files.iter().any(|(owned, _)| *owned == path) {
                            return Err(InstallError::InvalidType);
                        }
                    }
                    for (path, identity) in &new_files {
                        let actual = fs::symlink_metadata(path).map_err(map_io)?;
                        if !actual.is_file()
                            || actual.file_type().is_symlink()
                            || hook_file_identity(&actual) != *identity
                        {
                            return Err(InstallError::InvalidType);
                        }
                    }
                    for (path, _) in new_files.iter().rev() {
                        fs::remove_file(path).map_err(map_io)?;
                        File::open(path.parent().ok_or(InstallError::InvalidType)?)
                            .and_then(|parent| parent.sync_all())
                            .map_err(map_io)?;
                    }
                    fs::remove_dir(&directory).map_err(map_io)?;
                    File::open(directory.parent().ok_or(InstallError::InvalidType)?)
                        .and_then(|parent| parent.sync_all())
                        .map_err(map_io)
                })
            })();
            if cleanup.is_err() {
                preserved.extend(new_assets);
            }
        }
        ManagedInstallError {
            stage,
            cause,
            preserved,
        }
    })
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookGeneration {
    pub generation: u64,
    pub protocol_version: u16,
    pub executable: PathBuf,
    pub runtime_snapshot: PathBuf,
    pub compatible: bool,
}

impl fmt::Debug for HookGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookGeneration")
            .field("generation", &self.generation)
            .field("protocol_version", &self.protocol_version)
            .field("compatible", &self.compatible)
            .field("paths_configured", &true)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationRegistry {
    registry_version: u16,
    current_generation: u64,
    generations: Vec<HookGeneration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenHookFile {
    pub directories: Vec<(PathBuf, u64, u64)>,
    pub source: PathBuf,
    pub relative_path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookBackupSnapshot {
    pub current_generation: Option<u64>,
    pub retained_generations: Vec<u64>,
    pub pin_count: u32,
    pub pinned_generation_count: u32,
    pub files: Vec<FrozenHookFile>,
}

pub struct CurrentHookSnapshot {
    pub generation: u64,
    pub files: [FrozenHookFile; 4],
}

pub struct UnpublishedPackage {
    pub generation: u64,
    pub executable: PathBuf,
    pub runtime: PathBuf,
    pub host_configuration: PathBuf,
    pub service_unit: PathBuf,
    assets: Vec<(PathBuf, HookFileIdentity)>,
    snapshot: CurrentHookSnapshot,
    host: InstallFile,
    service: InstallFile,
}

impl UnpublishedPackage {
    pub fn validate(&self) -> Result<(), InstallError> {
        self.host
            .revalidate(self.host.original.as_ref().map(|(identity, _)| identity))?;
        self.service
            .revalidate(self.service.original.as_ref().map(|(identity, _)| identity))?;
        let host_wiring = owned_wiring(
            self.host
                .desired
                .as_deref()
                .ok_or(InstallError::InvalidType)?,
        )?;
        for (path, expected) in [
            (&self.host_configuration, host_wiring.as_slice()),
            (
                &self.service_unit,
                self.service
                    .desired
                    .as_deref()
                    .ok_or(InstallError::InvalidType)?,
            ),
        ] {
            if read_private_file_bounded(path, 0o600, MAX_CONFIG_BYTES)? != expected {
                return Err(InstallError::InvalidType);
            }
        }
        for file in &self.snapshot.files {
            revalidate_frozen_file(file)?;
        }
        for (path, identity) in &self.assets {
            if hook_file_identity(&fs::symlink_metadata(path).map_err(map_io)?) != *identity {
                return Err(InstallError::InvalidType);
            }
        }
        Ok(())
    }
}

pub struct PackageCheckPreflight {
    generation: u64,
    package: PathBuf,
    assets: Vec<(PathBuf, HookFileIdentity)>,
    snapshot: CurrentHookSnapshot,
    host: InstallFile,
    service: InstallFile,
}

/// Wiring for the caller-owned disposable package probe only.
pub fn candidate_host_arguments() -> [String; 6] {
    // Literal definitions remain stable across disposable roots. Environment is
    // routing only; normal Host hook trust and candidate evidence still apply.
    let command =
        "exec \"$EVERTRACE_CANDIDATE_ROOT/hook-v1\" --launcher-root \"$EVERTRACE_CANDIDATE_ROOT\"";
    let hooks = toml::Value::String(command.into()).to_string();
    [
        format!("hooks.PreToolUse=[{{hooks=[{{type=\"command\",command={hooks},timeout=3}}]}}]"),
        format!("hooks.PostToolUse=[{{hooks=[{{type=\"command\",command={hooks},timeout=3}}]}}]"),
        format!("hooks.UserPromptSubmit=[{{hooks=[{{type=\"command\",command={hooks},timeout=3}}]}}]"),
        "mcp_servers.evertrace.command=\"/bin/sh\"".into(),
        "mcp_servers.evertrace.env_vars=[\"EVERTRACE_CANDIDATE_PACKAGE\",\"EVERTRACE_CANDIDATE_CONFIG\"]".into(),
        format!("mcp_servers.evertrace.args={}", toml::Value::Array(vec![toml::Value::String("-c".into()), toml::Value::String("exec \"$EVERTRACE_CANDIDATE_PACKAGE/evertrace\" --config \"$EVERTRACE_CANDIDATE_CONFIG\" mcp".into())])),
    ]
}

/// The ordered session arguments themselves are the candidate's wiring.
pub fn candidate_wiring_hash(arguments: &[String; 6]) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(arguments).expect("string array serialization");
    format!("{:x}", Sha256::digest(bytes))
}

/// Wiring for the caller-owned disposable package probe only.
pub fn prepare_probe_generation(
    root: &Path,
    executable: &Path,
    generation: u64,
    runtime: impl FnOnce(&Path) -> Result<(), InstallError>,
) -> Result<PathBuf, InstallError> {
    let required = package_metadata(executable)?
        .len()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(16 * 1024 * 1024))
        .ok_or(InstallError::ResourceExhausted)?;
    if fs2::available_space(root).map_err(map_io)? < required {
        return Err(InstallError::ResourceExhausted);
    }
    let launcher = StableLauncher::open(root)?;
    launcher.install_launcher_binary(executable)?;
    if generation == 0 {
        return Err(InstallError::InvalidType);
    }
    let directory = root.join(generation_relative(generation, GENERATION_EXECUTABLE_NAME));
    ensure_private_directory(directory.parent().ok_or(InstallError::InvalidType)?)?;
    atomic_write(&directory, &package_bytes(executable)?, 0o700)?;
    let snapshot = root.join(generation_relative(generation, GENERATION_RUNTIME_NAME));
    runtime(&snapshot)?;
    launcher.publish_generation(HookGeneration {
        generation,
        protocol_version: 1,
        executable: directory,
        runtime_snapshot: snapshot,
        compatible: true,
    })?;
    Ok(launcher.launcher_path())
}

/// Reject invalid inputs before the caller creates its backup/native candidate.
pub fn preflight_package_check(
    data: &Path,
    config: &Path,
    host_config: &Path,
    unit: &Path,
    package: &Path,
) -> Result<PackageCheckPreflight, InstallError> {
    let old_cli = validate_installed_wiring(data, config, host_config)?;
    let old_package = old_cli.parent().ok_or(InstallError::InvalidType)?;
    if !package.is_absolute()
        || package.starts_with(old_package)
        || old_package.starts_with(package)
    {
        return Err(InstallError::InvalidType);
    }
    let snapshot = StableLauncher::freeze_current_snapshot(
        data,
        std::time::Instant::now() + std::time::Duration::from_secs(3),
    )?;
    let launcher = StableLauncher {
        root: data.to_owned(),
    };
    let registry = launcher.read_registry()?;
    let generation = registry
        .generations
        .last()
        .and_then(|entry| entry.generation.checked_add(1))
        .ok_or(InstallError::ResourceExhausted)?;
    if data
        .join(generation_relative(generation, GENERATION_EXECUTABLE_NAME))
        .parent()
        .ok_or(InstallError::InvalidType)?
        .try_exists()
        .map_err(map_io)?
    {
        return Err(InstallError::InvalidType);
    }
    let mut assets = Vec::new();
    for name in ["evertrace", "evertrace-hook", "evertraced"] {
        let source = package.join(name);
        let identity = hook_file_identity(&package_metadata(&source)?);
        let previous = package_metadata(&old_package.join(name))?;
        if (identity.device, identity.inode) == (previous.dev(), previous.ino()) {
            return Err(InstallError::InvalidType);
        }
        assets.push((source, identity));
    }
    let (status, output) = bounded_install_command(
        &package.join("evertrace"),
        &[
            "--config",
            config.to_str().ok_or(InstallError::InvalidType)?,
            "config",
            "check",
        ],
        None,
    )?;
    if status != 0 || output.trim() != "configuration is valid" {
        return Err(InstallError::InvalidType);
    }
    let mut host = InstallFile::read(host_config)?;
    let old_host = &host.original.as_ref().ok_or(InstallError::InvalidType)?.1;
    let proposed = replace_wiring(
        old_host,
        &wiring(data, &old_cli, config)?,
        Some(&wiring(data, &package.join("evertrace"), config)?),
    )?;
    let mut service = InstallFile::read(unit)?;
    let expected_unit = unit_bytes(&old_package.join("evertraced"), config)?;
    if service
        .original
        .as_ref()
        .is_none_or(|(_, bytes)| *bytes != expected_unit)
    {
        return Err(InstallError::InvalidType);
    }
    host.desired = Some(proposed);
    service.desired = Some(unit_bytes(&package.join("evertraced"), config)?);
    Ok(PackageCheckPreflight {
        generation,
        package: package.to_owned(),
        assets,
        snapshot,
        host,
        service,
    })
}

/// Consume the preflight only inside the caller-owned private native candidate.
/// No registry, launcher, pin, Host file or service operation is published.
pub fn prepare_package_check(
    preflight: PackageCheckPreflight,
    candidate: &Path,
    prepare_runtime: impl FnOnce(&Path) -> Result<(), InstallError>,
) -> Result<UnpublishedPackage, InstallError> {
    let PackageCheckPreflight {
        generation,
        package,
        assets,
        snapshot,
        host,
        service,
    } = preflight;
    let directory = candidate.join("package");
    let needed = package_metadata(&package.join("evertrace-hook"))?
        .len()
        .checked_add(16 * 1024 * 1024)
        .ok_or(InstallError::ResourceExhausted)?;
    if fs2::available_space(candidate).map_err(map_io)? < needed {
        return Err(InstallError::ResourceExhausted);
    }
    DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(map_io)?;
    let mut result = UnpublishedPackage {
        generation,
        executable: directory.join(GENERATION_EXECUTABLE_NAME),
        runtime: directory.join(GENERATION_RUNTIME_NAME),
        host_configuration: directory.join("host-config.toml"),
        service_unit: directory.join("evertraced.service"),
        assets,
        snapshot,
        host,
        service,
    };
    atomic_write(
        &result.executable,
        &package_bytes(&package.join("evertrace-hook"))?,
        0o700,
    )?;
    prepare_runtime(&result.runtime)?;
    atomic_write(
        &result.host_configuration,
        &owned_wiring(
            result
                .host
                .desired
                .as_ref()
                .ok_or(InstallError::InvalidType)?,
        )?,
        0o600,
    )?;
    atomic_write(
        &result.service_unit,
        result
            .service
            .desired
            .as_ref()
            .ok_or(InstallError::InvalidType)?,
        0o600,
    )?;
    for (path, mode) in [
        (&result.executable, 0o700),
        (&result.runtime, 0o600),
        (&result.host_configuration, 0o600),
        (&result.service_unit, 0o600),
    ] {
        result
            .assets
            .push((path.clone(), private_file_identity(path, mode)?));
    }
    result.validate()?;
    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookBackupSemantic {
    pub current_generation: Option<u64>,
    pub retained_generations: Vec<u64>,
    pub pin_count: u32,
    pub pinned_generation_count: u32,
}

#[derive(Clone, Debug)]
pub struct StableLauncher {
    root: PathBuf,
}

pub struct RestoredHookPackage {
    pub current_generation: u64,
    /// Local runtime files whose contents remain owned by Capture, not this parser.
    pub pinned_runtime_files: Vec<PathBuf>,
    pub current_runtime_file: PathBuf,
}

impl StableLauncher {
    pub fn prepare_restored_package(
        candidate: &Path,
        active_root: &Path,
        current_executable: &Path,
    ) -> Result<RestoredHookPackage, InstallError> {
        let backup = Self::verify_backup_snapshot(candidate)?;
        let launcher = Self::open(candidate)?;
        let mut registry = if backup.current_generation.is_some() {
            serde_json::from_slice::<GenerationRegistry>(&read_private_file_bounded(
                &launcher.registry_path(),
                0o600,
                MAX_REGISTRY_BYTES,
            )?)
            .map_err(|_| InstallError::InvalidRegistry)?
        } else {
            GenerationRegistry {
                registry_version: REGISTRY_VERSION,
                current_generation: 1,
                generations: Vec::new(),
            }
        };
        let pins = read_pins(&candidate.join(HOOKS_DIRECTORY).join(PINS_DIRECTORY), false)?;
        let pinned = pins
            .iter()
            .map(|pin| pin.generation)
            .collect::<BTreeSet<_>>();
        let generation = registry
            .generations
            .last()
            .map_or(Some(1), |item| item.generation.checked_add(1))
            .ok_or(InstallError::ResourceExhausted)?;
        let mut pinned_runtime_files = Vec::new();
        for item in &mut registry.generations {
            item.executable = active_root.join(generation_relative(
                item.generation,
                GENERATION_EXECUTABLE_NAME,
            ));
            item.runtime_snapshot = active_root.join(generation_relative(
                item.generation,
                GENERATION_RUNTIME_NAME,
            ));
            item.compatible = pinned.contains(&item.generation);
            if item.compatible {
                let executable = candidate.join(generation_relative(
                    item.generation,
                    GENERATION_EXECUTABLE_NAME,
                ));
                validate_private_file(&executable, 0o600)?;
                fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
                    .map_err(map_io)?;
                pinned_runtime_files.push(candidate.join(generation_relative(
                    item.generation,
                    GENERATION_RUNTIME_NAME,
                )));
            }
        }
        let source_parent = current_executable
            .parent()
            .ok_or(InstallError::InvalidType)?;
        for directory in source_parent.ancestors() {
            let metadata = fs::symlink_metadata(directory).map_err(map_io)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(InstallError::InvalidType);
            }
        }
        let parent_identity = fs::symlink_metadata(source_parent).map_err(map_io)?;
        let owner = fs::metadata("/proc/self").map_err(map_io)?.uid();
        if parent_identity.mode() & 0o022 != 0 || ![0, owner].contains(&parent_identity.uid()) {
            return Err(InstallError::InvalidType);
        }
        let metadata = fs::symlink_metadata(current_executable).map_err(map_io)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
            || ![0, owner].contains(&metadata.uid())
            || metadata.len() > 256 * 1024 * 1024
        {
            return Err(InstallError::InvalidType);
        }
        if fs2::available_space(candidate).map_err(map_io)?
            < metadata.len().saturating_mul(2).saturating_add(1024 * 1024)
        {
            return Err(InstallError::ResourceExhausted);
        }
        let mut source = File::open(current_executable).map_err(map_io)?;
        if hook_file_identity(&source.metadata().map_err(map_io)?) != hook_file_identity(&metadata)
        {
            return Err(InstallError::InvalidType);
        }
        let mut bytes = Vec::new();
        (&mut source)
            .take(256 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(map_io)?;
        if u64::try_from(bytes.len()).map_err(|_| InstallError::ResourceExhausted)?
            != metadata.len()
            || hook_file_identity(&source.metadata().map_err(map_io)?)
                != hook_file_identity(&metadata)
        {
            return Err(InstallError::InvalidType);
        }
        let after = fs::symlink_metadata(current_executable).map_err(map_io)?;
        let parent_after = fs::symlink_metadata(source_parent).map_err(map_io)?;
        if hook_file_identity(&metadata) != hook_file_identity(&after)
            || (parent_identity.dev(), parent_identity.ino())
                != (parent_after.dev(), parent_after.ino())
        {
            return Err(InstallError::InvalidType);
        }
        let directory = candidate
            .join(HOOKS_DIRECTORY)
            .join(GENERATIONS_DIRECTORY)
            .join(generation.to_string());
        ensure_private_directory(&directory)?;
        atomic_write(&directory.join(GENERATION_EXECUTABLE_NAME), &bytes, 0o700)?;
        atomic_write(&launcher.launcher_path(), &bytes, 0o700)?;
        registry.current_generation = generation;
        registry.generations.push(HookGeneration {
            generation,
            protocol_version: 1,
            executable: active_root
                .join(generation_relative(generation, GENERATION_EXECUTABLE_NAME)),
            runtime_snapshot: active_root
                .join(generation_relative(generation, GENERATION_RUNTIME_NAME)),
            compatible: true,
        });
        validate_registry(active_root, &registry)?;
        atomic_json(&launcher.registry_path(), &registry, 0o600)?;
        Ok(RestoredHookPackage {
            current_generation: generation,
            pinned_runtime_files,
            current_runtime_file: directory.join(GENERATION_RUNTIME_NAME),
        })
    }

    pub fn validate_restored_package(
        candidate: &Path,
        active_root: &Path,
    ) -> Result<(), InstallError> {
        validate_private_directory(candidate)?;
        validate_private_file(&candidate.join("hook-v1"), 0o700)?;
        let registry: GenerationRegistry = serde_json::from_slice(&read_private_file_bounded(
            &candidate.join(HOOKS_DIRECTORY).join(REGISTRY_NAME),
            0o600,
            MAX_REGISTRY_BYTES,
        )?)
        .map_err(|_| InstallError::InvalidRegistry)?;
        validate_registry(active_root, &registry)?;
        let pins = read_pins(&candidate.join(HOOKS_DIRECTORY).join(PINS_DIRECTORY), false)?;
        for generation in retained_generations(&registry, &pins)? {
            let mut local = registry
                .generations
                .iter()
                .find(|item| item.generation == generation)
                .cloned()
                .ok_or(InstallError::InvalidRegistry)?;
            local.executable =
                candidate.join(generation_relative(generation, GENERATION_EXECUTABLE_NAME));
            local.runtime_snapshot =
                candidate.join(generation_relative(generation, GENERATION_RUNTIME_NAME));
            validate_generation(candidate, &local)?;
        }
        Ok(())
    }
    pub fn open(data_root: impl Into<PathBuf>) -> Result<Self, InstallError> {
        let root = data_root.into();
        ensure_private_directory(&root)?;
        ensure_private_directory(&root.join(HOOKS_DIRECTORY))?;
        ensure_private_directory(&root.join(HOOKS_DIRECTORY).join(PINS_DIRECTORY))?;
        ensure_private_directory(&root.join(HOOKS_DIRECTORY).join(GENERATIONS_DIRECTORY))?;
        let lock_path = root.join(HOOKS_DIRECTORY).join(REGISTRY_LOCK_NAME);
        if !lock_path.exists() {
            let _ = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&lock_path);
        }
        validate_private_file(&lock_path, 0o600)?;
        Ok(Self { root })
    }

    pub fn launcher_path(&self) -> PathBuf {
        self.root.join("hook-v1")
    }

    pub fn install_launcher_binary(&self, source: &Path) -> Result<(), InstallError> {
        let metadata = fs::symlink_metadata(source).map_err(map_io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(InstallError::InvalidType);
        }
        let bytes = fs::read(source).map_err(map_io)?;
        atomic_write(&self.launcher_path(), &bytes, 0o700)
    }

    pub fn publish_generation(&self, generation: HookGeneration) -> Result<(), InstallError> {
        validate_generation(&self.root, &generation)?;
        self.with_lock(|| {
            let registry_path = self.registry_path();
            let mut registry = match fs::symlink_metadata(&registry_path) {
                Ok(_) => self.read_registry()?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => GenerationRegistry {
                    registry_version: REGISTRY_VERSION,
                    current_generation: generation.generation,
                    generations: Vec::new(),
                },
                Err(error) => return Err(map_io(error)),
            };
            registry
                .generations
                .retain(|item| item.generation != generation.generation);
            registry.generations.push(generation.clone());
            registry.generations.sort_by_key(|item| item.generation);
            registry.current_generation = generation.generation;
            validate_registry(&self.root, &registry)?;
            atomic_json(&self.registry_path(), &registry, 0o600)
        })
    }

    pub fn resolve_for_session(&self, session_id: &str) -> Result<HookGeneration, InstallError> {
        validate_session_id(session_id)?;
        self.with_lock(|| {
            let registry = self.read_registry()?;
            let pin_path = self
                .root
                .join(HOOKS_DIRECTORY)
                .join(PINS_DIRECTORY)
                .join(format!("{session_id}.pin"));
            let generation = match fs::symlink_metadata(&pin_path) {
                Ok(_) => std::str::from_utf8(&read_private_file_bounded(
                    &pin_path,
                    0o600,
                    MAX_PIN_BYTES,
                )?)
                .map_err(|_| InstallError::InvalidRegistry)?
                .parse::<u64>()
                .map_err(|_| InstallError::InvalidRegistry)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let selected = registry
                        .generations
                        .iter()
                        .find(|item| {
                            item.generation == registry.current_generation && item.compatible
                        })
                        .ok_or(InstallError::GenerationUnavailable)?;
                    validate_generation(&self.root, selected)?;
                    atomic_write(
                        &pin_path,
                        registry.current_generation.to_string().as_bytes(),
                        0o600,
                    )?;
                    registry.current_generation
                }
                Err(error) => return Err(map_io(error)),
            };
            let selected = registry
                .generations
                .into_iter()
                .find(|item| item.generation == generation && item.compatible)
                .ok_or(InstallError::GenerationUnavailable)?;
            validate_generation(&self.root, &selected)?;
            Ok(selected)
        })
    }

    pub fn retained_generations(&self) -> Result<Vec<u64>, InstallError> {
        self.with_lock(|| {
            let registry = self.read_registry()?;
            let pins = read_pins(&self.root.join(HOOKS_DIRECTORY).join(PINS_DIRECTORY), true)?;
            let retained = retained_generations(&registry, &pins)?;
            for generation in &retained {
                let value = registry
                    .generations
                    .iter()
                    .find(|item| item.generation == *generation)
                    .ok_or(InstallError::GenerationUnavailable)?;
                validate_generation(&self.root, value)?;
            }
            Ok(retained)
        })
    }

    pub fn retained_native_reports(
        data: &Path,
    ) -> Result<Vec<crate::probe::HostProbeReport>, InstallError> {
        let launcher = Self {
            root: data.to_owned(),
        };
        match fs::symlink_metadata(launcher.registry_path()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(map_io(error)),
            Ok(_) => {}
        }
        launcher
            .retained_generations()?
            .into_iter()
            .map(|generation| {
                crate::hook_input::native_generation_report(generation)
                    .map_err(|_| InstallError::InvalidRegistry)
            })
            .collect()
    }

    /// Fixed current-install closure, not the retained backup closure. The
    /// deadline is cooperative between bounded reads; blocking filesystem calls
    /// themselves cannot be interrupted by this synchronous API.
    pub fn freeze_current_snapshot(
        data_root: &Path,
        deadline: std::time::Instant,
    ) -> Result<CurrentHookSnapshot, InstallError> {
        let check_deadline = || {
            if std::time::Instant::now() >= deadline {
                Err(InstallError::ResourceExhausted)
            } else {
                Ok(())
            }
        };
        check_deadline()?;
        validate_private_directory(data_root)?;
        let hooks = data_root.join(HOOKS_DIRECTORY);
        validate_private_directory(&hooks)?;
        let lock_path = hooks.join(REGISTRY_LOCK_NAME);
        let before = private_file_identity(&lock_path, 0o600)?;
        let lock = File::open(&lock_path).map_err(map_io)?;
        if hook_file_identity(&lock.metadata().map_err(map_io)?) != before {
            return Err(InstallError::InvalidRegistry);
        }
        fs2::FileExt::try_lock_shared(&lock).map_err(|_| InstallError::LockBusy)?;
        let launcher = Self {
            root: data_root.to_owned(),
        };
        check_deadline()?;
        // The sole closed registry is bounded to 1 MiB. Historical entries get
        // shape/layout validation, never historical asset or pin traversal.
        let registry = launcher.read_registry()?;
        check_deadline()?;
        let current = registry
            .generations
            .iter()
            .find(|entry| entry.generation == registry.current_generation && entry.compatible)
            .ok_or(InstallError::GenerationUnavailable)?;
        validate_generation(data_root, current)?;
        let files = [
            freeze_file(&data_root.join("hook-v1"), Path::new("hook-v1"), 0o700)?,
            freeze_file(
                &launcher.registry_path(),
                &PathBuf::from(HOOKS_DIRECTORY).join(REGISTRY_NAME),
                0o600,
            )?,
            freeze_file(
                &current.executable,
                &generation_relative(current.generation, GENERATION_EXECUTABLE_NAME),
                0o700,
            )?,
            freeze_file(
                &current.runtime_snapshot,
                &generation_relative(current.generation, GENERATION_RUNTIME_NAME),
                0o600,
            )?,
        ];
        for file in &files {
            check_deadline()?;
            revalidate_frozen_file(file)?;
        }
        if private_file_identity(&lock_path, 0o600)? != before {
            return Err(InstallError::InvalidRegistry);
        }
        check_deadline()?;
        Ok(CurrentHookSnapshot {
            generation: current.generation,
            files,
        })
    }

    pub fn freeze_backup_snapshot(data_root: &Path) -> Result<HookBackupSnapshot, InstallError> {
        validate_private_directory(data_root)?;
        let launcher_path = data_root.join("hook-v1");
        let hooks_path = data_root.join(HOOKS_DIRECTORY);
        match (
            fs::symlink_metadata(&launcher_path),
            fs::symlink_metadata(&hooks_path),
        ) {
            (Err(launcher), Err(hooks))
                if launcher.kind() == io::ErrorKind::NotFound
                    && hooks.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(HookBackupSnapshot {
                    current_generation: None,
                    retained_generations: Vec::new(),
                    pin_count: 0,
                    pinned_generation_count: 0,
                    files: Vec::new(),
                });
            }
            (Ok(_), Ok(_)) => {}
            _ => return Err(InstallError::InvalidRegistry),
        }
        validate_private_directory(&hooks_path)?;
        validate_private_file(&launcher_path, 0o700)?;
        let lock_path = hooks_path.join(REGISTRY_LOCK_NAME);
        let lock_before = private_file_identity(&lock_path, 0o600)?;
        let lock = File::open(&lock_path).map_err(map_io)?;
        if hook_file_identity(&lock.metadata().map_err(map_io)?) != lock_before {
            return Err(InstallError::InvalidRegistry);
        }
        fs2::FileExt::try_lock_shared(&lock).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                InstallError::LockBusy
            } else {
                map_io(error)
            }
        })?;
        let hooks_before = private_directory_identity(&hooks_path)?;
        let pins_path = hooks_path.join(PINS_DIRECTORY);
        let pins_before = private_directory_identity(&pins_path)?;

        let launcher = Self {
            root: data_root.to_owned(),
        };
        let registry = launcher.read_registry()?;
        let pins = read_pins(&pins_path, true)?;
        let retained = retained_generations(&registry, &pins)?;
        let pinned_generation_count = unique_pin_generation_count(&pins)?;
        let mut files = vec![
            freeze_file(&launcher_path, Path::new("hook-v1"), 0o700)?,
            freeze_file(
                &launcher.registry_path(),
                &PathBuf::from(HOOKS_DIRECTORY).join(REGISTRY_NAME),
                0o600,
            )?,
        ];
        for pin in &pins {
            files.push(freeze_file(
                &pin.path,
                &PathBuf::from(HOOKS_DIRECTORY)
                    .join(PINS_DIRECTORY)
                    .join(format!("{}.pin", pin.session_id)),
                0o600,
            )?);
        }
        for generation in &retained {
            let value = registry
                .generations
                .iter()
                .find(|value| value.generation == *generation && value.compatible)
                .ok_or(InstallError::GenerationUnavailable)?;
            validate_generation(data_root, value)?;
            files.push(freeze_file(
                &value.executable,
                &generation_relative(*generation, GENERATION_EXECUTABLE_NAME),
                0o700,
            )?);
            files.push(freeze_file(
                &value.runtime_snapshot,
                &generation_relative(*generation, GENERATION_RUNTIME_NAME),
                0o600,
            )?);
        }
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if files.len() > MAX_HOOK_SNAPSHOT_FILES
            || files
                .windows(2)
                .any(|pair| pair[0].relative_path == pair[1].relative_path)
        {
            return Err(InstallError::ResourceExhausted);
        }
        for file in &files {
            revalidate_frozen_file(file)?;
        }
        if private_file_identity(&lock_path, 0o600)? != lock_before {
            return Err(InstallError::InvalidRegistry);
        }
        if private_directory_identity(&hooks_path)? != hooks_before
            || private_directory_identity(&pins_path)? != pins_before
        {
            return Err(InstallError::InvalidRegistry);
        }
        Ok(HookBackupSnapshot {
            current_generation: Some(registry.current_generation),
            retained_generations: retained,
            pin_count: u32::try_from(pins.len()).map_err(|_| InstallError::ResourceExhausted)?,
            pinned_generation_count,
            files,
        })
    }

    pub fn verify_backup_snapshot(backup_root: &Path) -> Result<HookBackupSemantic, InstallError> {
        validate_private_directory(backup_root)?;
        let launcher_path = backup_root.join("hook-v1");
        let hooks_path = backup_root.join(HOOKS_DIRECTORY);
        match (
            fs::symlink_metadata(&launcher_path),
            fs::symlink_metadata(&hooks_path),
        ) {
            (Err(launcher), Err(hooks))
                if launcher.kind() == io::ErrorKind::NotFound
                    && hooks.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(HookBackupSemantic {
                    current_generation: None,
                    retained_generations: Vec::new(),
                    pin_count: 0,
                    pinned_generation_count: 0,
                });
            }
            (Ok(_), Ok(_)) => {}
            _ => return Err(InstallError::InvalidRegistry),
        }
        validate_private_directory(&hooks_path)?;
        validate_private_file(&launcher_path, 0o600)?;
        let registry_path = hooks_path.join(REGISTRY_NAME);
        let registry: GenerationRegistry = serde_json::from_slice(&read_private_file_bounded(
            &registry_path,
            0o600,
            MAX_REGISTRY_BYTES,
        )?)
        .map_err(|_| InstallError::InvalidRegistry)?;
        validate_registry_shape(&registry)?;
        validate_registry_layout(&registry)?;
        let pins = read_pins(&hooks_path.join(PINS_DIRECTORY), false)?;
        let retained = retained_generations(&registry, &pins)?;
        for generation in &retained {
            validate_private_file(
                &backup_root.join(generation_relative(*generation, GENERATION_EXECUTABLE_NAME)),
                0o600,
            )?;
            validate_private_file(
                &backup_root.join(generation_relative(*generation, GENERATION_RUNTIME_NAME)),
                0o600,
            )?;
        }
        Ok(HookBackupSemantic {
            current_generation: Some(registry.current_generation),
            retained_generations: retained,
            pin_count: u32::try_from(pins.len()).map_err(|_| InstallError::ResourceExhausted)?,
            pinned_generation_count: unique_pin_generation_count(&pins)?,
        })
    }

    fn read_registry(&self) -> Result<GenerationRegistry, InstallError> {
        let path = self.registry_path();
        let registry = serde_json::from_slice(&read_private_file_bounded(
            &path,
            0o600,
            MAX_REGISTRY_BYTES,
        )?)
        .map_err(|_| InstallError::InvalidRegistry)?;
        validate_registry(&self.root, &registry)?;
        Ok(registry)
    }

    fn registry_path(&self) -> PathBuf {
        self.root.join(HOOKS_DIRECTORY).join(REGISTRY_NAME)
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, InstallError>,
    ) -> Result<T, InstallError> {
        let lock =
            File::open(self.root.join(HOOKS_DIRECTORY).join(REGISTRY_LOCK_NAME)).map_err(map_io)?;
        FileExt::lock_exclusive(&lock).map_err(map_io)?;
        operation()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InstallError {
    #[error("systemctl exited with status {0}")]
    ServiceExit(i32),
    #[error("hook generation registry is invalid")]
    InvalidRegistry,
    #[error("hook generation is unavailable")]
    GenerationUnavailable,
    #[error("hook installation path has an invalid type")]
    InvalidType,
    #[error("hook installation permissions are invalid")]
    InvalidPermissions,
    #[error("hook generation registry is busy")]
    LockBusy,
    #[error("hook generation snapshot exceeded its resource boundary")]
    ResourceExhausted,
    #[error("hook installation operation failed")]
    Io,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PinRecord {
    session_id: String,
    generation: u64,
    path: PathBuf,
}

fn validate_generation(data_root: &Path, value: &HookGeneration) -> Result<(), InstallError> {
    validate_generation_shape(value)?;
    if generation_data_root(value)? != data_root
        || value.executable
            != data_root.join(generation_relative(
                value.generation,
                GENERATION_EXECUTABLE_NAME,
            ))
        || value.runtime_snapshot
            != data_root.join(generation_relative(
                value.generation,
                GENERATION_RUNTIME_NAME,
            ))
    {
        return Err(InstallError::InvalidRegistry);
    }
    for path in [
        data_root.join(HOOKS_DIRECTORY),
        data_root.join(HOOKS_DIRECTORY).join(GENERATIONS_DIRECTORY),
        value
            .executable
            .parent()
            .ok_or(InstallError::InvalidRegistry)?
            .to_owned(),
    ] {
        validate_private_directory(&path)?;
    }
    validate_private_file(&value.executable, 0o700)?;
    validate_private_file(&value.runtime_snapshot, 0o600)?;
    Ok(())
}

fn validate_generation_shape(value: &HookGeneration) -> Result<(), InstallError> {
    if value.generation == 0
        || value.protocol_version == 0
        || !value.executable.is_absolute()
        || !value.runtime_snapshot.is_absolute()
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn validate_registry(data_root: &Path, value: &GenerationRegistry) -> Result<(), InstallError> {
    validate_registry_shape(value)?;
    validate_registry_layout(value)?;
    if value
        .generations
        .iter()
        .any(|item| generation_data_root(item) != Ok(data_root))
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn validate_registry_shape(value: &GenerationRegistry) -> Result<(), InstallError> {
    if value.registry_version != REGISTRY_VERSION
        || value.generations.is_empty()
        || value.generations.len() > MAX_HOOK_SNAPSHOT_FILES
        || value
            .generations
            .iter()
            .any(|item| validate_generation_shape(item).is_err())
        || value
            .generations
            .windows(2)
            .any(|pair| pair[0].generation >= pair[1].generation)
        || !value
            .generations
            .iter()
            .any(|item| item.generation == value.current_generation && item.compatible)
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn validate_registry_layout(value: &GenerationRegistry) -> Result<(), InstallError> {
    let mut roots = BTreeSet::new();
    for generation in &value.generations {
        roots.insert(generation_data_root(generation)?.to_owned());
    }
    if roots.len() != 1 {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn generation_data_root(value: &HookGeneration) -> Result<&Path, InstallError> {
    let directory = value
        .executable
        .parent()
        .ok_or(InstallError::InvalidRegistry)?;
    if value.executable.file_name().and_then(|name| name.to_str())
        != Some(GENERATION_EXECUTABLE_NAME)
        || directory.file_name().and_then(|name| name.to_str())
            != Some(value.generation.to_string().as_str())
        || directory
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some(GENERATIONS_DIRECTORY)
        || directory
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some(HOOKS_DIRECTORY)
        || value.runtime_snapshot != directory.join(GENERATION_RUNTIME_NAME)
    {
        return Err(InstallError::InvalidRegistry);
    }
    directory
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or(InstallError::InvalidRegistry)
}

fn generation_relative(generation: u64, file: &str) -> PathBuf {
    PathBuf::from(HOOKS_DIRECTORY)
        .join(GENERATIONS_DIRECTORY)
        .join(generation.to_string())
        .join(file)
}

fn retained_generations(
    registry: &GenerationRegistry,
    pins: &[PinRecord],
) -> Result<Vec<u64>, InstallError> {
    let mut retained = BTreeSet::from([registry.current_generation]);
    if let Some(previous) = registry
        .generations
        .iter()
        .filter(|item| item.compatible && item.generation < registry.current_generation)
        .map(|item| item.generation)
        .max()
    {
        retained.insert(previous);
    }
    retained.extend(pins.iter().map(|pin| pin.generation));
    if retained.iter().any(|generation| {
        !registry
            .generations
            .iter()
            .any(|item| item.generation == *generation && item.compatible)
    }) {
        return Err(InstallError::GenerationUnavailable);
    }
    Ok(retained.into_iter().collect())
}

fn unique_pin_generation_count(pins: &[PinRecord]) -> Result<u32, InstallError> {
    u32::try_from(
        pins.iter()
            .map(|pin| pin.generation)
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .map_err(|_| InstallError::ResourceExhausted)
}

fn validate_session_id(value: &str) -> Result<(), InstallError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HookFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn read_pins(path: &Path, required: bool) -> Result<Vec<PinRecord>, InstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path)?,
        Err(error) if !required && error.kind() == io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(map_io(error)),
    }
    let mut pins = BTreeMap::new();
    for entry in fs::read_dir(path).map_err(map_io)? {
        if pins.len() == MAX_HOOK_SNAPSHOT_FILES {
            return Err(InstallError::ResourceExhausted);
        }
        let entry = entry.map_err(map_io)?;
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| InstallError::InvalidRegistry)?;
        let session_id = file_name
            .strip_suffix(".pin")
            .ok_or(InstallError::InvalidRegistry)?;
        validate_session_id(session_id)?;
        let path = entry.path();
        let value = read_private_file_bounded(&path, 0o600, MAX_PIN_BYTES)?;
        let generation = std::str::from_utf8(&value)
            .map_err(|_| InstallError::InvalidRegistry)?
            .parse::<u64>()
            .map_err(|_| InstallError::InvalidRegistry)?;
        if generation == 0
            || pins
                .insert(
                    session_id.to_owned(),
                    PinRecord {
                        session_id: session_id.to_owned(),
                        generation,
                        path,
                    },
                )
                .is_some()
        {
            return Err(InstallError::InvalidRegistry);
        }
    }
    Ok(pins.into_values().collect())
}

fn freeze_file(
    source: &Path,
    relative_path: &Path,
    mode: u32,
) -> Result<FrozenHookFile, InstallError> {
    let mut directory = source;
    let mut directories = Vec::new();
    for _ in relative_path.components() {
        directory = directory.parent().ok_or(InstallError::InvalidRegistry)?;
        let identity = private_directory_identity(directory)?;
        directories.push((directory.to_owned(), identity.device, identity.inode));
    }
    let identity = private_file_identity(source, mode)?;
    Ok(FrozenHookFile {
        directories,
        source: source.to_owned(),
        relative_path: relative_path.to_owned(),
        device: identity.device,
        inode: identity.inode,
        length: identity.length,
        modified_seconds: identity.modified_seconds,
        modified_nanoseconds: identity.modified_nanoseconds,
        changed_seconds: identity.changed_seconds,
        changed_nanoseconds: identity.changed_nanoseconds,
    })
}

fn revalidate_frozen_file(file: &FrozenHookFile) -> Result<(), InstallError> {
    for (path, device, inode) in &file.directories {
        let identity = private_directory_identity(path)?;
        if identity.device != *device || identity.inode != *inode {
            return Err(InstallError::InvalidRegistry);
        }
    }
    let metadata = fs::symlink_metadata(&file.source).map_err(map_io)?;
    validate_private_file_metadata(&metadata, None)?;
    if hook_file_identity(&metadata)
        != (HookFileIdentity {
            device: file.device,
            inode: file.inode,
            length: file.length,
            modified_seconds: file.modified_seconds,
            modified_nanoseconds: file.modified_nanoseconds,
            changed_seconds: file.changed_seconds,
            changed_nanoseconds: file.changed_nanoseconds,
        })
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn read_private_file_bounded(
    path: &Path,
    mode: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, InstallError> {
    let before = private_file_identity(path, mode)?;
    if before.length == 0 || before.length > max_bytes {
        return Err(InstallError::ResourceExhausted);
    }
    let file = File::open(path).map_err(map_io)?;
    if hook_file_identity(&file.metadata().map_err(map_io)?) != before {
        return Err(InstallError::InvalidRegistry);
    }
    let capacity = usize::try_from(before.length).map_err(|_| InstallError::ResourceExhausted)?;
    let limit = max_bytes
        .checked_add(1)
        .ok_or(InstallError::ResourceExhausted)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit).read_to_end(&mut bytes).map_err(map_io)?;
    if u64::try_from(bytes.len()).ok() != Some(before.length)
        || private_file_identity(path, mode)? != before
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(bytes)
}

fn private_file_identity(path: &Path, mode: u32) -> Result<HookFileIdentity, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    validate_private_file_metadata(&metadata, Some(mode))?;
    Ok(hook_file_identity(&metadata))
}

fn private_directory_identity(path: &Path) -> Result<HookFileIdentity, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    validate_private_directory_metadata(&metadata)?;
    Ok(hook_file_identity(&metadata))
}

fn hook_file_identity(metadata: &fs::Metadata) -> HookFileIdentity {
    HookFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != current_uid()?
                || metadata.permissions().mode() & 0o777 != 0o700
            {
                return Err(InstallError::InvalidPermissions);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(path).map_err(map_io)?;
        }
        Err(error) => return Err(map_io(error)),
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    validate_private_directory_metadata(&metadata)
}

fn validate_private_directory_metadata(metadata: &fs::Metadata) -> Result<(), InstallError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != current_uid()?
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(InstallError::InvalidPermissions);
    }
    Ok(())
}

fn validate_private_file(path: &Path, mode: u32) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    validate_private_file_metadata(&metadata, Some(mode))
}

fn validate_private_file_metadata(
    metadata: &fs::Metadata,
    mode: Option<u32>,
) -> Result<(), InstallError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InstallError::InvalidType);
    }
    if metadata.uid() != current_uid()?
        || mode.is_some_and(|mode| metadata.permissions().mode() & 0o777 != mode)
    {
        return Err(InstallError::InvalidPermissions);
    }
    Ok(())
}

fn atomic_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), InstallError> {
    let bytes = serde_json::to_vec(value).map_err(|_| InstallError::InvalidRegistry)?;
    atomic_write(path, &bytes, mode)
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::InvalidRegistry)?;
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != current_uid()? =>
        {
            return Err(InstallError::InvalidType);
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(map_io(error)),
    }
    for attempt in 0..32_u32 {
        let staging = parent.join(format!(".install-{}-{attempt}.tmp", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&staging)
        {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(bytes).map_err(map_io)?;
                    file.sync_all().map_err(map_io)?;
                    fs::rename(&staging, path).map_err(map_io)?;
                    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(map_io)?;
                    File::open(parent)
                        .and_then(|dir| dir.sync_all())
                        .map_err(map_io)
                })();
                if result.is_err() {
                    let _ = fs::remove_file(staging);
                }
                return result;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(map_io(error)),
        }
    }
    Err(InstallError::Io)
}

fn current_uid() -> Result<u32, InstallError> {
    fs::metadata("/proc/self")
        .map(|value| value.uid())
        .map_err(map_io)
}

fn map_io(_: io::Error) -> InstallError {
    InstallError::Io
}
