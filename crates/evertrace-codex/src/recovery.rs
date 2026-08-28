//! Closed deterministic classifier for Codex local destructive mutators.

use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use evertrace_domain::repository::{
    DestructiveClass, DestructiveDetectionStatus, UntrackedCaptureScope,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const RECOVERY_CLASSIFIER_REVISION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedPathKind {
    Tracked,
    AttemptAnchor,
    RegisteredArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedPath {
    pub path: PathBuf,
    pub kind: ProtectedPathKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructiveCommandInput {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub worktree_root: PathBuf,
    pub known_worktree_roots: Vec<PathBuf>,
    pub protected_paths: Vec<ProtectedPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructiveClassification {
    pub detection_status: DestructiveDetectionStatus,
    pub destructive_class: Option<DestructiveClass>,
    pub untracked_capture_scope: Option<UntrackedCaptureScope>,
    pub target_worktree: Option<PathBuf>,
    pub target_paths: Vec<PathBuf>,
    pub command_fingerprint: String,
    pub reason_code: &'static str,
}

pub fn classify_destructive_command(input: &DestructiveCommandInput) -> DestructiveClassification {
    let fingerprint = fingerprint(input);
    if normalize_absolute(&input.cwd).as_deref() != Some(input.cwd.as_path())
        || normalize_absolute(&input.worktree_root).as_deref()
            != Some(input.worktree_root.as_path())
    {
        return unknown(fingerprint, "ambiguous_worktree");
    }
    let Some(program) = Path::new(&input.program)
        .file_name()
        .and_then(OsStr::to_str)
    else {
        return unknown(fingerprint, "dynamic_wrapper");
    };
    if matches!(
        program,
        "sh" | "bash" | "zsh" | "fish" | "cmd" | "powershell"
    ) {
        return unknown(fingerprint, "complex_shell");
    }
    match program {
        "git" => classify_git(input, fingerprint),
        "rm" | "unlink" | "rmdir" => classify_remove(input, fingerprint),
        _ => unsupported(fingerprint, "unsupported_tool"),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexLocalCommandPayload {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: String,
}

pub fn parse_codex_pretool_payload(payload: &str) -> Option<CodexLocalCommandPayload> {
    serde_json::from_str(payload).ok()
}

pub fn classify_codex_pretool_payload(
    payload: &str,
    observed_cwd: &Path,
) -> DestructiveClassification {
    let Some(command) = parse_codex_pretool_payload(payload) else {
        return unknown(
            payload_fingerprint(payload),
            "untyped_or_complex_host_payload",
        );
    };
    let cwd = PathBuf::from(command.cwd);
    if cwd != observed_cwd {
        return unknown(payload_fingerprint(payload), "host_cwd_mismatch");
    }
    classify_destructive_command(&DestructiveCommandInput {
        program: command.program,
        args: command.args,
        cwd: cwd.clone(),
        worktree_root: cwd,
        known_worktree_roots: vec![observed_cwd.to_path_buf()],
        protected_paths: Vec::new(),
    })
}

/// Produces a lexical Hook-side candidate only. The daemon must rerun
/// [`classify_destructive_command`] with store-owned worktree and protected
/// path evidence before this candidate can become a logical request.
pub fn classify_codex_pretool_candidate(
    payload: &str,
    observed_cwd: &Path,
) -> DestructiveClassification {
    let Some(command) = parse_codex_pretool_payload(payload) else {
        return unknown(
            payload_fingerprint(payload),
            "untyped_or_complex_host_payload",
        );
    };
    let cwd = PathBuf::from(&command.cwd);
    if cwd != observed_cwd {
        return unknown(payload_fingerprint(payload), "host_cwd_mismatch");
    }
    let protected_paths = Path::new(&command.program)
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|program| matches!(*program, "rm" | "unlink" | "rmdir"))
        .map(|_| {
            command
                .args
                .iter()
                .filter(|arg| !arg.starts_with('-'))
                .filter_map(|value| resolve(&cwd, Path::new(value)))
                .map(|path| ProtectedPath {
                    path,
                    kind: ProtectedPathKind::Tracked,
                })
                .collect()
        })
        .unwrap_or_default();
    let mut known_worktree_roots = vec![cwd.clone()];
    if Path::new(&command.program)
        .file_name()
        .and_then(OsStr::to_str)
        == Some("git")
        && command
            .args
            .first()
            .is_some_and(|value| value == "worktree")
        && command.args.get(1).is_some_and(|value| value == "remove")
    {
        let targets = command.args[2..]
            .iter()
            .filter(|value| !value.starts_with('-'))
            .collect::<Vec<_>>();
        if targets.len() == 1
            && let Some(target) = resolve(&cwd, Path::new(targets[0]))
        {
            known_worktree_roots.push(target);
        }
    }
    classify_destructive_command(&DestructiveCommandInput {
        program: command.program,
        args: command.args,
        cwd: cwd.clone(),
        worktree_root: cwd.clone(),
        known_worktree_roots,
        protected_paths,
    })
}

fn payload_fingerprint(payload: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"evertrace.recovery_untyped_payload.v1\0");
    hash.update(payload.as_bytes());
    format!("{:x}", hash.finalize())
}

fn classify_git(input: &DestructiveCommandInput, fingerprint: String) -> DestructiveClassification {
    let Some(subcommand) = input.args.first() else {
        return unsupported(fingerprint, "missing_git_subcommand");
    };
    if subcommand.starts_with('-') {
        return unsupported(fingerprint, "git_global_options_unsupported");
    }
    let tail = &input.args[1..];
    let class = match subcommand.as_str() {
        "reset" if tail.iter().any(|arg| arg == "--hard") => DestructiveClass::GitResetHard,
        "clean" => {
            let Some(scope) = classify_clean_scope(tail) else {
                return unsupported(fingerprint, "unsupported_git_clean_options");
            };
            if !input.cwd.starts_with(&input.worktree_root) {
                return unknown(fingerprint, "command_cwd_outside_target_worktree");
            }
            return matched_with_scope(
                fingerprint,
                DestructiveClass::GitClean,
                input.worktree_root.clone(),
                Vec::new(),
                scope,
            );
        }
        "checkout" if tail.iter().any(|arg| arg == "-f" || arg == "--force") => {
            DestructiveClass::GitCheckoutForce
        }
        "switch" if tail.iter().any(|arg| arg == "--discard-changes") => {
            DestructiveClass::GitSwitchDiscardChanges
        }
        "restore" if !tail.is_empty() => DestructiveClass::GitRestoreDiscard,
        "worktree" if tail.first().is_some_and(|arg| arg == "remove") => {
            if tail[1..]
                .iter()
                .any(|arg| arg.starts_with('-') && arg != "-f" && arg != "--force")
            {
                return unsupported(fingerprint, "unsupported_worktree_remove_options");
            }
            let targets = tail[1..]
                .iter()
                .filter(|arg| !arg.starts_with('-'))
                .collect::<Vec<_>>();
            if targets.len() != 1 {
                return unknown(fingerprint, "ambiguous_worktree_target");
            }
            let Some(target) = resolve(&input.cwd, Path::new(targets[0])) else {
                return unknown(fingerprint, "ambiguous_worktree_target");
            };
            let matches = input
                .known_worktree_roots
                .iter()
                .filter_map(|root| normalize_absolute(root))
                .filter(|root| *root == target)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return unknown(fingerprint, "unknown_worktree_target");
            }
            return matched(
                fingerprint,
                DestructiveClass::GitWorktreeRemove,
                matches[0].clone(),
                Vec::new(),
            );
        }
        _ => return unsupported(fingerprint, "outside_supported_mutation_domain"),
    };
    if !input.cwd.starts_with(&input.worktree_root) {
        return unknown(fingerprint, "command_cwd_outside_target_worktree");
    }
    matched(fingerprint, class, input.worktree_root.clone(), Vec::new())
}

fn classify_remove(
    input: &DestructiveCommandInput,
    fingerprint: String,
) -> DestructiveClassification {
    if input.args.iter().any(|arg| {
        arg.starts_with('-')
            && arg != "--"
            && arg != "-f"
            && arg != "--force"
            && arg != "-d"
            && arg != "--dir"
    }) {
        return unsupported(fingerprint, "unsupported_remove_options");
    }
    let raw = input
        .args
        .iter()
        .filter(|arg| !arg.starts_with('-') && arg.as_str() != "--")
        .collect::<Vec<_>>();
    if raw.is_empty() {
        return unsupported(fingerprint, "missing_file_target");
    }
    let mut class = None;
    let mut targets = Vec::new();
    for value in raw {
        if Path::new(value)
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return unknown(fingerprint, "non_strict_file_target");
        }
        if value
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}' | b'$'))
        {
            return unknown(fingerprint, "dynamic_file_target");
        }
        let Some(target) = resolve(&input.cwd, Path::new(value)) else {
            return unknown(fingerprint, "dynamic_file_target");
        };
        if !target.starts_with(&input.worktree_root) {
            return unknown(fingerprint, "target_outside_worktree");
        }
        let Some(protected) = input
            .protected_paths
            .iter()
            .find(|known| normalize_absolute(&known.path).as_ref() == Some(&target))
        else {
            return unsupported(fingerprint, "file_not_in_supported_recovery_set");
        };
        let candidate = match protected.kind {
            ProtectedPathKind::Tracked => DestructiveClass::TrackedFileRemove,
            ProtectedPathKind::AttemptAnchor => DestructiveClass::AttemptAnchorRemove,
            ProtectedPathKind::RegisteredArtifact => DestructiveClass::RegisteredArtifactRemove,
        };
        if class.is_some_and(|current| current != candidate) {
            return unknown(fingerprint, "mixed_destructive_classes");
        }
        class = Some(candidate);
        targets.push(target);
    }
    matched(
        fingerprint,
        class.expect("targets are non-empty"),
        input.worktree_root.clone(),
        targets,
    )
}

fn fingerprint(input: &DestructiveCommandInput) -> String {
    let mut hash = Sha256::new();
    hash.update(b"evertrace.recovery_classifier.v1\0");
    let cwd = input.cwd.to_string_lossy();
    for value in std::iter::once(input.program.as_str())
        .chain(input.args.iter().map(String::as_str))
        .chain(std::iter::once(cwd.as_ref()))
    {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

fn resolve(cwd: &Path, path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        normalize_absolute(path)
    } else {
        normalize_absolute(&cwd.join(path))
    }
}

fn normalize_absolute(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                output.push(component.as_os_str())
            }
            Component::CurDir => {}
            Component::ParentDir if output.pop() => {}
            Component::ParentDir => return None,
        }
    }
    Some(output)
}

fn matched(
    fingerprint: String,
    class: DestructiveClass,
    worktree: PathBuf,
    paths: Vec<PathBuf>,
) -> DestructiveClassification {
    matched_with_scope(
        fingerprint,
        class,
        worktree,
        paths,
        UntrackedCaptureScope::Standard,
    )
}

fn matched_with_scope(
    fingerprint: String,
    class: DestructiveClass,
    worktree: PathBuf,
    paths: Vec<PathBuf>,
    scope: UntrackedCaptureScope,
) -> DestructiveClassification {
    DestructiveClassification {
        detection_status: DestructiveDetectionStatus::Matched,
        destructive_class: Some(class),
        untracked_capture_scope: Some(scope),
        target_worktree: Some(worktree),
        target_paths: paths,
        command_fingerprint: fingerprint,
        reason_code: "supported_local_mutator",
    }
}

fn unknown(fingerprint: String, reason: &'static str) -> DestructiveClassification {
    DestructiveClassification {
        detection_status: DestructiveDetectionStatus::Unknown,
        destructive_class: None,
        untracked_capture_scope: None,
        target_worktree: None,
        target_paths: Vec::new(),
        command_fingerprint: fingerprint,
        reason_code: reason,
    }
}

fn unsupported(fingerprint: String, reason: &'static str) -> DestructiveClassification {
    DestructiveClassification {
        detection_status: DestructiveDetectionStatus::Unsupported,
        destructive_class: None,
        untracked_capture_scope: None,
        target_worktree: None,
        target_paths: Vec::new(),
        command_fingerprint: fingerprint,
        reason_code: reason,
    }
}

fn classify_clean_scope(args: &[String]) -> Option<UntrackedCaptureScope> {
    let mut force = false;
    let mut include_ignored = false;
    let mut ignored_only = false;
    for arg in args {
        if arg == "--force" {
            force = true;
            continue;
        }
        let flags = arg.strip_prefix('-').filter(|value| !value.is_empty())?;
        if flags.starts_with('-') {
            return None;
        }
        for flag in flags.chars() {
            match flag {
                'f' => force = true,
                'd' => {}
                'x' if !ignored_only => include_ignored = true,
                'X' if !include_ignored => ignored_only = true,
                _ => return None,
            }
        }
    }
    if !force {
        None
    } else if include_ignored {
        Some(UntrackedCaptureScope::StandardAndIgnored)
    } else if ignored_only {
        Some(UntrackedCaptureScope::IgnoredOnly)
    } else {
        Some(UntrackedCaptureScope::Standard)
    }
}
