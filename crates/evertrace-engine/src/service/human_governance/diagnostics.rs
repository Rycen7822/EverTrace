use std::{
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use evertrace_capture::{ConfinedRoot, RuntimeSnapshot};
use evertrace_domain::{config::EffectiveConfig, evidence::hex};
use evertrace_store::{JobStatus, NativeDiagnostics, RuntimeSchedulerView};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanDiagnosticState {
    Checked,
    Unavailable,
    Inconsistent,
    NotChecked,
    NotRun,
    Disabled,
    Exhausted,
    Historical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanDiagnosticCheck {
    /// Closed, payload-free check name; never a filesystem name or user string.
    pub name: &'static str,
    pub state: HumanDiagnosticState,
    pub count: Option<u64>,
    pub limit: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanTableDiagnostic {
    pub schema_matches: Option<bool>,
    pub version: Option<u64>,
    pub checkpoint: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanDiagnostics {
    pub config_version: u32,
    pub algorithm_revision: u32,
    pub config_hash: String,
    pub observed_at_us: i64,
    /// journal, objects, relations, search, in that fixed order.
    pub tables: Vec<HumanTableDiagnostic>,
    pub checks: Vec<HumanDiagnosticCheck>,
    pub host: Option<crate::HostCanaryDiagnostic>,
}

pub(super) fn compile(
    config: &EffectiveConfig,
    runtime: Option<&RuntimeSnapshot>,
    native: &NativeDiagnostics,
    host: Option<crate::HostCanaryDiagnostic>,
) -> HumanDiagnostics {
    use HumanDiagnosticState::*;
    let observed_at_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .unwrap_or(0);
    let mut checks = Vec::new();
    let mut add = |name, state, count, limit| {
        checks.push(HumanDiagnosticCheck {
            name,
            state,
            count,
            limit,
        })
    };
    let journal = native.tables[0].checkpoint;
    add(
        "projection_checkpoints",
        match journal {
            Some(frontier)
                if native
                    .tables
                    .iter()
                    .all(|table| table.checkpoint == Some(frontier)) =>
            {
                Checked
            }
            Some(_) if native.tables.iter().all(|table| table.checkpoint.is_some()) => Inconsistent,
            _ => Unavailable,
        },
        journal,
        None,
    );
    add(
        "fts_metadata",
        match native.fts_index_present {
            Some(true) => Checked,
            Some(false) => Inconsistent,
            None => Unavailable,
        },
        None,
        None,
    );
    add("journal_content", NotChecked, None, None);
    add(
        "objects_rows",
        if native.objects.is_some() {
            Checked
        } else {
            Unavailable
        },
        native
            .objects
            .as_ref()
            .map(|snapshot| snapshot.data_rows().count() as u64),
        None,
    );
    add("relations_content", NotChecked, None, None);
    add("search_content", NotChecked, None, None);
    // A cooperative metadata budget, not a hard deadline on blocking filesystem I/O.
    let deadline = Instant::now() + Duration::from_secs(2);
    for (name, path) in [
        (
            "spool_metadata",
            runtime.map(|value| value.spool_dir.as_path()),
        ),
        ("cas_metadata", runtime.map(|value| value.cas_dir.as_path())),
    ] {
        let count = path.and_then(|path| directory_metadata(path, deadline));
        let recovery_artifacts = if name == "spool_metadata" {
            path.and_then(|path| {
                directory_metadata(&path.join("emergency"), deadline)?
                    .checked_add(directory_metadata(&path.join("quarantine"), deadline)?)
            })
        } else {
            Some(0)
        };
        add(
            name,
            if recovery_artifacts.is_some_and(|count| count != 0) {
                Inconsistent
            } else if count.is_some() && recovery_artifacts.is_some() {
                Checked
            } else {
                Unavailable
            },
            count,
            Some(256),
        );
    }
    add("spool_frames", NotChecked, None, None);
    add("cas_content", NotChecked, None, None);
    let jobs = native
        .objects
        .as_ref()
        .and_then(|snapshot| RuntimeSchedulerView::from_snapshot(snapshot).ok());
    for (name, state) in [
        ("jobs_queued", JobStatus::Queued),
        ("jobs_leased", JobStatus::Leased),
        ("jobs_failed_history", JobStatus::Failed),
    ] {
        add(
            name,
            if jobs.is_none() {
                Unavailable
            } else if state == JobStatus::Failed {
                Historical
            } else {
                Checked
            },
            jobs.as_ref()
                .map(|view| view.jobs.iter().filter(|job| job.state == state).count() as u64),
            None,
        );
    }
    for (name, kind) in [
        (
            "backup_create_history",
            evertrace_store::QUIESCED_BACKUP_CREATE_JOB_KIND,
        ),
        (
            "backup_verify_history",
            evertrace_store::QUIESCED_BACKUP_VERIFY_JOB_KIND,
        ),
    ] {
        add(
            name,
            if jobs.is_some() {
                Historical
            } else {
                Unavailable
            },
            jobs.as_ref().map(|view| {
                view.jobs
                    .iter()
                    .filter(|job| {
                        job.kind == kind
                            && job.state == JobStatus::Succeeded
                            && job.terminal.as_ref().is_some_and(|terminal| {
                                terminal.reason == evertrace_store::JobTerminalReason::Completed
                            })
                    })
                    .count() as u64
            }),
            None,
        );
    }
    add("backup_content_current", NotChecked, None, None);
    let sampled_backup = jobs.as_ref().and_then(|view| {
        view.jobs
            .iter()
            .filter(|job| {
                job.kind == evertrace_store::QUIESCED_BACKUP_CREATE_JOB_KIND
                    && job.state == JobStatus::Succeeded
                    && job.terminal.as_ref().is_some_and(|terminal| {
                        terminal.reason == evertrace_store::JobTerminalReason::Completed
                    })
            })
            .max_by_key(|job| job.job_id)
    });
    let backup = sampled_backup.and_then(|job| {
        runtime
            .and_then(|value| value.data_dir().ok())
            .and_then(|root| evertrace_store::backup::read_backup_summary(root, job.job_id).ok())
    });
    add(
        "backup_manifest_sample",
        if sampled_backup.is_none() {
            NotRun
        } else if backup.is_some() {
            Checked
        } else {
            Unavailable
        },
        backup.as_ref().map(|value| value.frontier),
        None,
    );
    add(
        "backup_sample_declared_bytes",
        if backup.is_some() {
            Historical
        } else {
            NotChecked
        },
        backup.as_ref().map(|value| value.total_bytes),
        None,
    );
    let purge = native
        .objects
        .as_ref()
        .and_then(|snapshot| evertrace_store::ScopePurgeCurrentView::from_snapshot(snapshot).ok());
    add(
        "purge_current",
        if purge.is_some() {
            Checked
        } else {
            Unavailable
        },
        purge.as_ref().map(|view| view.events.len() as u64),
        None,
    );
    let deletion = native.objects.as_ref().and_then(|snapshot| {
        evertrace_store::ObjectDeletionCurrentView::from_snapshot(snapshot).ok()
    });
    add(
        "object_deletion_current",
        if deletion.is_some() {
            Checked
        } else {
            Unavailable
        },
        deletion.as_ref().map(|view| view.events.len() as u64),
        None,
    );
    add("native_history_cleanup", Unavailable, None, None);
    let llm = &config.config().llm;
    let usage = native.objects.as_ref().and_then(|snapshot| {
        crate::jobs::synthesis::recorded_daily_usage(snapshot, observed_at_us).ok()
    });
    for (name, used, limit, unlimited) in [
        (
            "llm_daily_calls",
            usage.as_ref().map(|value| u64::from(value.calls)),
            u64::from(llm.daily_call_budget),
            false,
        ),
        (
            "llm_daily_input_tokens",
            usage.as_ref().map(|value| value.input_tokens),
            llm.daily_input_token_budget,
            llm.unlimited_token_budget,
        ),
        (
            "llm_daily_output_tokens",
            usage.as_ref().map(|value| value.output_tokens),
            llm.daily_output_token_budget,
            llm.unlimited_token_budget,
        ),
        (
            "llm_daily_wall_time_us",
            usage.as_ref().map(|value| value.wall_time_us),
            llm.daily_wall_time_budget
                .seconds()
                .saturating_mul(1_000_000),
            false,
        ),
    ] {
        add(
            name,
            quota_state(llm.enabled, used, limit, unlimited),
            used,
            (!unlimited).then_some(limit),
        );
    }
    add("provider_connectivity", NotChecked, None, None);
    add("acceptance_a_f", NotRun, None, None);
    for (name, count) in [
        ("runtime_generation", runtime.map(|value| value.generation)),
        (
            "runtime_snapshot_version",
            runtime.map(|value| u64::from(value.snapshot_version)),
        ),
        (
            "recovery_classifier_revision",
            runtime.map(|value| u64::from(value.recovery_classifier_revision)),
        ),
        (
            "spool_high_watermark_bytes",
            runtime.map(|value| value.main_high_watermark_bytes),
        ),
        (
            "spool_low_watermark_bytes",
            runtime.map(|value| value.main_low_watermark_bytes),
        ),
        (
            "spool_max_main_files",
            runtime.map(|value| u64::from(value.max_main_files)),
        ),
    ] {
        add(
            name,
            if count.is_some() {
                Checked
            } else {
                Unavailable
            },
            count,
            None,
        );
    }
    HumanDiagnostics {
        config_version: config.config().config_version,
        config_hash: hex(&config.hash()),
        observed_at_us,
        algorithm_revision: evertrace_domain::revision::AlgorithmRevision::V1.version(),
        tables: native
            .tables
            .iter()
            .map(|table| HumanTableDiagnostic {
                schema_matches: table.schema_matches,
                version: table.version,
                checkpoint: table.checkpoint,
            })
            .collect(),
        checks,
        host,
    }
}

fn directory_metadata(path: &Path, deadline: Instant) -> Option<u64> {
    let root = ConfinedRoot::open_owned_private(path).ok()?;
    let before = std::fs::symlink_metadata(path).ok()?;
    if !before.is_dir() || before.mode() & 0o077 != 0 {
        return None;
    }
    let entries = root.list_directory(None, 256, deadline).ok()?;
    for entry in &entries {
        if Instant::now() >= deadline {
            return None;
        }
        let metadata = std::fs::symlink_metadata(path.join(&entry.name)).ok()?;
        if metadata.uid() != before.uid()
            || metadata.mode() & 0o077 != 0
            || metadata.dev() != entry.identity.device
            || metadata.ino() != entry.identity.inode
            || metadata.len() != entry.identity.size
            || metadata.ctime() != entry.identity.ctime_seconds
            || u64::try_from(metadata.ctime_nsec()).ok()? != entry.identity.ctime_nanoseconds
        {
            return None;
        }
    }
    // Names/content are not returned, and descendants are not claimed verified.
    root.revalidate().ok()?;
    Some(entries.len() as u64)
}

fn quota_state(
    enabled: bool,
    used: Option<u64>,
    limit: u64,
    unlimited: bool,
) -> HumanDiagnosticState {
    use HumanDiagnosticState::*;
    if !enabled {
        Disabled
    } else {
        match used {
            None => Unavailable,
            Some(value) if !unlimited && value >= limit => Exhausted,
            Some(_) => Checked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_sampling_rejects_permissions_and_links_without_repair() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
        let path = std::env::temp_dir().join(format!(
            "evertrace-diagnostics-{}",
            evertrace_domain::ids::CommandId::new_v7()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let file = path.join("sample");
        std::fs::write(&file, b"unchanged").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        assert_eq!(directory_metadata(&path, deadline), Some(1));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(directory_metadata(&path, deadline), None);
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, 0o666);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&file, path.join("link")).unwrap();
        assert_eq!(directory_metadata(&path, deadline), None);
        std::fs::remove_file(path.join("link")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(directory_metadata(&path, deadline), None);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(directory_metadata(&path, deadline), Some(1));
        assert_eq!(std::fs::read(&file).unwrap(), b"unchanged");
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(path).unwrap();
    }

    #[test]
    fn recorded_budget_is_not_a_future_request_prediction() {
        use HumanDiagnosticState::*;
        assert_eq!(quota_state(false, Some(5), 5, false), Disabled);
        assert_eq!(quota_state(true, None, 5, false), Unavailable);
        assert_eq!(quota_state(true, Some(5), 5, false), Exhausted);
        assert_eq!(quota_state(true, Some(4), 5, false), Checked);
        assert_eq!(quota_state(true, Some(6), 5, true), Checked);
    }
}
