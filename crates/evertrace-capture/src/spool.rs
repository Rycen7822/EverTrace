use std::{
    collections::BTreeSet,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::frame::{
    DecodedFrame, SpoolFrameError, SpoolRecord, decode_validated_record_body, encode_frame,
    scan_frames,
};

const ACTIVE_NAME: &str = "active.open";
const ISOLATED_PREFIX: &str = "isolated-";
const MARKER_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpoolLimits {
    pub high_watermark_bytes: u64,
    pub low_watermark_bytes: u64,
    pub max_main_files: u32,
    pub emergency_slots: u16,
}

impl SpoolLimits {
    pub fn validate(self) -> Result<Self, SpoolError> {
        if self.low_watermark_bytes == 0
            || self.high_watermark_bytes < self.low_watermark_bytes
            || self.max_main_files == 0
            || self.emergency_slots == 0
            || self.emergency_slots > 64
        {
            return Err(SpoolError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureGapMarker {
    pub marker_id: String,
    pub source_ref: String,
    pub session_ref: String,
    pub turn_ref: Option<String>,
    pub tool_ref: Option<String>,
    pub failure_reason: GapReason,
    pub redacted_fingerprint: String,
    pub attempted_bytes: u64,
    pub last_durable_watermark: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    MainPressure,
    MainUnavailable,
    CorruptSegment,
    RecoveryUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GapEvidence {
    pub quarantined_file: PathBuf,
    pub reason: GapReason,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    pub repaired_tail_bytes: u64,
    pub gaps: Vec<GapEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableWrite {
    pub end_watermark: u64,
    pub frame_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedFrame {
    pub record: SpoolRecord,
    pub byte_start: u64,
    pub byte_end: u64,
}

#[derive(Debug)]
pub struct SealedSegment {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    length: u64,
    frames: Vec<SealedFrame>,
}

#[derive(Debug)]
pub struct PendingGapMarker {
    marker: CaptureGapMarker,
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    length: u64,
}

impl PendingGapMarker {
    pub const fn marker(&self) -> &CaptureGapMarker {
        &self.marker
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub struct PendingQuarantine {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    length: u64,
    fingerprint: String,
}

impl PendingQuarantine {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn device(&self) -> u64 {
        self.device
    }

    pub const fn inode(&self) -> u64 {
        self.inode
    }

    pub const fn length(&self) -> u64 {
        self.length
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl SealedSegment {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn frames(&self) -> &[SealedFrame] {
        &self.frames
    }

    pub const fn length(&self) -> u64 {
        self.length
    }
}

#[derive(Debug)]
pub struct DurableSpool {
    root: PathBuf,
    main_dir: PathBuf,
    emergency_dir: PathBuf,
    quarantine_dir: PathBuf,
    limits: SpoolLimits,
    last_watermark: u64,
}

impl DurableSpool {
    pub fn open(
        root: impl Into<PathBuf>,
        limits: SpoolLimits,
    ) -> Result<(Self, RecoveryReport), SpoolError> {
        let root = root.into();
        let limits = limits.validate()?;
        ensure_directory(&root)?;
        let main_dir = root.join("main");
        let emergency_dir = root.join("emergency");
        let quarantine_dir = root.join("quarantine");
        for path in [&main_dir, &emergency_dir, &quarantine_dir] {
            ensure_directory(path)?;
        }
        let mut spool = Self {
            root,
            main_dir,
            emergency_dir,
            quarantine_dir,
            limits,
            last_watermark: 0,
        };
        let report = spool.recover()?;
        Ok((spool, report))
    }

    pub fn open_read_only(
        root: impl Into<PathBuf>,
        limits: SpoolLimits,
    ) -> Result<Self, SpoolError> {
        let root = root.into();
        let limits = limits.validate()?;
        let spool = Self {
            main_dir: root.join("main"),
            emergency_dir: root.join("emergency"),
            quarantine_dir: root.join("quarantine"),
            root,
            limits,
            last_watermark: 0,
        };
        spool.validate_directories()?;
        Ok(spool)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn active_path(&self) -> PathBuf {
        self.main_dir.join(ACTIVE_NAME)
    }

    pub const fn last_durable_watermark(&self) -> u64 {
        self.last_watermark
    }

    pub fn append(&mut self, record: &SpoolRecord) -> Result<DurableWrite, SpoolError> {
        self.validate_directories()?;
        let directory_lock = File::open(&self.main_dir).map_err(map_io)?;
        FileExt::lock_exclusive(&directory_lock).map_err(map_io)?;
        let frame = encode_frame(record)?;
        let usage = self.main_usage()?;
        let frame_bytes = u64::try_from(frame.len()).map_err(|_| SpoolError::ResourceExhausted)?;
        let path = self.active_path();
        let active_exists = owned_file_exists(&path)?;
        if (!active_exists && usage.files >= u64::from(self.limits.max_main_files))
            || usage.bytes.saturating_add(frame_bytes) > self.limits.high_watermark_bytes
        {
            return Err(SpoolError::Pressure);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(&path)
            .map_err(map_write_error)?;
        validate_owned_file(&path, &file)?;
        file.write_all(&frame).map_err(map_write_error)?;
        file.sync_data().map_err(map_write_error)?;
        if !active_exists {
            File::open(&self.main_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(map_write_error)?;
        }
        self.last_watermark = file.metadata().map_err(map_io)?.len();
        Ok(DurableWrite {
            end_watermark: self.last_watermark,
            frame_bytes,
        })
    }

    /// Publishes one complete frame as its own claimed sealed segment without touching
    /// the ordinary active Hook segment.
    pub fn append_isolated_sealed(
        &self,
        record: &SpoolRecord,
        routing_hint: &str,
    ) -> Result<SealedSegment, SpoolError> {
        if routing_hint.is_empty()
            || routing_hint.len() > 96
            || !routing_hint
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(SpoolError::InvalidConfiguration);
        }
        self.validate_directories()?;
        let frame = encode_frame(record)?;
        let frame_bytes = u64::try_from(frame.len()).map_err(|_| SpoolError::ResourceExhausted)?;
        let directory_lock = File::open(&self.main_dir).map_err(map_io)?;
        FileExt::lock_exclusive(&directory_lock).map_err(map_io)?;
        let existing_prefix = format!("{ISOLATED_PREFIX}{routing_hint}-");
        for entry in fs::read_dir(&self.main_dir).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&existing_prefix))
            {
                return Err(SpoolError::DuplicateRecord);
            }
        }
        let usage = self.main_usage()?;
        if usage.files >= u64::from(self.limits.max_main_files)
            || usage.bytes.saturating_add(frame_bytes) > self.limits.high_watermark_bytes
        {
            return Err(SpoolError::Pressure);
        }
        let destination = unique_path(
            &self.main_dir,
            &format!("{ISOLATED_PREFIX}{routing_hint}"),
            ".sealed",
        )?;
        let publish = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .read(true)
                .mode(0o600)
                .open(&destination)
                .map_err(map_write_error)?;
            file.write_all(&frame).map_err(map_write_error)?;
            file.sync_data().map_err(map_write_error)?;
            FileExt::lock_exclusive(&file).map_err(map_io)?;
            File::open(&self.main_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(map_write_error)?;
            let metadata = file.metadata().map_err(map_io)?;
            Ok::<_, SpoolError>((file, metadata))
        })();
        let (file, metadata) = match publish {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_file(&destination);
                let _ = File::open(&self.main_dir).and_then(|directory| directory.sync_all());
                return Err(error);
            }
        };
        Ok(SealedSegment {
            path: destination,
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            frames: vec![SealedFrame {
                record: record.clone(),
                byte_start: 0,
                byte_end: frame_bytes,
            }],
        })
    }

    pub fn read_active(&self) -> Result<Vec<DecodedFrame>, SpoolError> {
        let directory_lock = File::open(&self.main_dir).map_err(map_io)?;
        FileExt::lock_shared(&directory_lock).map_err(map_io)?;
        let path = self.active_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = read_owned_file(&path)?;
                let scan = scan_frames(&bytes)?;
                if scan.incomplete_tail {
                    return Err(SpoolError::Corrupt);
                }
                Ok(scan.frames)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(map_io(error)),
        }
    }

    /// Bounded read-only lookup across active and sealed durable segments.
    pub fn find_durable_record(
        &self,
        spool_record_id: &str,
        max_segments: usize,
        max_bytes: u64,
    ) -> Result<Option<SpoolRecord>, SpoolError> {
        if spool_record_id.is_empty() {
            return Err(SpoolError::InvalidConfiguration);
        }
        let mut found = None;
        for record in self.read_durable_records(max_segments, max_bytes)? {
            if record.spool_record_id == spool_record_id {
                if found.is_some() {
                    return Err(SpoolError::DuplicateRecord);
                }
                found = Some(record);
            }
        }
        Ok(found)
    }

    /// Bounded read-only scan used for typed recovery successor replay.
    pub fn read_durable_records(
        &self,
        max_segments: usize,
        max_bytes: u64,
    ) -> Result<Vec<SpoolRecord>, SpoolError> {
        let mut records = Vec::new();
        self.visit_durable_records(max_segments, max_bytes, |record| {
            records.push(record.clone());
            Ok(())
        })?;
        Ok(records)
    }

    /// Bounded intersection of durable spool CAS references with a caller-owned candidate set.
    pub fn durable_cas_refs_intersect(
        &self,
        candidates: &BTreeSet<String>,
        max_segments: usize,
        max_bytes: u64,
    ) -> Result<BTreeSet<String>, SpoolError> {
        let mut retained = BTreeSet::new();
        self.visit_durable_records(max_segments, max_bytes, |record| {
            let (body, _) = decode_validated_record_body(record)?;
            if candidates.contains(&body.cas_ref) {
                retained.insert(body.cas_ref);
            }
            Ok(())
        })?;
        Ok(retained)
    }

    fn visit_durable_records(
        &self,
        max_segments: usize,
        max_bytes: u64,
        mut visit: impl FnMut(&SpoolRecord) -> Result<(), SpoolError>,
    ) -> Result<(), SpoolError> {
        if max_segments == 0 || max_bytes == 0 {
            return Err(SpoolError::InvalidConfiguration);
        }
        self.validate_directories()?;
        let directory_lock = File::open(&self.main_dir).map_err(map_io)?;
        FileExt::lock_shared(&directory_lock).map_err(map_io)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.main_dir).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(map_io)?;
            validate_owned_file_metadata(&metadata)?;
            let is_active = entry.file_name() == ACTIVE_NAME;
            if !is_active && path.extension().is_none_or(|value| value != "sealed") {
                return Err(SpoolError::Corrupt);
            }
            if paths
                .len()
                .checked_add(1)
                .is_none_or(|count| count > max_segments)
            {
                return Err(SpoolError::ResourceExhausted);
            }
            paths.push((!is_active, path, metadata));
        }
        paths.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let mut consumed = 0_u64;
        let mut record_ids = BTreeSet::new();
        for (_, path, metadata) in paths {
            let length = metadata.len();
            let next_consumed = consumed
                .checked_add(length)
                .filter(|value| *value <= max_bytes)
                .ok_or(SpoolError::ResourceExhausted)?;
            let remaining = max_bytes
                .checked_sub(consumed)
                .ok_or(SpoolError::ResourceExhausted)?;
            let bytes = read_owned_file_exact(&path, &metadata, remaining)?;
            consumed = next_consumed;
            let scan = scan_frames(&bytes)?;
            if scan.incomplete_tail || scan.complete_length != length {
                return Err(SpoolError::Corrupt);
            }
            for frame in scan.frames {
                if !record_ids.insert(frame.record.spool_record_id.clone()) {
                    return Err(SpoolError::DuplicateRecord);
                }
                visit(&frame.record)?;
            }
        }
        Ok(())
    }

    pub fn seal_active(&mut self, generation: u64) -> Result<Option<PathBuf>, SpoolError> {
        let directory_lock = File::open(&self.main_dir).map_err(map_io)?;
        FileExt::lock_exclusive(&directory_lock).map_err(map_io)?;
        let active = self.active_path();
        let metadata = match fs::symlink_metadata(&active) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(map_io(error)),
        };
        if metadata.len() == 0 {
            return Ok(None);
        }
        let destination = unique_path(&self.main_dir, &format!("segment-{generation}"), ".sealed")?;
        fs::rename(&active, &destination).map_err(map_io)?;
        File::open(&self.main_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(map_io)?;
        self.last_watermark = 0;
        Ok(Some(destination))
    }

    pub fn sealed_segments(&self, limit: usize) -> Result<Vec<SealedSegment>, SpoolError> {
        self.claimed_segments(limit, false)
    }

    pub fn isolated_segments(&self, limit: usize) -> Result<Vec<SealedSegment>, SpoolError> {
        self.claimed_segments(limit, true)
    }

    fn claimed_segments(
        &self,
        limit: usize,
        isolated: bool,
    ) -> Result<Vec<SealedSegment>, SpoolError> {
        let configured_limit = usize::try_from(self.limits.max_main_files)
            .map_err(|_| SpoolError::InvalidConfiguration)?;
        if limit == 0 || limit > configured_limit.max(64) {
            return Err(SpoolError::InvalidConfiguration);
        }
        self.validate_directories()?;
        let directory_lock = File::open(&self.main_dir).map_err(map_io)?;
        FileExt::lock_shared(&directory_lock).map_err(map_io)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.main_dir).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            let path = entry.path();
            if entry.file_name() == ACTIVE_NAME {
                continue;
            }
            let is_isolated = entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(ISOLATED_PREFIX));
            if is_isolated != isolated {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(map_io)?;
            validate_owned_file_metadata(&metadata)?;
            if path.extension().is_none_or(|value| value != "sealed") {
                return Err(SpoolError::Corrupt);
            }
            paths.push(path);
        }
        paths.sort();
        let mut segments = Vec::with_capacity(paths.len());
        for path in paths {
            if segments.len() == limit {
                break;
            }
            let before = fs::symlink_metadata(&path).map_err(map_io)?;
            validate_owned_file_metadata(&before)?;
            if before.len() == 0 || before.len() > self.limits.high_watermark_bytes {
                return Err(SpoolError::Corrupt);
            }
            let mut file = File::open(&path).map_err(map_io)?;
            validate_owned_file(&path, &file)?;
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(map_io(error)),
            }
            let opened = file.metadata().map_err(map_io)?;
            let capacity =
                usize::try_from(opened.len()).map_err(|_| SpoolError::ResourceExhausted)?;
            let mut bytes = Vec::with_capacity(capacity);
            file.read_to_end(&mut bytes).map_err(map_io)?;
            let scan = scan_frames(&bytes)?;
            if scan.incomplete_tail
                || scan.complete_length != opened.len()
                || scan.frames.is_empty()
            {
                return Err(SpoolError::Corrupt);
            }
            let mut offset = 0_u64;
            let frames = scan
                .frames
                .into_iter()
                .map(|frame| {
                    let start = offset;
                    offset = offset
                        .checked_add(frame.frame_length)
                        .ok_or(SpoolError::ResourceExhausted)?;
                    Ok(SealedFrame {
                        record: frame.record,
                        byte_start: start,
                        byte_end: offset,
                    })
                })
                .collect::<Result<Vec<_>, SpoolError>>()?;
            if offset != opened.len() {
                return Err(SpoolError::Corrupt);
            }
            segments.push(SealedSegment {
                path,
                file,
                device: opened.dev(),
                inode: opened.ino(),
                length: opened.len(),
                frames,
            });
        }
        Ok(segments)
    }

    pub fn acknowledge_segment(
        &self,
        segment: SealedSegment,
        committed_frames: usize,
    ) -> Result<(), SpoolError> {
        if committed_frames != segment.frames.len() || committed_frames == 0 {
            return Err(SpoolError::InvalidAcknowledgement);
        }
        let directory_lock = File::open(&self.main_dir).map_err(map_io)?;
        FileExt::lock_exclusive(&directory_lock).map_err(map_io)?;
        let path_metadata = fs::symlink_metadata(&segment.path).map_err(map_io)?;
        validate_owned_file_metadata(&path_metadata)?;
        let opened = segment.file.metadata().map_err(map_io)?;
        if path_metadata.dev() != segment.device
            || path_metadata.ino() != segment.inode
            || opened.dev() != segment.device
            || opened.ino() != segment.inode
            || opened.len() != segment.length
        {
            return Err(SpoolError::IdentityChanged);
        }
        fs::remove_file(&segment.path).map_err(map_io)?;
        File::open(&self.main_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(map_io)
    }

    pub fn recover(&mut self) -> Result<RecoveryReport, SpoolError> {
        self.validate_directories()?;
        let directory_lock = File::open(&self.main_dir).map_err(map_io)?;
        FileExt::lock_exclusive(&directory_lock).map_err(map_io)?;
        let mut report = RecoveryReport::default();
        let mut sealed = Vec::new();
        for entry in fs::read_dir(&self.main_dir).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            let path = entry.path();
            if entry.file_name() == ACTIVE_NAME {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(map_io)?;
            validate_owned_file_metadata(&metadata)?;
            if path.extension().is_none_or(|value| value != "sealed") {
                return Err(SpoolError::Corrupt);
            }
            sealed.push(path);
        }
        sealed.sort();
        for path in sealed {
            let bytes = read_owned_file(&path)?;
            let invalid = match scan_frames(&bytes) {
                Ok(scan) => scan.incomplete_tail || scan.frames.is_empty(),
                Err(_) => true,
            };
            if invalid {
                self.quarantine(&path)?;
            }
        }
        let active = self.active_path();
        match fs::symlink_metadata(&active) {
            Ok(metadata) => {
                validate_owned_file_metadata(&metadata)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&active)
                    .map_err(map_io)?;
                validate_owned_file(&active, &file)?;
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).map_err(map_io)?;
                match scan_frames(&bytes) {
                    Ok(scan) if scan.incomplete_tail => {
                        let old = bytes.len() as u64;
                        file.set_len(scan.complete_length).map_err(map_io)?;
                        file.seek(SeekFrom::Start(scan.complete_length))
                            .map_err(map_io)?;
                        file.sync_data().map_err(map_io)?;
                        report.repaired_tail_bytes = old.saturating_sub(scan.complete_length);
                        self.last_watermark = scan.complete_length;
                    }
                    Ok(scan) => self.last_watermark = scan.complete_length,
                    Err(_) => {
                        drop(file);
                        self.quarantine(&active)?;
                        self.last_watermark = 0;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
        }
        report.gaps = self.quarantine_evidence()?;
        Ok(report)
    }

    pub fn write_gap_marker(&self, marker: &CaptureGapMarker) -> Result<PathBuf, SpoolError> {
        validate_marker(marker)?;
        validate_directory(&self.root)?;
        validate_directory(&self.emergency_dir)?;
        let body = encode_marker_body(marker)?;
        let mut digest = Sha256::new();
        digest.update(b"evertrace.capture.gap.v1");
        digest.update(&body);
        let checksum: [u8; 32] = digest.finalize().into();
        let mut encoded = Vec::with_capacity(2 + 4 + body.len() + checksum.len());
        encoded.extend_from_slice(&MARKER_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&body);
        encoded.extend_from_slice(&checksum);
        for slot in 0..self.limits.emergency_slots {
            let path = self.emergency_dir.join(format!("slot-{slot:02}.marker"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(&encoded).map_err(map_write_error)?;
                    file.sync_all().map_err(map_write_error)?;
                    File::open(&self.emergency_dir)
                        .and_then(|dir| dir.sync_all())
                        .map_err(map_io)?;
                    return Ok(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(map_write_error(error)),
            }
        }
        Err(SpoolError::EmergencyExhausted)
    }

    pub fn acknowledge_gap_marker(&self, marker_id: &str) -> Result<bool, SpoolError> {
        if let Some(handle) = self
            .pending_gap_marker_handles(self.limits.emergency_slots as usize)?
            .into_iter()
            .find(|handle| handle.marker.marker_id == marker_id)
        {
            self.acknowledge_gap_marker_handle(handle)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn pending_gap_marker_handles(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingGapMarker>, SpoolError> {
        if limit == 0 || limit > self.limits.emergency_slots as usize {
            return Err(SpoolError::InvalidConfiguration);
        }
        self.validate_directories()?;
        let directory_lock = File::open(&self.emergency_dir).map_err(map_io)?;
        FileExt::lock_shared(&directory_lock).map_err(map_io)?;
        let mut handles = Vec::new();
        for slot in 0..self.limits.emergency_slots {
            if handles.len() == limit {
                break;
            }
            let path = self.emergency_dir.join(format!("slot-{slot:02}.marker"));
            let mut file = match File::open(&path) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(map_io(error)),
            };
            validate_owned_file(&path, &file)?;
            let metadata = file.metadata().map_err(map_io)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(map_io)?;
            handles.push(PendingGapMarker {
                marker: decode_marker(&bytes)?,
                path,
                file,
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
            });
        }
        Ok(handles)
    }

    pub fn acknowledge_gap_marker_handle(
        &self,
        mut handle: PendingGapMarker,
    ) -> Result<(), SpoolError> {
        let directory_lock = File::open(&self.emergency_dir).map_err(map_io)?;
        FileExt::lock_exclusive(&directory_lock).map_err(map_io)?;
        validate_ack_identity(
            &handle.path,
            &handle.file,
            handle.device,
            handle.inode,
            handle.length,
        )?;
        handle.file.seek(SeekFrom::Start(0)).map_err(map_io)?;
        let mut bytes = Vec::new();
        handle.file.read_to_end(&mut bytes).map_err(map_io)?;
        if decode_marker(&bytes)? != handle.marker {
            return Err(SpoolError::IdentityChanged);
        }
        fs::remove_file(&handle.path).map_err(map_io)?;
        File::open(&self.emergency_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(map_io)
    }

    pub fn pending_quarantine(&self, limit: usize) -> Result<Vec<PendingQuarantine>, SpoolError> {
        self.pending_quarantine_from(limit, 0)
    }

    pub fn pending_quarantine_from(
        &self,
        limit: usize,
        stable_start: u64,
    ) -> Result<Vec<PendingQuarantine>, SpoolError> {
        if limit == 0 || limit > 64 {
            return Err(SpoolError::InvalidConfiguration);
        }
        self.validate_directories()?;
        let directory_lock = File::open(&self.quarantine_dir).map_err(map_io)?;
        FileExt::lock_shared(&directory_lock).map_err(map_io)?;
        let mut paths = fs::read_dir(&self.quarantine_dir)
            .map_err(map_io)?
            .map(|entry| entry.map(|value| value.path()).map_err(map_io))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        if !paths.is_empty() {
            let path_count = u64::try_from(paths.len()).map_err(|_| SpoolError::Corrupt)?;
            let start =
                usize::try_from(stable_start % path_count).map_err(|_| SpoolError::Corrupt)?;
            paths.rotate_left(start);
        }
        paths.truncate(limit);
        let mut handles = Vec::new();
        for path in paths {
            if path.extension().is_none_or(|value| value != "spool") {
                return Err(SpoolError::Corrupt);
            }
            let mut file = File::open(&path).map_err(map_io)?;
            validate_owned_file(&path, &file)?;
            let metadata = file.metadata().map_err(map_io)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(map_io)?;
            let fingerprint = hex_digest(&bytes);
            handles.push(PendingQuarantine {
                path,
                file,
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                fingerprint,
            });
        }
        Ok(handles)
    }

    pub fn acknowledge_quarantine(&self, mut handle: PendingQuarantine) -> Result<(), SpoolError> {
        let directory_lock = File::open(&self.quarantine_dir).map_err(map_io)?;
        FileExt::lock_exclusive(&directory_lock).map_err(map_io)?;
        validate_ack_identity(
            &handle.path,
            &handle.file,
            handle.device,
            handle.inode,
            handle.length,
        )?;
        handle.file.seek(SeekFrom::Start(0)).map_err(map_io)?;
        let mut bytes = Vec::new();
        handle.file.read_to_end(&mut bytes).map_err(map_io)?;
        if hex_digest(&bytes) != handle.fingerprint {
            return Err(SpoolError::IdentityChanged);
        }
        fs::remove_file(&handle.path).map_err(map_io)?;
        File::open(&self.quarantine_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(map_io)
    }

    pub fn pending_gap_markers(&self) -> Result<Vec<CaptureGapMarker>, SpoolError> {
        let mut markers = Vec::new();
        for slot in 0..self.limits.emergency_slots {
            let path = self.emergency_dir.join(format!("slot-{slot:02}.marker"));
            match fs::read(path) {
                Ok(bytes) => markers.push(decode_marker(&bytes)?),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(map_io(error)),
            }
        }
        Ok(markers)
    }

    pub fn below_low_watermark(&self) -> Result<bool, SpoolError> {
        let usage = self.main_usage()?;
        let active_exists = owned_file_exists(&self.active_path())?;
        Ok(usage.bytes <= self.limits.low_watermark_bytes
            && (active_exists || usage.files < u64::from(self.limits.max_main_files))
            && self.pending_gap_markers()?.is_empty()
            && self.quarantine_evidence()?.is_empty())
    }

    fn quarantine(&self, source: &Path) -> Result<PathBuf, SpoolError> {
        let destination = unique_path(&self.quarantine_dir, "corrupt", ".spool")?;
        fs::rename(source, &destination).map_err(map_io)?;
        File::open(&self.main_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(map_io)?;
        File::open(&self.quarantine_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(map_io)?;
        Ok(destination)
    }

    fn validate_directories(&self) -> Result<(), SpoolError> {
        for path in [
            &self.root,
            &self.main_dir,
            &self.emergency_dir,
            &self.quarantine_dir,
        ] {
            validate_directory(path)?;
        }
        Ok(())
    }

    fn main_usage(&self) -> Result<Usage, SpoolError> {
        let mut usage = Usage::default();
        for entry in fs::read_dir(&self.main_dir).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(map_io)?;
            validate_owned_file_metadata(&metadata)?;
            usage.files += 1;
            usage.bytes = usage.bytes.saturating_add(metadata.len());
        }
        Ok(usage)
    }

    fn quarantine_evidence(&self) -> Result<Vec<GapEvidence>, SpoolError> {
        let mut gaps = Vec::new();
        for entry in fs::read_dir(&self.quarantine_dir).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(map_io)?;
            validate_owned_file_metadata(&metadata)?;
            if path.extension().is_none_or(|value| value != "spool") {
                return Err(SpoolError::Corrupt);
            }
            let file = File::open(&path).map_err(map_io)?;
            validate_owned_file(&path, &file)?;
            gaps.push(GapEvidence {
                quarantined_file: path,
                reason: GapReason::CorruptSegment,
            });
        }
        gaps.sort_by(|left, right| left.quarantined_file.cmp(&right.quarantined_file));
        Ok(gaps)
    }
}

#[derive(Default)]
struct Usage {
    bytes: u64,
    files: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SpoolError {
    #[error("spool configuration is invalid")]
    InvalidConfiguration,
    #[error("spool frame failed validation")]
    Frame,
    #[error("spool is under pressure")]
    Pressure,
    #[error("spool is unavailable")]
    Unavailable,
    #[error("emergency control segment is exhausted")]
    EmergencyExhausted,
    #[error("spool resource limit was exceeded")]
    ResourceExhausted,
    #[error("spool segment acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("spool segment identity changed during acknowledgement")]
    IdentityChanged,
    #[error("spool contains duplicate record IDs")]
    DuplicateRecord,
    #[error("spool path has an invalid type")]
    InvalidType,
    #[error("spool path has the wrong owner")]
    WrongOwner,
    #[error("spool path permissions are invalid")]
    InvalidPermissions,
    #[error("spool is corrupt")]
    Corrupt,
    #[error("spool serialization failed")]
    Serialization,
    #[error("spool operation failed")]
    Io,
}

impl From<SpoolFrameError> for SpoolError {
    fn from(value: SpoolFrameError) -> Self {
        match value {
            SpoolFrameError::Oversize => Self::ResourceExhausted,
            SpoolFrameError::Corrupt => Self::Corrupt,
            SpoolFrameError::Invalid
            | SpoolFrameError::Serialization
            | SpoolFrameError::LegacyUnsupported => Self::Frame,
        }
    }
}

fn ensure_directory(path: &Path) -> Result<(), SpoolError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(path).map_err(map_io)?;
            validate_directory(path)
        }
        Err(error) => Err(map_io(error)),
    }
}

fn validate_directory(path: &Path) -> Result<(), SpoolError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SpoolError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(SpoolError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(SpoolError::InvalidPermissions);
    }
    Ok(())
}

fn validate_owned_file(path: &Path, file: &File) -> Result<(), SpoolError> {
    let before = fs::symlink_metadata(path).map_err(map_io)?;
    let opened = file.metadata().map_err(map_io)?;
    validate_owned_file_metadata(&before)?;
    validate_owned_file_metadata(&opened)?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(SpoolError::Corrupt);
    }
    Ok(())
}

fn validate_owned_file_metadata(metadata: &fs::Metadata) -> Result<(), SpoolError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SpoolError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(SpoolError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(SpoolError::InvalidPermissions);
    }
    Ok(())
}

fn validate_ack_identity(
    path: &Path,
    file: &File,
    device: u64,
    inode: u64,
    length: u64,
) -> Result<(), SpoolError> {
    let path_metadata = fs::symlink_metadata(path).map_err(map_io)?;
    let opened = file.metadata().map_err(map_io)?;
    validate_owned_file_metadata(&path_metadata)?;
    validate_owned_file_metadata(&opened)?;
    if path_metadata.dev() != device
        || path_metadata.ino() != inode
        || path_metadata.len() != length
        || opened.dev() != device
        || opened.ino() != inode
        || opened.len() != length
    {
        return Err(SpoolError::IdentityChanged);
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn owned_file_exists(path: &Path) -> Result<bool, SpoolError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_owned_file_metadata(&metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(map_io(error)),
    }
}

fn read_owned_file(path: &Path) -> Result<Vec<u8>, SpoolError> {
    let mut file = File::open(path).map_err(map_io)?;
    validate_owned_file(path, &file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(map_io)?;
    Ok(bytes)
}

fn read_owned_file_exact(
    path: &Path,
    expected: &fs::Metadata,
    remaining: u64,
) -> Result<Vec<u8>, SpoolError> {
    validate_owned_file_metadata(expected)?;
    let expected_length = expected.len();
    if expected_length > remaining {
        return Err(SpoolError::ResourceExhausted);
    }
    let mut file = File::open(path).map_err(map_io)?;
    validate_ack_identity(path, &file, expected.dev(), expected.ino(), expected_length)?;
    let read_limit = expected_length.saturating_add(1).min(remaining);
    let capacity = usize::try_from(expected_length.min(read_limit))
        .map_err(|_| SpoolError::ResourceExhausted)?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if u64::try_from(bytes.len()).map_err(|_| SpoolError::ResourceExhausted)? != expected_length {
        return Err(SpoolError::Corrupt);
    }
    validate_ack_identity(path, &file, expected.dev(), expected.ino(), expected_length)?;
    Ok(bytes)
}

fn validate_marker(marker: &CaptureGapMarker) -> Result<(), SpoolError> {
    if marker.marker_id.is_empty()
        || marker.source_ref.is_empty()
        || marker.session_ref.is_empty()
        || marker.redacted_fingerprint.len() != 64
        || !marker
            .redacted_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SpoolError::Frame);
    }
    Ok(())
}

fn decode_marker(bytes: &[u8]) -> Result<CaptureGapMarker, SpoolError> {
    if bytes.len() < 2 + 4 + 32 || u16::from_be_bytes([bytes[0], bytes[1]]) != MARKER_VERSION {
        return Err(SpoolError::Corrupt);
    }
    let length =
        u32::from_be_bytes(bytes[2..6].try_into().map_err(|_| SpoolError::Corrupt)?) as usize;
    if bytes.len() != 6 + length + 32 {
        return Err(SpoolError::Corrupt);
    }
    let body = &bytes[6..6 + length];
    let mut digest = Sha256::new();
    digest.update(b"evertrace.capture.gap.v1");
    digest.update(body);
    if &bytes[6 + length..] != digest.finalize().as_slice() {
        return Err(SpoolError::Corrupt);
    }
    let marker = decode_marker_body(body)?;
    validate_marker(&marker)?;
    Ok(marker)
}

fn encode_marker_body(marker: &CaptureGapMarker) -> Result<Vec<u8>, SpoolError> {
    let mut body = Vec::new();
    put_marker_string(&mut body, &marker.marker_id)?;
    put_marker_string(&mut body, &marker.source_ref)?;
    put_marker_string(&mut body, &marker.session_ref)?;
    put_optional_marker_string(&mut body, marker.turn_ref.as_deref())?;
    put_optional_marker_string(&mut body, marker.tool_ref.as_deref())?;
    body.push(match marker.failure_reason {
        GapReason::MainPressure => 0,
        GapReason::MainUnavailable => 1,
        GapReason::CorruptSegment => 2,
        GapReason::RecoveryUnavailable => 3,
    });
    body.extend_from_slice(marker.redacted_fingerprint.as_bytes());
    body.extend_from_slice(&marker.attempted_bytes.to_be_bytes());
    body.extend_from_slice(&marker.last_durable_watermark.to_be_bytes());
    Ok(body)
}

fn decode_marker_body(body: &[u8]) -> Result<CaptureGapMarker, SpoolError> {
    let mut cursor = MarkerCursor { remaining: body };
    let marker_id = cursor.string()?;
    let source_ref = cursor.string()?;
    let session_ref = cursor.string()?;
    let turn_ref = cursor.optional_string()?;
    let tool_ref = cursor.optional_string()?;
    let failure_reason = match cursor.byte()? {
        0 => GapReason::MainPressure,
        1 => GapReason::MainUnavailable,
        2 => GapReason::CorruptSegment,
        3 => GapReason::RecoveryUnavailable,
        _ => return Err(SpoolError::Corrupt),
    };
    let redacted_fingerprint = std::str::from_utf8(cursor.take(64)?)
        .map_err(|_| SpoolError::Corrupt)?
        .to_owned();
    let attempted_bytes = cursor.u64()?;
    let last_durable_watermark = cursor.u64()?;
    if !cursor.remaining.is_empty() {
        return Err(SpoolError::Corrupt);
    }
    Ok(CaptureGapMarker {
        marker_id,
        source_ref,
        session_ref,
        turn_ref,
        tool_ref,
        failure_reason,
        redacted_fingerprint,
        attempted_bytes,
        last_durable_watermark,
    })
}

fn put_marker_string(output: &mut Vec<u8>, value: &str) -> Result<(), SpoolError> {
    let length = u16::try_from(value.len()).map_err(|_| SpoolError::Serialization)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_optional_marker_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), SpoolError> {
    match value {
        Some(value) => {
            output.push(1);
            put_marker_string(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

struct MarkerCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> MarkerCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], SpoolError> {
        if self.remaining.len() < length {
            return Err(SpoolError::Corrupt);
        }
        let (value, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, SpoolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SpoolError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| SpoolError::Corrupt)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, SpoolError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| SpoolError::Corrupt)?,
        ))
    }

    fn string(&mut self) -> Result<String, SpoolError> {
        let length = self.u16()? as usize;
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| SpoolError::Corrupt)
    }

    fn optional_string(&mut self) -> Result<Option<String>, SpoolError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.string().map(Some),
            _ => Err(SpoolError::Corrupt),
        }
    }
}

fn unique_path(directory: &Path, stem: &str, suffix: &str) -> Result<PathBuf, SpoolError> {
    for index in 0..1024_u32 {
        let path = directory.join(format!("{stem}-{index:04}{suffix}"));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(SpoolError::ResourceExhausted)
}

fn current_uid() -> Result<u32, SpoolError> {
    fs::metadata("/proc/self")
        .map(|value| value.uid())
        .map_err(map_io)
}

fn map_write_error(error: io::Error) -> SpoolError {
    if matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
    ) {
        SpoolError::Unavailable
    } else {
        map_io(error)
    }
}

fn map_io(_: io::Error) -> SpoolError {
    SpoolError::Io
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

    fn test_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "evertrace-spool-exact-reader-{}-{}",
            std::process::id(),
            NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700).create(&root).unwrap();
        root
    }

    fn write_owned(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn exact_reader_rejects_growth_and_path_identity_replacement() {
        let root = test_root();
        let path = root.join("segment.sealed");
        write_owned(&path, b"abc");
        let expected = fs::symlink_metadata(&path).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"d")
            .unwrap();
        assert!(matches!(
            read_owned_file_exact(&path, &expected, 4),
            Err(SpoolError::Corrupt | SpoolError::IdentityChanged)
        ));

        fs::remove_file(&path).unwrap();
        write_owned(&path, b"abc");
        let expected = fs::symlink_metadata(&path).unwrap();
        fs::rename(&path, root.join("displaced.sealed")).unwrap();
        write_owned(&path, b"abc");
        assert_eq!(
            read_owned_file_exact(&path, &expected, 4),
            Err(SpoolError::IdentityChanged)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
