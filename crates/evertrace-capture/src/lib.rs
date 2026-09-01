#![forbid(unsafe_code)]
#![deny(warnings)]

//! Secret-safe capture, device-local keys, filesystem CAS, and durable spool.

pub mod admission;
pub mod cas;
pub mod confined_read;
pub mod frame;
pub mod key;
pub mod protect;
pub mod runtime_snapshot;
pub mod spool;

pub use admission::{
    CaptureAdmissionState, CaptureError, CaptureOutcome, CaptureRecordInput, CaptureRuntime,
    DurableRecoveryPreflight, IsolatedCaptureOutcome,
};
pub use cas::{
    CasDeleteOutcome, CasDigest, CasError, CasStore, MaintenanceFence, MaintenanceGuard,
};
pub use confined_read::{
    ConfinedDirectoryEntry, ConfinedEntryType, ConfinedFile, ConfinedFileIdentity,
    ConfinedFileMetadata, ConfinedFileRange, ConfinedLimitKind, ConfinedReadError,
    ConfinedReadLimits, ConfinedRoot,
};
pub use frame::{
    CAPTURE_RECORD_BODY_VERSION, CaptureRecordBody, DecodedFrame, FrameScan,
    RecoveryPreflightCandidate, SpoolFrameError, SpoolRecord, decode_record_body,
    decode_validated_record_body, encode_frame, encode_record_body, scan_frames,
};
pub use key::{DeviceKey, DeviceKeyError, DeviceKeyStore};
pub use protect::{
    ArchiveMode, ProtectError, ProtectedPayload, RedactionSpan, SecretKind, mcp_call_auth_tag,
    protect, recovery_content_token, recovery_path_token, recovery_ticket_auth_tag,
    verify_mcp_call_auth_tag, verify_recovery_ticket_auth_tag,
};
pub use runtime_snapshot::{
    RUNTIME_SNAPSHOT_VERSION, RecallCueGateMode, RecoveryGateMode, RecoverySnapshotSettings,
    RuntimeSnapshot, RuntimeSnapshotError,
};
pub use spool::{
    CaptureGapMarker, DurableSpool, GapEvidence, GapReason, PendingGapMarker, PendingQuarantine,
    RecoveryReport, SealedFrame, SealedSegment, SpoolError, SpoolLimits,
};
