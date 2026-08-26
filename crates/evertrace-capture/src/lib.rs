#![forbid(unsafe_code)]
#![deny(warnings)]

//! Secret-safe capture, device-local keys, filesystem CAS, and durable spool.

pub mod admission;
pub mod cas;
pub mod frame;
pub mod key;
pub mod protect;
pub mod runtime_snapshot;
pub mod spool;

pub use admission::{
    CaptureAdmissionState, CaptureError, CaptureOutcome, CaptureRecordInput, CaptureRuntime,
};
pub use cas::{CasDigest, CasError, CasStore};
pub use frame::{
    CAPTURE_RECORD_BODY_VERSION, CaptureRecordBody, DecodedFrame, FrameScan, SpoolFrameError,
    SpoolRecord, decode_record_body, encode_frame, encode_record_body, scan_frames,
};
pub use key::{DeviceKey, DeviceKeyError, DeviceKeyStore};
pub use protect::{
    ArchiveMode, ProtectError, ProtectedPayload, RedactionSpan, SecretKind, protect,
};
pub use runtime_snapshot::{RUNTIME_SNAPSHOT_VERSION, RuntimeSnapshot, RuntimeSnapshotError};
pub use spool::{
    CaptureGapMarker, DurableSpool, GapEvidence, GapReason, RecoveryReport, SealedFrame,
    SealedSegment, SpoolError, SpoolLimits,
};
