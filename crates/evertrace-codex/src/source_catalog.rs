use crate::adapter_manifest::ObservableCapability;

pub const CODEX_ELIGIBLE_EVENT_MANIFEST: &str = "codex_host_events_v1";

pub const REQUIRED_FOR_FULL: [ObservableCapability; 4] = [
    ObservableCapability::ChildSessionId,
    ObservableCapability::ChildToolCall,
    ObservableCapability::ChildToolResult,
    ObservableCapability::ChildFinalResult,
];

pub const ELIGIBLE_CAPABILITIES: [ObservableCapability; 10] = [
    ObservableCapability::DelegationStart,
    ObservableCapability::ChildSessionId,
    ObservableCapability::ChildToolCall,
    ObservableCapability::ChildToolResult,
    ObservableCapability::ChildFileChange,
    ObservableCapability::ChildPlan,
    ObservableCapability::ChildReasoningSummary,
    ObservableCapability::ChildFinalResult,
    ObservableCapability::DelegationEnd,
    ObservableCapability::RawHiddenReasoning,
];
