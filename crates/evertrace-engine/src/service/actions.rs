use std::{collections::BTreeSet, path::Path};

use evertrace_capture::{CaptureOutcome, CaptureRecordInput, CaptureRuntime, RuntimeSnapshot};
use evertrace_codex::binding::CanonicalBindingCall;
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, InstructionAuthority, ObservationRole,
        SourceInstanceId, SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
        source_observation_id,
    },
    ids::{AtomId, CommandId, CoreMembershipId, ProcedureId, RequestId},
    query::{
        FacetParseStatus, LifecycleBoundary, Polarity, QuantityConstraint, QueryFacetSet,
        RetrievalBudget, RetrievalCompleteness, SearchContext, SearchIntent, SuppressionSnapshot,
        TemporalMode,
    },
    recall::{
        RecallAgentResponse, RecallLedgerEvent, RecallObligationState, RetrievalOutcomeState,
    },
};
use evertrace_domain::{
    revision::RevisionId,
    semantic::{
        AtomProposalPayload, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalTargetId, ProposalTargetKind,
    },
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload, ObjectDeletionCurrentView, ObjectRow,
    ObjectRowClass, ObjectRowKind, ProjectionSnapshot, SearchIndex, SemanticCurrentView,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    EvidenceIngestor, WriterActorError, WriterHandle,
    search::ProductionSearch,
    semantic::{
        ProposalCommandContext, ProposalResolution, RevisionProposalService, SubmitProposalRequest,
    },
};

use super::{
    McpBindingAuthority, McpBindingError, McpQueryAnchor, McpResolvedScope, McpScopeMechanism,
    scope::resolve_query_anchor,
};

mod read;
mod write;

struct McpRequestScope {
    binding: McpResolvedScope,
    anchor: McpQueryAnchor,
    snapshot: ProjectionSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpServiceAction {
    Search,
    Get,
    Add,
    Organize,
}

impl McpServiceAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::Get => "get",
            Self::Add => "add",
            Self::Organize => "organize",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpServiceStatus {
    Ok,
    NoMatch,
    NoRecallNeeded,
    Partial,
    DegradedIndex,
    ScopeUnresolved,
    Conflict,
    InvalidInput,
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpServiceItem {
    pub partition: McpItemPartition,
    pub kind: String,
    pub object_ref: Option<String>,
    pub object_revision_ref: Option<String>,
    pub source_revision_ref: Option<String>,
    pub scope: Option<String>,
    pub applicability: Option<String>,
    pub authority: Option<String>,
    pub content_trust: ContentTrust,
    pub capture_completeness: Option<String>,
    pub instruction_authority: InstructionAuthority,
    pub text: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpItemPartition {
    NormativeConstraint,
    Procedure,
    Evidence,
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpServiceResult {
    pub request_id: RequestId,
    pub status: McpServiceStatus,
    pub scope: String,
    pub freshness: String,
    pub completeness: String,
    pub items: Vec<McpServiceItem>,
    pub warnings: Vec<String>,
    pub truncated: bool,
    pub next_refs: Vec<String>,
}

pub struct McpServiceRequest {
    pub request_id: RequestId,
    pub action: McpServiceAction,
    pub workspace: String,
    pub input: String,
    pub refs: Vec<String>,
    pub client_cwd: String,
}

#[derive(Debug, Error)]
pub enum McpServiceError {
    #[error("MCP service store failed")]
    Store,
}

#[derive(Clone)]
pub struct McpActionService {
    bindings: McpBindingAuthority,
    search_index: SearchIndex,
    writer: WriterHandle,
    runtime_snapshot: RuntimeSnapshot,
}

impl McpActionService {
    pub async fn open(
        bindings: McpBindingAuthority,
        data_dir: &Path,
        writer: WriterHandle,
        runtime_snapshot: RuntimeSnapshot,
    ) -> Result<Self, McpServiceError> {
        let search_index = SearchIndex::open(data_dir)
            .await
            .map_err(|_| McpServiceError::Store)?;
        Ok(Self::new(bindings, search_index, writer, runtime_snapshot))
    }

    pub fn new(
        bindings: McpBindingAuthority,
        search_index: SearchIndex,
        writer: WriterHandle,
        runtime_snapshot: RuntimeSnapshot,
    ) -> Self {
        Self {
            bindings,
            search_index,
            writer,
            runtime_snapshot,
        }
    }

    pub async fn handle(
        &self,
        connection_id: &str,
        request: McpServiceRequest,
    ) -> Result<McpServiceResult, McpServiceError> {
        let McpServiceRequest {
            request_id,
            action,
            workspace,
            input,
            refs,
            client_cwd,
        } = request;
        let call = CanonicalBindingCall {
            action: action.as_str().into(),
            workspace,
            input: input.clone(),
            refs: refs.clone(),
        };
        if call.validate_transport().is_err() {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::InvalidInput,
                "unresolved",
                "unknown",
                ["invalid_call"],
            ));
        }
        if self
            .bindings
            .pin_client_cwd(connection_id, &client_cwd)
            .is_err()
        {
            return Ok(scope_unresolved(request_id));
        }
        let binding = match self.bindings.resolve(&call) {
            Ok(scope) => scope,
            Err(McpBindingError::ScopeUnresolved) => return Ok(scope_unresolved(request_id)),
        };
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| McpServiceError::Store)?;
        let Some(anchor) = resolve_query_anchor(&snapshot, &binding, &client_cwd) else {
            return Ok(scope_unresolved(request_id));
        };
        let scope = McpRequestScope {
            binding,
            anchor,
            snapshot,
        };
        match action {
            McpServiceAction::Search => self.search(request_id, scope, input).await,
            McpServiceAction::Get => self.get(request_id, scope, input).await,
            McpServiceAction::Add => self.add(request_id, scope, input, refs).await,
            McpServiceAction::Organize => self.organize(request_id, scope, input, refs).await,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OrganizeInput {
    v: u32,
    op: String,
    target: String,
    expected_revision: Option<String>,
    patch: Value,
    reason: String,
}

#[derive(Serialize)]
struct AddResultDetails {
    authorization_status: &'static str,
    proposal_created: bool,
}

#[derive(Serialize)]
struct OrganizeResultDetails<'a> {
    target: &'a str,
    operation: &'static str,
    status: &'static str,
}

fn organize_target(
    target: &str,
    operation: ProposalOperation,
) -> Option<(ProposalTargetKind, Option<ProposalTargetId>)> {
    if target == "new" && operation == ProposalOperation::Create {
        return Some((ProposalTargetKind::Atom, None));
    }
    if operation == ProposalOperation::Create {
        return None;
    }
    target
        .parse::<AtomId>()
        .map(|id| (ProposalTargetKind::Atom, Some(ProposalTargetId::Atom(id))))
        .or_else(|_| {
            target.parse::<ProcedureId>().map(|id| {
                (
                    ProposalTargetKind::Procedure,
                    Some(ProposalTargetId::Procedure(id)),
                )
            })
        })
        .or_else(|_| {
            target.parse::<CoreMembershipId>().map(|id| {
                (
                    ProposalTargetKind::CoreMembership,
                    Some(ProposalTargetId::CoreMembership(id)),
                )
            })
        })
        .ok()
}

fn proposal_payload(
    target: ProposalTargetKind,
    operation: ProposalOperation,
    mut patch: Value,
    reason: String,
) -> Option<ProposalPayload> {
    if reason.is_empty() || reason.len() > 4_096 || reason.chars().any(char::is_control) {
        return None;
    }
    if target != ProposalTargetKind::Atom {
        let summary = serde_json::to_string(&serde_json::json!({
            "patch": patch,
            "reason": reason
        }))
        .ok()?;
        if summary.len() > 2_048 {
            return None;
        }
        return Some(ProposalPayload::ReservedTarget {
            schema_version: 1,
            summary,
        });
    }
    if operation == ProposalOperation::Deprecate {
        return Some(ProposalPayload::Atom(Box::new(
            AtomProposalPayload::Deprecate { reason },
        )));
    }
    let object = patch.as_object_mut()?;
    object.insert("operation".into(), Value::String(operation.as_str().into()));
    serde_json::from_value::<AtomProposalPayload>(patch)
        .ok()
        .map(Box::new)
        .map(ProposalPayload::Atom)
}

fn contains_protected_patch_key(value: &Value) -> bool {
    const PROTECTED: &[&str] = &[
        "authority",
        "user_authorization_provenance",
        "policy_authority_provenance",
        "trust",
        "authorized_scope_ceiling",
        "acceptance",
        "acceptance_event",
        "reviewer",
        "reviewer_identity",
    ];
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            PROTECTED.contains(&key.as_str()) || contains_protected_patch_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_protected_patch_key),
        _ => false,
    }
}

fn select_object_row<'a>(
    snapshot: &'a ProjectionSnapshot,
    identifier: &str,
) -> Result<Option<(&'a ObjectRow, bool)>, ()> {
    let eligible = |row: &&ObjectRow| {
        row.row_kind == ObjectRowKind::Data && row.row_class == Some(ObjectRowClass::Object)
    };
    let mut exact = snapshot
        .rows
        .iter()
        .filter(eligible)
        .filter(|row| row.current_revision_id.as_deref() == Some(identifier));
    if let Some(row) = exact.next() {
        if exact.next().is_some() {
            return Err(());
        }
        let object_id = row.object_id.as_deref().ok_or(())?;
        let current = current_object_row(snapshot, object_id)?.ok_or(())?;
        return Ok(Some((row, current == row)));
    }
    Ok(current_object_row(snapshot, identifier)?.map(|row| (row, true)))
}

fn current_object_row<'a>(
    snapshot: &'a ProjectionSnapshot,
    object_id: &str,
) -> Result<Option<&'a ObjectRow>, ()> {
    let mut rows = snapshot.rows.iter().filter(|row| {
        row.row_kind == ObjectRowKind::Data
            && row.row_class == Some(ObjectRowClass::Object)
            && row.object_id.as_deref() == Some(object_id)
    });
    let Some(mut current) = rows.next() else {
        return Ok(None);
    };
    if current.object_id.is_none() || current.current_revision_id.is_none() {
        return Err(());
    }
    let mut tied = false;
    for row in rows {
        if row.object_id.is_none() || row.current_revision_id.is_none() {
            return Err(());
        }
        match row.source_event_seq.cmp(&current.source_event_seq) {
            std::cmp::Ordering::Greater => {
                current = row;
                tied = false;
            }
            std::cmp::Ordering::Equal => tied = true,
            std::cmp::Ordering::Less => {}
        }
    }
    (!tied).then_some(Some(current)).ok_or(())
}

fn classify_object_row(
    row: &ObjectRow,
    text: Option<String>,
    is_current: bool,
    now: i64,
) -> McpServiceItem {
    let payload = row
        .payload_json
        .as_deref()
        .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok());
    let (partition, content_trust, applicability, authority) = match payload.as_ref() {
        Some(JournalPayload::AtomRecorded(atom)) => {
            let interval_current = atom.validity_interval.contains(now);
            let applicability = match atom.applicability_expr {
                evertrace_domain::semantic::ApplicabilityExpr::Always if interval_current => "true",
                evertrace_domain::semantic::ApplicabilityExpr::Always => "false",
                _ => "unknown",
            };
            let normative = is_current && normative_eligible(atom, now);
            let trust = match atom.authority {
                evertrace_domain::semantic::AtomAuthority::UserExplicit => {
                    ContentTrust::UserStatement
                }
                evertrace_domain::semantic::AtomAuthority::ProjectPolicy
                | evertrace_domain::semantic::AtomAuthority::ObjectiveEvidence => {
                    ContentTrust::Observed
                }
                evertrace_domain::semantic::AtomAuthority::AgentInferred => {
                    ContentTrust::AgentClaim
                }
                evertrace_domain::semantic::AtomAuthority::ImportedClaim => {
                    ContentTrust::ImportedClaim
                }
            };
            (
                if normative {
                    McpItemPartition::NormativeConstraint
                } else {
                    McpItemPartition::Evidence
                },
                trust,
                Some(applicability.into()),
                Some(atom.authority.as_str().to_owned()),
            )
        }
        Some(JournalPayload::SourceObservationRecorded(observation)) => (
            McpItemPartition::Evidence,
            observation.content_trust,
            None,
            None,
        ),
        Some(JournalPayload::EvidenceSurfaceRecorded(surface)) => (
            McpItemPartition::Evidence,
            surface.content_trust,
            None,
            None,
        ),
        Some(JournalPayload::SourceReceiptRecorded(_)) => (
            McpItemPartition::Evidence,
            ContentTrust::Observed,
            None,
            None,
        ),
        Some(JournalPayload::RevisionProposalRecorded(_)) => (
            McpItemPartition::Evidence,
            ContentTrust::AgentClaim,
            None,
            Some("agent_inferred".into()),
        ),
        _ => (
            McpItemPartition::Evidence,
            ContentTrust::Observed,
            None,
            row.authority.clone(),
        ),
    };
    let scope = row
        .task_id
        .clone()
        .or_else(|| row.worktree_id.clone())
        .or_else(|| row.repository_id.clone());
    McpServiceItem {
        partition,
        kind: row.object_kind.clone().unwrap_or_else(|| "object".into()),
        object_ref: row.object_id.clone(),
        object_revision_ref: row.current_revision_id.clone(),
        source_revision_ref: match payload.as_ref() {
            Some(JournalPayload::SourceObservationRecorded(value)) => {
                Some(value.source_revision.as_str().to_owned())
            }
            Some(JournalPayload::SourceReceiptRecorded(value)) => {
                Some(value.source_revision.as_str().to_owned())
            }
            Some(JournalPayload::EvidenceSurfaceRecorded(value)) => {
                Some(value.source_observation_revision_ref.to_string())
            }
            _ => None,
        },
        scope,
        applicability,
        authority,
        content_trust,
        capture_completeness: match payload.as_ref() {
            Some(JournalPayload::SourceObservationRecorded(value)) => {
                Some(capture_completeness(value.capture_completeness))
            }
            Some(JournalPayload::SourceReceiptRecorded(value)) => {
                Some(capture_completeness(value.capture_completeness))
            }
            Some(JournalPayload::EvidenceSurfaceRecorded(value)) => {
                Some(capture_completeness(value.capture_completeness))
            }
            _ => None,
        },
        instruction_authority: InstructionAuthority::None,
        text,
    }
}

fn capture_completeness(value: CaptureCompleteness) -> String {
    match value {
        CaptureCompleteness::Complete => "complete",
        CaptureCompleteness::Partial => "partial",
        CaptureCompleteness::Opaque => "opaque",
    }
    .into()
}

fn task_membership_matches(
    memberships: &[evertrace_domain::work::TaskScopeMembership],
    repository_id: Option<evertrace_domain::ids::RepositoryId>,
    worktree_id: Option<evertrace_domain::ids::WorktreeId>,
) -> bool {
    if repository_id.is_none() && worktree_id.is_none() {
        return true;
    }
    memberships.iter().any(|membership| {
        repository_id.is_none_or(|id| {
            membership.repository_instance_id == Some(id)
                && worktree_id
                    .is_none_or(|worktree| membership.worktree_instance_ids.contains(&worktree))
        })
    })
}

fn normative_eligible(atom: &evertrace_domain::semantic::Atom, now: i64) -> bool {
    atom.validate().is_ok()
        && atom.kind.is_normative()
        && atom.lifecycle_status == evertrace_domain::semantic::AtomLifecycleStatus::Active
        && atom.authority == evertrace_domain::semantic::AtomAuthority::UserExplicit
        && matches!(
            atom.applicability_expr,
            evertrace_domain::semantic::ApplicabilityExpr::Always
        )
        && atom.validity_interval.contains(now)
}

fn invalid_organize(
    request_id: RequestId,
    scope: &McpRequestScope,
    reason: &'static str,
) -> McpServiceResult {
    empty_result(
        request_id,
        McpServiceStatus::InvalidInput,
        &scope_label(scope),
        "unknown",
        [reason],
    )
}

fn unresolved_add(request_id: RequestId, scope: &McpRequestScope) -> McpServiceResult {
    empty_result(
        request_id,
        McpServiceStatus::ScopeUnresolved,
        &scope_label(scope),
        "unknown",
        ["exact_task_binding_required"],
    )
}

fn unix_time_us_for_mcp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .unwrap_or(0)
}

fn empty_result<const N: usize>(
    request_id: RequestId,
    status: McpServiceStatus,
    scope: &str,
    completeness: &str,
    warnings: [&str; N],
) -> McpServiceResult {
    McpServiceResult {
        request_id,
        status,
        scope: scope.into(),
        freshness: "unknown".into(),
        completeness: completeness.into(),
        items: Vec::new(),
        warnings: warnings.into_iter().map(str::to_owned).collect(),
        truncated: false,
        next_refs: Vec::new(),
    }
}

fn scope_label(scope: &McpRequestScope) -> String {
    scope.binding.workspace.canonical()
}

fn scope_unresolved(request_id: RequestId) -> McpServiceResult {
    empty_result(
        request_id,
        McpServiceStatus::ScopeUnresolved,
        "unresolved",
        "unknown",
        ["scope_unresolved"],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_constraint_atom() -> evertrace_domain::semantic::Atom {
        use evertrace_domain::semantic::{
            Atom, AtomAuthority, AtomKind, AtomLifecycleStatus, AtomProvenance, AtomScope,
            AtomValue, EpistemicStatus, UserAuthorizationMode, UserAuthorizationProvenance,
            ValidityInterval,
        };

        let observation = evertrace_domain::evidence::source_observation_id(
            &SourceInstanceId::parse("source-actions-test").unwrap(),
            &SourceRevision::parse("revision-actions-test").unwrap(),
            &SourceRecordIdentity::parse("record-actions-test").unwrap(),
        )
        .unwrap();
        let scope = AtomScope::Task {
            task_id: evertrace_domain::ids::TaskId::new_v7(),
        };
        let value = AtomValue {
            text: "current user constraint".into(),
            subject: "workspace".into(),
            predicate: "requires".into(),
            object: Some("review".into()),
            qualifiers: Vec::new(),
            critical_revision_refs: Vec::new(),
        };
        let exact_value_hash = value.exact_hash().unwrap();
        Atom {
            atom_id: AtomId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            kind: AtomKind::Constraint,
            epistemic_status: EpistemicStatus::NotApplicable,
            lifecycle_status: AtomLifecycleStatus::Active,
            authority: AtomAuthority::UserExplicit,
            value,
            scope: scope.clone(),
            condition_ir_version: 1,
            applicability_expr: evertrace_domain::semantic::ApplicabilityExpr::Always,
            future_cue_lifecycle_exprs: None,
            validity_interval: ValidityInterval {
                valid_from_us: 0,
                valid_until_us: Some(i64::MAX),
            },
            provenance: vec![AtomProvenance::UserAsserted],
            user_authorization_provenance: Some(UserAuthorizationProvenance {
                mode: UserAuthorizationMode::CurrentTaskExactMessage,
                user_source_observation_ref: observation,
                source_message_hash: [7; 32],
                exact_value_hash,
                authorized_scope_ceiling: scope,
                acceptance_event_ref: None,
            }),
            policy_authority_provenance: None,
            source_observation_refs: vec![observation],
            evidence_refs: vec![observation.to_string()],
            supersedes_revision_refs: Vec::new(),
            supports_revision_refs: Vec::new(),
            contradicts_revision_refs: Vec::new(),
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 1,
        }
    }

    fn atom_row(atom: &evertrace_domain::semantic::Atom, sequence: u64) -> ObjectRow {
        ObjectRow {
            row_id: format!("atom:{}", atom.revision_id),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Object),
            object_family: Some(evertrace_store::ObjectFamily::Atom),
            object_kind: Some("atom_revision".into()),
            object_id: Some(atom.atom_id.to_string()),
            current_revision_id: Some(atom.revision_id.to_string()),
            lifecycle: Some(atom.lifecycle_status.as_str().into()),
            epistemic: Some(atom.epistemic_status.as_str().into()),
            authority: Some(atom.authority.as_str().into()),
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: atom.scope.task_id().map(|id| id.to_string()),
            workstream_id: None,
            session_id: None,
            payload_json: Some(
                serde_json::to_string(&JournalPayload::AtomRecorded(Box::new(atom.clone())))
                    .unwrap(),
            ),
            source_event_seq: sequence,
            projection_generation: 0,
        }
    }

    #[test]
    fn reserved_organize_payload_preserves_the_complete_canonical_patch() {
        let patch = serde_json::json!({"steps":["one","two"],"title":"procedure"});
        let payload = proposal_payload(
            ProposalTargetKind::Procedure,
            ProposalOperation::Replace,
            patch.clone(),
            "reason".into(),
        )
        .unwrap();
        let ProposalPayload::ReservedTarget { summary, .. } = payload else {
            panic!("reserved target expected")
        };
        let decoded: Value = serde_json::from_str(&summary).unwrap();
        assert_eq!(decoded["patch"], patch);
        assert_eq!(decoded["reason"], "reason");
        assert!(contains_protected_patch_key(&serde_json::json!({
            "nested": {"authority": "project_policy"}
        })));
    }

    #[test]
    fn non_repository_task_requires_no_synthetic_membership_for_add() {
        assert!(task_membership_matches(&[], None, None));
        assert!(!task_membership_matches(
            &[],
            Some(evertrace_domain::ids::RepositoryId::new_v7()),
            None
        ));
    }

    #[test]
    fn normative_validity_uses_the_domain_half_open_interval_boundary() {
        let interval = evertrace_domain::semantic::ValidityInterval {
            valid_from_us: 10,
            valid_until_us: Some(20),
        };
        assert!(interval.contains(10));
        assert!(interval.contains(19));
        assert!(!interval.contains(20));
    }

    #[test]
    fn stable_object_selection_and_classifier_distinguish_current_from_history() {
        let current = user_constraint_atom();
        assert!(current.validate().is_ok());
        let mut historical = current.clone();
        historical.revision_id = RevisionId::new_v7();
        historical.created_at_us = 0;
        let historical_row = atom_row(&historical, 10);
        let current_row = atom_row(&current, 20);
        let snapshot = ProjectionSnapshot {
            frontier: 20,
            rows: vec![historical_row.clone(), current_row.clone()],
        };

        let (stable, stable_is_current) =
            select_object_row(&snapshot, &current.atom_id.to_string())
                .unwrap()
                .unwrap();
        assert_eq!(stable.current_revision_id, current_row.current_revision_id);
        assert!(stable_is_current);
        let (old, old_is_current) =
            select_object_row(&snapshot, &historical.revision_id.to_string())
                .unwrap()
                .unwrap();
        assert_eq!(old.current_revision_id, historical_row.current_revision_id);
        assert!(!old_is_current);
        assert_eq!(
            classify_object_row(stable, None, true, unix_time_us_for_mcp()).partition,
            McpItemPartition::NormativeConstraint
        );
        assert_eq!(
            classify_object_row(old, None, false, unix_time_us_for_mcp()).partition,
            McpItemPartition::Evidence
        );

        let mut tied = current_row;
        tied.current_revision_id = Some(RevisionId::new_v7().to_string());
        tied.row_id.push_str(":tie");
        let ambiguous = ProjectionSnapshot {
            frontier: 20,
            rows: vec![historical_row, tied.clone(), atom_row(&current, 20)],
        };
        assert!(select_object_row(&ambiguous, &current.atom_id.to_string()).is_err());
    }

    #[test]
    fn normative_classifier_fails_closed_for_every_unproved_axis() {
        let current = user_constraint_atom();
        let row = atom_row(&current, 1);
        let now = unix_time_us_for_mcp();
        assert_eq!(
            classify_object_row(&row, None, true, now).partition,
            McpItemPartition::NormativeConstraint
        );

        let mut cases = Vec::new();
        let mut policy = current.clone();
        policy.authority = evertrace_domain::semantic::AtomAuthority::ProjectPolicy;
        cases.push(policy);
        let mut conditional = current.clone();
        conditional.applicability_expr = evertrace_domain::semantic::ApplicabilityExpr::Constraint(
            evertrace_domain::semantic::ConstraintExpr::Exists {
                field: evertrace_domain::semantic::ConstraintField::Phase,
            },
        );
        cases.push(conditional);
        let mut expired = current.clone();
        expired.validity_interval.valid_until_us = Some(1);
        cases.push(expired);
        let mut invalid = current.clone();
        invalid
            .user_authorization_provenance
            .as_mut()
            .unwrap()
            .exact_value_hash = [0; 32];
        cases.push(invalid);
        for atom in cases {
            assert_eq!(
                classify_object_row(&atom_row(&atom, 1), None, true, now).partition,
                McpItemPartition::Evidence
            );
        }
        assert_eq!(
            classify_object_row(&row, None, false, now).partition,
            McpItemPartition::Evidence
        );
    }
}
