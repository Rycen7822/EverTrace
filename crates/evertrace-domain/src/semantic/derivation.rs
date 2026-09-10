use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    evidence::{SourceInstanceId, SourceRevision},
    ids::{
        AtomId, CasId, ProcedureId, RepositoryId, SemanticDerivationRunId, SemanticDigestId,
        TaskId, WikiProjectionId, WorkEpisodeId, WorktreeId,
    },
    revision::RevisionId,
};

use super::{AtomProposalPayload, ProcedureProposalPayload, SemanticError};

const MAX_REFS: usize = 256;
const MAX_ITEMS: usize = 64;
const MAX_TEXT: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDigestTrigger {
    PhaseTransition,
    StrategyPivot,
    VerifierTransition,
    AdoptedDecision,
    ExperimentTerminal,
    BudgetBackstop,
    EpisodeFinalization,
    SourceMessages,
}

/// An archived source's confirmed scope, not a synthetic Work identity.
/// Digest/Run from/to watermarks are source_sequence (after, through] for this
/// target, never journal or Episode watermarks.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticSourceTarget {
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub repository_id: RepositoryId,
    pub worktree_id: WorktreeId,
}

impl SemanticSourceTarget {
    pub fn validate(&self) -> Result<(), SemanticError> {
        SourceInstanceId::parse(self.source_instance_id.as_str())
            .and_then(|_| SourceRevision::parse(self.source_revision.as_str()))
            .map(|_| ())
            .map_err(|_| SemanticError::InvalidProposal)
    }

    pub fn contains_message(
        &self,
        receipt: &crate::evidence::SourceReceipt,
        observation: &crate::evidence::SourceObservation,
        after_sequence: u64,
        through_sequence: u64,
    ) -> bool {
        receipt.source_kind == crate::evidence::EvidenceSourceKind::CodexSessionJsonl
            && receipt.observation_role == crate::evidence::ObservationRole::Message
            && receipt.unsupported_record_classification.is_none()
            && receipt.source_instance_id == self.source_instance_id
            && receipt.source_revision == self.source_revision
            && receipt.repository_instance_id == Some(self.repository_id)
            && receipt.worktree_instance_id == Some(self.worktree_id)
            && receipt.source_sequence > after_sequence
            && receipt.source_sequence <= through_sequence
            && observation.source_receipt_ref == receipt.source_receipt_id
            && observation.source_observation_id == receipt.source_observation_id
            && observation.source_instance_id == receipt.source_instance_id
            && observation.source_revision == receipt.source_revision
            && observation.source_record_identity == receipt.source_record_identity
            && observation.observation_role == receipt.observation_role
    }
}

/// One closed codec for scheduler admission, execution, recovery and purge.
/// Existing Episode targets remain bare revision IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticJobTarget {
    Episode(RevisionId),
    Source {
        first_observation_id: crate::ids::SourceObservationId,
        last_observation_id: crate::ids::SourceObservationId,
    },
}

impl SemanticJobTarget {
    pub fn encode(&self) -> Result<String, SemanticError> {
        match self {
            Self::Episode(revision) => Ok(revision.to_string()),
            Self::Source {
                first_observation_id,
                last_observation_id,
            } => Ok(format!(
                "source:v1:{first_observation_id}/{last_observation_id}"
            )),
        }
    }

    pub fn parse(value: &str) -> Result<Self, SemanticError> {
        if value.len() > 256 {
            return Err(SemanticError::InvalidProposal);
        }
        let target = if let Some(value) = value.strip_prefix("source:v1:") {
            let (first, last) = value
                .split_once('/')
                .ok_or(SemanticError::InvalidProposal)?;
            Self::Source {
                first_observation_id: first.parse().map_err(|_| SemanticError::InvalidProposal)?,
                last_observation_id: last.parse().map_err(|_| SemanticError::InvalidProposal)?,
            }
        } else {
            Self::Episode(value.parse().map_err(|_| SemanticError::InvalidProposal)?)
        };
        if target.encode()? != value {
            return Err(SemanticError::InvalidProposal);
        }
        Ok(target)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDigestStatus {
    DeterministicOnly,
    LlmEnriched,
    RejectedInvalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCompleteness {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticStructuredDelta {
    pub label: String,
    pub value: String,
    pub direct_refs: Vec<String>,
}

impl SemanticStructuredDelta {
    fn validate(&self) -> bool {
        valid_text(&self.label) && valid_text(&self.value) && valid_refs(&self.direct_refs, false)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticOmission {
    pub category: String,
    pub reason: String,
    pub direct_refs: Vec<String>,
}

impl SemanticOmission {
    fn validate(&self) -> bool {
        valid_text(&self.category)
            && valid_text(&self.reason)
            && valid_refs(&self.direct_refs, true)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticCandidate {
    ScenarioPatch {
        scenario_revision_id: RevisionId,
        task_id: TaskId,
        repository_id: Option<RepositoryId>,
        worktree_id: Option<WorktreeId>,
        current_state_delta: Vec<String>,
        open_loop_delta: Vec<String>,
        outcome_delta: Vec<String>,
    },
    AtomProposal {
        target_id: Option<AtomId>,
        base_revision_id: Option<RevisionId>,
        payload: Box<AtomProposalPayload>,
    },
    ProcedureProposal {
        target_id: Option<ProcedureId>,
        base_revision_id: Option<RevisionId>,
        payload: Box<ProcedureProposalPayload>,
    },
}

impl SemanticCandidate {
    pub fn validate(&self) -> Result<(), SemanticError> {
        match self {
            Self::ScenarioPatch {
                repository_id,
                worktree_id,
                current_state_delta,
                open_loop_delta,
                outcome_delta,
                ..
            } => {
                if worktree_id.is_some() && repository_id.is_none()
                    || !valid_refs(current_state_delta, true)
                    || !valid_refs(open_loop_delta, true)
                    || !valid_refs(outcome_delta, true)
                {
                    return Err(SemanticError::InvalidProposal);
                }
            }
            Self::AtomProposal {
                target_id,
                base_revision_id,
                payload,
            } => {
                payload.validate()?;
                if payload.operation() == super::ProposalOperation::Create
                    && (target_id.is_some() || base_revision_id.is_some())
                    || payload.operation() != super::ProposalOperation::Create
                        && (target_id.is_none() || base_revision_id.is_none())
                {
                    return Err(SemanticError::InvalidProposal);
                }
            }
            Self::ProcedureProposal {
                target_id,
                base_revision_id,
                payload,
            } => {
                payload
                    .draft()
                    .validate()
                    .map_err(|_| SemanticError::InvalidProposal)?;
                if payload.operation() == super::ProposalOperation::Create
                    && (target_id.is_some() || base_revision_id.is_some())
                    || payload.operation() != super::ProposalOperation::Create
                        && (target_id.is_none() || base_revision_id.is_none())
                {
                    return Err(SemanticError::InvalidProposal);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDigestApplication {
    pub progress_delta: Vec<SemanticStructuredDelta>,
    pub decision_delta: Vec<SemanticStructuredDelta>,
    pub failed_routes: Vec<SemanticStructuredDelta>,
    pub resolved_items: Vec<SemanticStructuredDelta>,
    pub open_loops: Vec<SemanticStructuredDelta>,
    pub outcome_delta: Vec<SemanticStructuredDelta>,
    pub omissions: Vec<SemanticOmission>,
    pub candidates: Vec<SemanticCandidate>,
    pub completeness: SemanticCompleteness,
}

impl SemanticDigestApplication {
    pub fn validate(&self) -> Result<(), SemanticError> {
        for values in [
            &self.progress_delta,
            &self.decision_delta,
            &self.failed_routes,
            &self.resolved_items,
            &self.open_loops,
            &self.outcome_delta,
        ] {
            if values.len() > MAX_ITEMS || !values.iter().all(SemanticStructuredDelta::validate) {
                return Err(SemanticError::InvalidProposal);
            }
        }
        if self.omissions.len() > MAX_ITEMS
            || !self.omissions.iter().all(SemanticOmission::validate)
            || self.candidates.len() > 8
        {
            return Err(SemanticError::InvalidProposal);
        }
        for candidate in &self.candidates {
            candidate.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDigest {
    pub semantic_digest_id: SemanticDigestId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode_id: Option<WorkEpisodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode_revision_id: Option<RevisionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    pub repository_id: Option<RepositoryId>,
    pub worktree_id: Option<WorktreeId>,
    pub from_watermark: u64,
    pub to_watermark: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode_source_watermark: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode_confirmation_watermark: Option<u64>,
    pub trigger: SemanticDigestTrigger,
    pub selected_direct_refs: Vec<String>,
    pub application: SemanticDigestApplication,
    pub model_id: String,
    pub prompt_hash: [u8; 32],
    pub schema_version: u32,
    pub algorithm_revision: String,
    pub effective_config_hash: [u8; 32],
    pub job_fingerprint: [u8; 32],
    pub status: SemanticDigestStatus,
    pub created_at_us: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_target: Option<SemanticSourceTarget>,
}

impl SemanticDigest {
    pub fn validate(&self) -> Result<(), SemanticError> {
        self.application.validate()?;
        match &self.source_target {
            Some(source) => {
                source.validate()?;
                if self.episode_id.is_some()
                    || self.episode_revision_id.is_some()
                    || self.task_id.is_some()
                    || self.episode_source_watermark.is_some()
                    || self.episode_confirmation_watermark.is_some()
                    || self.repository_id != Some(source.repository_id)
                    || self.worktree_id != Some(source.worktree_id)
                    || self.trigger != SemanticDigestTrigger::SourceMessages
                    || !self.application.candidates.is_empty()
                {
                    return Err(SemanticError::InvalidProposal);
                }
            }
            None => {
                if self.episode_id.is_none()
                    || self.episode_revision_id.is_none()
                    || self.task_id.is_none()
                    || self.episode_source_watermark != Some(self.to_watermark)
                    || self
                        .episode_confirmation_watermark
                        .is_none_or(|value| value > self.to_watermark)
                    || self.trigger == SemanticDigestTrigger::SourceMessages
                {
                    return Err(SemanticError::InvalidProposal);
                }
            }
        }
        let output_refs = [
            &self.application.progress_delta,
            &self.application.decision_delta,
            &self.application.failed_routes,
            &self.application.resolved_items,
            &self.application.open_loops,
            &self.application.outcome_delta,
        ]
        .into_iter()
        .flatten()
        .flat_map(|item| &item.direct_refs)
        .chain(
            self.application
                .omissions
                .iter()
                .flat_map(|item| &item.direct_refs),
        )
        .collect::<std::collections::BTreeSet<_>>();
        let output_refs_valid = output_refs
            == self
                .selected_direct_refs
                .iter()
                .collect::<std::collections::BTreeSet<_>>();
        if self.from_watermark >= self.to_watermark
            || self.worktree_id.is_some() && self.repository_id.is_none()
            || !valid_refs(&self.selected_direct_refs, false)
            || !output_refs_valid
            || !valid_text(&self.model_id)
            || !valid_text(&self.algorithm_revision)
            || self.schema_version == 0
            || self.created_at_us < 0
            || self.status == SemanticDigestStatus::LlmEnriched
                && self.application.completeness == SemanticCompleteness::Unknown
            || self.recompute_job_fingerprint()? != self.job_fingerprint
        {
            return Err(SemanticError::InvalidProposal);
        }
        Ok(())
    }

    pub fn recompute_job_fingerprint(&self) -> Result<[u8; 32], SemanticError> {
        if let Some(source) = &self.source_target {
            return source_job_fingerprint(
                source,
                self.from_watermark,
                self.to_watermark,
                &self.selected_direct_refs,
                &self.model_id,
                &self.prompt_hash,
                self.schema_version,
                &self.algorithm_revision,
                &self.effective_config_hash,
            );
        }
        job_fingerprint(
            self.episode_id.ok_or(SemanticError::InvalidProposal)?,
            self.episode_revision_id
                .ok_or(SemanticError::InvalidProposal)?,
            self.from_watermark,
            self.to_watermark,
            &self.selected_direct_refs,
            &self.model_id,
            &self.prompt_hash,
            self.schema_version,
            &self.algorithm_revision,
            &self.effective_config_hash,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationRunStatus {
    PlannerNotAdmitted,
    BudgetExhausted,
    ProviderUnavailable,
    ProviderFailed,
    SchemaRejected,
    Succeeded,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationQuotaUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub calls: u32,
    pub wall_time_us: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDerivationRun {
    pub derivation_run_id: SemanticDerivationRunId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode_id: Option<WorkEpisodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode_revision_id: Option<RevisionId>,
    pub from_watermark: u64,
    pub to_watermark: u64,
    pub selected_direct_refs: Vec<String>,
    pub job_fingerprint: [u8; 32],
    pub status: DerivationRunStatus,
    pub quota_usage: DerivationQuotaUsage,
    pub model_id: String,
    pub prompt_hash: [u8; 32],
    pub schema_version: u32,
    pub algorithm_revision: String,
    pub effective_config_hash: [u8; 32],
    pub created_at_us: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_target: Option<SemanticSourceTarget>,
}

impl SemanticDerivationRun {
    pub fn validate(&self) -> Result<(), SemanticError> {
        match &self.source_target {
            Some(source) if self.episode_id.is_none() && self.episode_revision_id.is_none() => {
                source.validate()?
            }
            None if self.episode_id.is_some() && self.episode_revision_id.is_some() => {}
            _ => return Err(SemanticError::InvalidProposal),
        }
        if self.from_watermark >= self.to_watermark
            || !valid_refs(&self.selected_direct_refs, false)
            || !valid_text(&self.model_id)
            || !valid_text(&self.algorithm_revision)
            || self.schema_version == 0
            || self.created_at_us < 0
            || self.status == DerivationRunStatus::Succeeded
                && (self.quota_usage.calls != 1 || self.quota_usage.wall_time_us == 0)
            || self.status != DerivationRunStatus::Succeeded && self.quota_usage.calls > 1
        {
            return Err(SemanticError::InvalidProposal);
        }
        if self.recompute_job_fingerprint()? != self.job_fingerprint {
            return Err(SemanticError::InvalidProposal);
        }
        Ok(())
    }

    pub fn recompute_job_fingerprint(&self) -> Result<[u8; 32], SemanticError> {
        if let Some(source) = &self.source_target {
            return source_job_fingerprint(
                source,
                self.from_watermark,
                self.to_watermark,
                &self.selected_direct_refs,
                &self.model_id,
                &self.prompt_hash,
                self.schema_version,
                &self.algorithm_revision,
                &self.effective_config_hash,
            );
        }
        job_fingerprint(
            self.episode_id.ok_or(SemanticError::InvalidProposal)?,
            self.episode_revision_id
                .ok_or(SemanticError::InvalidProposal)?,
            self.from_watermark,
            self.to_watermark,
            &self.selected_direct_refs,
            &self.model_id,
            &self.prompt_hash,
            self.schema_version,
            &self.algorithm_revision,
            &self.effective_config_hash,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WikiProjection {
    pub page_id: WikiProjectionId,
    pub topic: String,
    pub source_atom_ids: Vec<AtomId>,
    pub source_episode_ids: Vec<WorkEpisodeId>,
    pub compiler_version: u32,
    pub source_watermark: u64,
    pub rendered_blob_ref: CasId,
}

impl WikiProjection {
    pub fn validate(&self) -> Result<(), SemanticError> {
        let expected_page_id = WikiProjectionId::from_digest(
            sha256(
                "evertrace.wiki_projection.page",
                1,
                &CanonicalValue::String(self.topic.clone()),
            )
            .map_err(|_| SemanticError::InvalidProposal)?,
        );
        if !valid_text(&self.topic)
            || self.source_atom_ids.is_empty()
            || self.source_atom_ids.len() > MAX_REFS
            || !strictly_sorted(&self.source_atom_ids)
            || self.source_episode_ids.len() > MAX_REFS
            || !strictly_sorted(&self.source_episode_ids)
            || self.compiler_version == 0
            || self.source_watermark == 0
            || self.page_id != expected_page_id
        {
            return Err(SemanticError::InvalidProposal);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn job_fingerprint(
    episode_id: WorkEpisodeId,
    episode_revision_id: RevisionId,
    from_watermark: u64,
    to_watermark: u64,
    selected_direct_refs: &[String],
    model_id: &str,
    prompt_hash: &[u8; 32],
    schema_version: u32,
    algorithm_revision: &str,
    effective_config_hash: &[u8; 32],
) -> Result<[u8; 32], SemanticError> {
    sha256(
        "evertrace.semantic_derivation.job",
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(episode_id.to_string()),
            CanonicalValue::String(episode_revision_id.to_string()),
            CanonicalValue::Integer(i128::from(from_watermark)),
            CanonicalValue::Integer(i128::from(to_watermark)),
            CanonicalValue::Sequence(
                selected_direct_refs
                    .iter()
                    .cloned()
                    .map(CanonicalValue::String)
                    .collect(),
            ),
            CanonicalValue::String(model_id.to_owned()),
            CanonicalValue::Bytes(prompt_hash.to_vec()),
            CanonicalValue::Integer(i128::from(schema_version)),
            CanonicalValue::String(algorithm_revision.to_owned()),
            CanonicalValue::Bytes(effective_config_hash.to_vec()),
        ]),
    )
    .map_err(|_| SemanticError::InvalidProposal)
}

#[allow(clippy::too_many_arguments)]
pub fn source_job_fingerprint(
    source: &SemanticSourceTarget,
    after_sequence: u64,
    through_sequence: u64,
    selected_direct_refs: &[String],
    model_id: &str,
    prompt_hash: &[u8; 32],
    schema_version: u32,
    algorithm_revision: &str,
    effective_config_hash: &[u8; 32],
) -> Result<[u8; 32], SemanticError> {
    source.validate()?;
    sha256(
        "evertrace.semantic_derivation.source_job",
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(source.source_instance_id.as_str().into()),
            CanonicalValue::String(source.source_revision.as_str().into()),
            CanonicalValue::String(source.repository_id.to_string()),
            CanonicalValue::String(source.worktree_id.to_string()),
            CanonicalValue::Integer(i128::from(after_sequence)),
            CanonicalValue::Integer(i128::from(through_sequence)),
            CanonicalValue::Sequence(
                selected_direct_refs
                    .iter()
                    .cloned()
                    .map(CanonicalValue::String)
                    .collect(),
            ),
            CanonicalValue::String(model_id.into()),
            CanonicalValue::Bytes(prompt_hash.to_vec()),
            CanonicalValue::Integer(i128::from(schema_version)),
            CanonicalValue::String(algorithm_revision.into()),
            CanonicalValue::Bytes(effective_config_hash.to_vec()),
        ]),
    )
    .map_err(|_| SemanticError::InvalidProposal)
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

fn valid_refs(values: &[String], allow_empty: bool) -> bool {
    (allow_empty || !values.is_empty())
        && values.len() <= MAX_REFS
        && values.iter().all(|value| valid_text(value))
        && strictly_sorted(values)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
