use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
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
    pub episode_id: WorkEpisodeId,
    pub episode_revision_id: RevisionId,
    pub task_id: TaskId,
    pub repository_id: Option<RepositoryId>,
    pub worktree_id: Option<WorktreeId>,
    pub from_watermark: u64,
    pub to_watermark: u64,
    pub episode_source_watermark: u64,
    pub episode_confirmation_watermark: u64,
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
}

impl SemanticDigest {
    pub fn validate(&self) -> Result<(), SemanticError> {
        self.application.validate()?;
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
            || self.to_watermark != self.episode_source_watermark
            || self.episode_confirmation_watermark > self.episode_source_watermark
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
        job_fingerprint(
            self.episode_id,
            self.episode_revision_id,
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
    pub episode_id: WorkEpisodeId,
    pub episode_revision_id: RevisionId,
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
}

impl SemanticDerivationRun {
    pub fn validate(&self) -> Result<(), SemanticError> {
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
        if job_fingerprint(
            self.episode_id,
            self.episode_revision_id,
            self.from_watermark,
            self.to_watermark,
            &self.selected_direct_refs,
            &self.model_id,
            &self.prompt_hash,
            self.schema_version,
            &self.algorithm_revision,
            &self.effective_config_hash,
        )? != self.job_fingerprint
        {
            return Err(SemanticError::InvalidProposal);
        }
        Ok(())
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
