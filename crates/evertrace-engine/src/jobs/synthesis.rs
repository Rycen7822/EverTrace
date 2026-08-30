use evertrace_domain::{
    config::LlmConfig,
    ids::{CommandId, SemanticDerivationRunId, SemanticDigestId},
    procedure::{ProcedureDraft, ProcedureScope},
    revision::RevisionId,
    semantic::{
        AtomDraft, AtomProposalPayload, AtomProvenance, AtomScope, DerivationQuotaUsage,
        DerivationRunStatus, EpistemicStatus, ProposalCreatedBy, ProposalEligibility,
        ProposalPayload, ProposalTargetId, ProposalTargetKind, SemanticCandidate,
        SemanticDerivationRun, SemanticDigest, SemanticDigestApplication, SemanticDigestStatus,
        SemanticDigestTrigger, ValidityInterval,
    },
    work::{EpisodeLifecycle, PendingSemanticInterval, WorkEpisode},
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload, ProjectionSnapshot, SemanticCurrentView,
};

use crate::{
    provider::{
        OpenAiCompatibleProvider, ProtectedDeltaItem, ProtectedSemanticInput,
        ProviderAtomOperation, ProviderError, ProviderProcedureOperation,
        ProviderSemanticApplication, ProviderSemanticCandidate, SEMANTIC_SCHEMA_VERSION,
        canonical_prompt_hash,
    },
    semantic::{
        ProposalCommandContext, ProposalResolution, RevisionProposalService, SubmitProposalRequest,
    },
};

const DAY_US: i64 = 86_400_000_000;

struct SnapshotRefIndex {
    kinds: std::collections::BTreeMap<String, String>,
}

impl SnapshotRefIndex {
    fn new(snapshot: &ProjectionSnapshot) -> Self {
        let mut kinds = std::collections::BTreeMap::new();
        for row in snapshot.data_rows() {
            let Some(kind) = row.object_kind.as_ref() else {
                continue;
            };
            for reference in [row.object_id.as_ref(), row.current_revision_id.as_ref()]
                .into_iter()
                .flatten()
            {
                kinds.insert(reference.clone(), kind.clone());
            }
        }
        Self { kinds }
    }

    fn direct_source(&self, reference: &str) -> bool {
        self.kinds.get(reference).is_some_and(|kind| {
            !matches!(
                kind.as_str(),
                "semantic_digest" | "semantic_derivation_run" | "scenario" | "wiki_projection"
            )
        })
    }

    fn proposal_evidence(&self, reference: &str) -> bool {
        self.kinds.get(reference).is_some_and(|kind| {
            matches!(
                kind.as_str(),
                "source_receipt"
                    | "source_observation"
                    | "result_evidence"
                    | "work_artifact"
                    | "atom_revision"
            )
        })
    }
}

pub struct SynthesisRequest<'a> {
    pub snapshot: &'a ProjectionSnapshot,
    pub episode_revision_id: RevisionId,
    pub trigger: SemanticDigestTrigger,
    pub direct_delta: Vec<ProtectedDeltaItem>,
    pub selected_direct_refs: Vec<String>,
    pub command_id: CommandId,
    pub occurred_at_us: i64,
    pub algorithm_revision: String,
    pub effective_config_hash: [u8; 32],
}

pub enum SynthesisResolution {
    NoDelta,
    Audit {
        run: SemanticDerivationRun,
        command: JournalCommand,
    },
    Success {
        digest: Box<SemanticDigest>,
        run: SemanticDerivationRun,
        episode: Box<WorkEpisode>,
        command: JournalCommand,
    },
}

pub struct SynthesisPlanner {
    llm: LlmConfig,
    provider: Option<OpenAiCompatibleProvider>,
    prompt_hash: [u8; 32],
}

impl SynthesisPlanner {
    pub fn new(llm: LlmConfig) -> Self {
        let provider = OpenAiCompatibleProvider::new(&llm).ok();
        Self {
            llm,
            provider,
            prompt_hash: canonical_prompt_hash(),
        }
    }

    pub async fn execute(
        &self,
        mut request: SynthesisRequest<'_>,
    ) -> Result<SynthesisResolution, crate::semantic::SemanticServiceError> {
        let original_ref_count = request.selected_direct_refs.len();
        let ref_index = SnapshotRefIndex::new(request.snapshot);
        request.selected_direct_refs.sort();
        request.selected_direct_refs.dedup();
        if request.selected_direct_refs.is_empty()
            || request.selected_direct_refs.len() > 256
            || request.selected_direct_refs.len() != original_ref_count
            || request.direct_delta.is_empty()
            || request.direct_delta.len() > 64
            || request.occurred_at_us < 0
            || request.direct_delta.iter().any(|item| {
                item.value.trim().is_empty()
                    || item.value.len() > 4096
                    || item.value.chars().any(char::is_control)
                    || item.direct_refs.len() > 256
                    || item.direct_refs.is_empty()
                    || !item.direct_refs.windows(2).all(|pair| pair[0] < pair[1])
                    || item.direct_refs.iter().any(|reference| {
                        request
                            .selected_direct_refs
                            .binary_search(reference)
                            .is_err()
                    })
            })
        {
            return Err(crate::semantic::SemanticServiceError::InvalidInput);
        }
        let flattened = request
            .direct_delta
            .iter()
            .flat_map(|item| item.direct_refs.iter().cloned())
            .collect::<Vec<_>>();
        let unique = flattened.iter().collect::<std::collections::BTreeSet<_>>();
        if unique.into_iter().cloned().collect::<Vec<_>>() != request.selected_direct_refs {
            return Err(crate::semantic::SemanticServiceError::InvalidInput);
        }
        if request
            .selected_direct_refs
            .iter()
            .any(|reference| !ref_index.direct_source(reference))
        {
            return Err(crate::semantic::SemanticServiceError::InvalidInput);
        }
        let episode = current_episode(request.snapshot, request.episode_revision_id)?;
        if episode.semantic_watermark >= episode.source_watermark
            || episode.pending_semantic_delta
                != Some(PendingSemanticInterval {
                    after_watermark: episode.semantic_watermark,
                    through_watermark: episode.source_watermark,
                })
            || request.trigger == SemanticDigestTrigger::EpisodeFinalization
                && episode.lifecycle_status != EpisodeLifecycle::Closed
            || request.trigger != SemanticDigestTrigger::EpisodeFinalization
                && episode.lifecycle_status != EpisodeLifecycle::Open
        {
            return Err(crate::semantic::SemanticServiceError::InvalidInput);
        }
        let fingerprint = evertrace_domain::semantic::job_fingerprint(
            episode.episode_id,
            episode.revision_id,
            episode.semantic_watermark,
            episode.source_watermark,
            &request.selected_direct_refs,
            &self.llm.model,
            &self.prompt_hash,
            SEMANTIC_SCHEMA_VERSION,
            &request.algorithm_revision,
            &request.effective_config_hash,
        )
        .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
        let prior = prior_runs(request.snapshot)?;
        if prior.iter().any(|run| {
            run.job_fingerprint == fingerprint && run.status == DerivationRunStatus::Succeeded
        }) {
            return Ok(SynthesisResolution::NoDelta);
        }
        let today = request.occurred_at_us / DAY_US;
        let daily = prior
            .iter()
            .filter(|run| run.created_at_us / DAY_US == today)
            .fold(DerivationQuotaUsage::default(), |mut total, run| {
                total.input_tokens = total
                    .input_tokens
                    .saturating_add(run.quota_usage.input_tokens);
                total.output_tokens = total
                    .output_tokens
                    .saturating_add(run.quota_usage.output_tokens);
                total.calls = total.calls.saturating_add(run.quota_usage.calls);
                total.wall_time_us = total
                    .wall_time_us
                    .saturating_add(run.quota_usage.wall_time_us);
                total
            });
        let episode_successes = prior
            .iter()
            .filter(|run| {
                run.episode_id == episode.episode_id && run.status == DerivationRunStatus::Succeeded
            })
            .count();
        let input = ProtectedSemanticInput {
            episode_id: episode.episode_id,
            episode_revision_id: episode.revision_id,
            task_id: episode.task_id,
            from_watermark: episode.semantic_watermark,
            to_watermark: episode.source_watermark,
            trigger: trigger_name(request.trigger),
            direct_delta: request.direct_delta.clone(),
            source_refs: request.selected_direct_refs.clone(),
        };
        let estimated_input = u64::try_from(
            serde_json::to_vec(&input)
                .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?
                .len()
                .div_ceil(4),
        )
        .unwrap_or(u64::MAX);
        let quota_blocked = self.llm.episode_enrichment
            == evertrace_domain::config::EpisodeEnrichment::Off
            || episode.lifecycle_status == EpisodeLifecycle::Open
                && episode_successes
                    >= usize::from(self.llm.max_episode_enrichments.saturating_sub(1))
            || episode.lifecycle_status != EpisodeLifecycle::Open
                && episode_successes >= usize::from(self.llm.max_episode_enrichments)
            || daily.calls >= self.llm.daily_call_budget
            || daily.wall_time_us
                >= self
                    .llm
                    .daily_wall_time_budget
                    .seconds()
                    .saturating_mul(1_000_000)
            || !self.llm.unlimited_token_budget
                && (daily.input_tokens.saturating_add(estimated_input)
                    > self.llm.daily_input_token_budget
                    || daily.output_tokens >= self.llm.daily_output_token_budget);
        if quota_blocked {
            return audit_resolution(
                self,
                &request,
                &episode,
                fingerprint,
                DerivationRunStatus::BudgetExhausted,
                DerivationQuotaUsage::default(),
            );
        }
        let provider = match &self.provider {
            Some(provider) => provider,
            None => {
                return audit_resolution(
                    self,
                    &request,
                    &episode,
                    fingerprint,
                    DerivationRunStatus::ProviderUnavailable,
                    DerivationQuotaUsage::default(),
                );
            }
        };
        let started = std::time::Instant::now();
        let derived = match provider.derive(&input).await {
            Ok(value) => value,
            Err(error) => {
                let status = if error == ProviderError::Schema {
                    DerivationRunStatus::SchemaRejected
                } else if matches!(
                    error,
                    ProviderError::MissingSecret | ProviderError::Disabled
                ) {
                    DerivationRunStatus::ProviderUnavailable
                } else {
                    DerivationRunStatus::ProviderFailed
                };
                let calls = u32::from(!matches!(
                    error,
                    ProviderError::MissingSecret
                        | ProviderError::Disabled
                        | ProviderError::RequestOversize
                ));
                return audit_resolution(
                    self,
                    &request,
                    &episode,
                    fingerprint,
                    status,
                    DerivationQuotaUsage {
                        calls,
                        wall_time_us: u64::try_from(started.elapsed().as_micros())
                            .unwrap_or(u64::MAX),
                        ..DerivationQuotaUsage::default()
                    },
                );
            }
        };
        if !self.llm.unlimited_token_budget
            && (daily.input_tokens.saturating_add(derived.input_tokens)
                > self.llm.daily_input_token_budget
                || daily.output_tokens.saturating_add(derived.output_tokens)
                    > self.llm.daily_output_token_budget)
            || daily.wall_time_us.saturating_add(derived.wall_time_us)
                > self
                    .llm
                    .daily_wall_time_budget
                    .seconds()
                    .saturating_mul(1_000_000)
        {
            return audit_resolution(
                self,
                &request,
                &episode,
                fingerprint,
                DerivationRunStatus::BudgetExhausted,
                DerivationQuotaUsage {
                    input_tokens: derived.input_tokens,
                    output_tokens: derived.output_tokens,
                    calls: 1,
                    wall_time_us: derived.wall_time_us,
                },
            );
        }
        let evidence_refs = request
            .selected_direct_refs
            .iter()
            .filter(|reference| ref_index.proposal_evidence(reference))
            .cloned()
            .collect::<Vec<_>>();
        let application = match materialize_application(
            derived.application,
            &episode,
            &evidence_refs,
            request.occurred_at_us,
        ) {
            Ok(value) => value,
            Err(_) => {
                return audit_resolution(
                    self,
                    &request,
                    &episode,
                    fingerprint,
                    DerivationRunStatus::SchemaRejected,
                    DerivationQuotaUsage {
                        input_tokens: derived.input_tokens,
                        output_tokens: derived.output_tokens,
                        calls: 1,
                        wall_time_us: derived.wall_time_us,
                    },
                );
            }
        };
        if validate_candidates(&application.candidates, &episode, request.snapshot).is_err() {
            return audit_resolution(
                self,
                &request,
                &episode,
                fingerprint,
                DerivationRunStatus::SchemaRejected,
                DerivationQuotaUsage {
                    input_tokens: derived.input_tokens,
                    output_tokens: derived.output_tokens,
                    calls: 1,
                    wall_time_us: derived.wall_time_us,
                },
            );
        }
        let digest_id = SemanticDigestId::new_v7();
        let digest = SemanticDigest {
            semantic_digest_id: digest_id,
            episode_id: episode.episode_id,
            episode_revision_id: episode.revision_id,
            task_id: episode.task_id,
            repository_id: episode.repository_instance_id,
            worktree_id: episode.worktree_instance_id,
            from_watermark: episode.semantic_watermark,
            to_watermark: episode.source_watermark,
            episode_source_watermark: episode.source_watermark,
            episode_confirmation_watermark: episode.confirmation_watermark,
            trigger: request.trigger,
            selected_direct_refs: request.selected_direct_refs.clone(),
            application,
            model_id: self.llm.model.clone(),
            prompt_hash: self.prompt_hash,
            schema_version: SEMANTIC_SCHEMA_VERSION,
            algorithm_revision: request.algorithm_revision.clone(),
            effective_config_hash: request.effective_config_hash,
            job_fingerprint: fingerprint,
            status: SemanticDigestStatus::LlmEnriched,
            created_at_us: request.occurred_at_us,
        };
        if digest.validate().is_err() {
            return audit_resolution(
                self,
                &request,
                &episode,
                fingerprint,
                DerivationRunStatus::SchemaRejected,
                DerivationQuotaUsage {
                    input_tokens: derived.input_tokens,
                    output_tokens: derived.output_tokens,
                    calls: 1,
                    wall_time_us: derived.wall_time_us,
                },
            );
        }
        let run = run(
            self,
            &request,
            &episode,
            fingerprint,
            DerivationRunStatus::Succeeded,
            DerivationQuotaUsage {
                input_tokens: derived.input_tokens,
                output_tokens: derived.output_tokens,
                calls: 1,
                wall_time_us: derived.wall_time_us.max(1),
            },
        );
        let mut successor = episode.clone();
        successor.revision_id = RevisionId::new_v7();
        successor.predecessor_revision_id = Some(episode.revision_id);
        successor.revision_generation = episode
            .revision_generation
            .checked_add(1)
            .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?;
        successor.semantic_watermark = episode.source_watermark;
        successor.pending_semantic_delta = None;
        successor.semantic_digest_refs.push(digest_id.to_string());
        successor.semantic_digest_refs.sort();
        episode
            .validate_successor(&successor)
            .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
        let mut payloads = proposal_payloads(&digest, request.snapshot, &request, &evidence_refs)?;
        payloads.extend([
            JournalPayload::SemanticDigestRecorded(Box::new(digest.clone())),
            JournalPayload::SemanticDerivationRunRecorded(Box::new(run.clone())),
            JournalPayload::WorkEpisodeRecorded(Box::new(successor.clone())),
        ]);
        let command = command(&request, payloads)?;
        Ok(SynthesisResolution::Success {
            digest: Box::new(digest),
            run,
            episode: Box::new(successor),
            command,
        })
    }
}

fn current_episode(
    snapshot: &ProjectionSnapshot,
    revision_id: RevisionId,
) -> Result<WorkEpisode, crate::semantic::SemanticServiceError> {
    let episodes = snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("work_episode"))
        .map(|row| {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?,
            )
            .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
            match payload {
                JournalPayload::WorkEpisodeRecorded(value) => Ok(*value),
                _ => Err(crate::semantic::SemanticServiceError::InvalidInput),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let matching = episodes
        .iter()
        .filter(|episode| episode.revision_id == revision_id)
        .collect::<Vec<_>>();
    let [episode] = matching.as_slice() else {
        return Err(crate::semantic::SemanticServiceError::ImmutableConflict);
    };
    let newer = episodes.iter().any(|candidate| {
        candidate.episode_id == episode.episode_id
            && candidate.revision_generation > episode.revision_generation
    });
    if newer {
        return Err(crate::semantic::SemanticServiceError::BaseConflict);
    }
    Ok((*episode).clone())
}

fn prior_runs(
    snapshot: &ProjectionSnapshot,
) -> Result<Vec<SemanticDerivationRun>, crate::semantic::SemanticServiceError> {
    snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("semantic_derivation_run"))
        .map(|row| {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?,
            )
            .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
            match payload {
                JournalPayload::SemanticDerivationRunRecorded(value) => Ok(*value),
                _ => Err(crate::semantic::SemanticServiceError::InvalidInput),
            }
        })
        .collect()
}

fn validate_candidates(
    candidates: &[SemanticCandidate],
    episode: &WorkEpisode,
    snapshot: &ProjectionSnapshot,
) -> Result<(), crate::semantic::SemanticServiceError> {
    if candidates.len() > 1 {
        return Err(crate::semantic::SemanticServiceError::InvalidInput);
    }
    let semantic = SemanticCurrentView::from_snapshot(snapshot)
        .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
    for candidate in candidates {
        candidate
            .validate()
            .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
        match candidate {
            SemanticCandidate::ScenarioPatch {
                scenario_revision_id,
                task_id,
                repository_id,
                worktree_id,
                ..
            } => {
                if task_id != &episode.task_id
                    || repository_id != &episode.repository_instance_id
                    || worktree_id != &episode.worktree_instance_id
                    || !snapshot.data_rows().any(|row| {
                        row.object_kind.as_deref() == Some("scenario")
                            && row.current_revision_id.as_deref()
                                == Some(&scenario_revision_id.to_string())
                    })
                {
                    return Err(crate::semantic::SemanticServiceError::InvalidInput);
                }
            }
            SemanticCandidate::AtomProposal {
                target_id,
                base_revision_id,
                payload,
            } => {
                let expected = evertrace_domain::semantic::AtomScope::Task {
                    task_id: episode.task_id,
                };
                let scopes = atom_payload_scopes(payload);
                if scopes.iter().any(|scope| scope != &&expected) {
                    return Err(crate::semantic::SemanticServiceError::InvalidInput);
                }
                if let Some(target_id) = target_id {
                    let current = semantic
                        .atoms
                        .get(target_id)
                        .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?;
                    if Some(current.revision_id) != *base_revision_id || current.scope != expected {
                        return Err(crate::semantic::SemanticServiceError::InvalidInput);
                    }
                }
            }
            SemanticCandidate::ProcedureProposal {
                target_id,
                base_revision_id,
                payload,
            } => {
                let expected = match (episode.repository_instance_id, episode.worktree_instance_id)
                {
                    (Some(repository_id), Some(worktree_id)) => {
                        evertrace_domain::procedure::ProcedureScope::Worktree {
                            repository_id,
                            worktree_id,
                        }
                    }
                    (Some(repository_id), None) => {
                        evertrace_domain::procedure::ProcedureScope::Repository { repository_id }
                    }
                    _ => return Err(crate::semantic::SemanticServiceError::InvalidInput),
                };
                if payload.draft().scope != expected {
                    return Err(crate::semantic::SemanticServiceError::InvalidInput);
                }
                if let Some(target_id) = target_id {
                    let mut current = snapshot.data_rows().filter_map(|row| {
                        let payload: JournalPayload =
                            serde_json::from_str(row.payload_json.as_deref()?).ok()?;
                        let JournalPayload::ProcedureRevisionRecorded(value) = payload else {
                            return None;
                        };
                        (value.procedure_id == *target_id).then_some(*value)
                    });
                    let Some(first) = current.next() else {
                        return Err(crate::semantic::SemanticServiceError::InvalidInput);
                    };
                    let latest = current.try_fold(first, |selected, candidate| {
                        if candidate.revision_generation == selected.revision_generation {
                            Err(crate::semantic::SemanticServiceError::ImmutableConflict)
                        } else if candidate.revision_generation > selected.revision_generation {
                            Ok(candidate)
                        } else {
                            Ok(selected)
                        }
                    })?;
                    if Some(latest.revision_id) != *base_revision_id
                        || latest.draft.scope != expected
                    {
                        return Err(crate::semantic::SemanticServiceError::BaseConflict);
                    }
                }
            }
        }
    }
    Ok(())
}

fn materialize_application(
    provider: ProviderSemanticApplication,
    episode: &WorkEpisode,
    evidence_refs: &[String],
    occurred_at_us: i64,
) -> Result<SemanticDigestApplication, crate::semantic::SemanticServiceError> {
    if provider.candidates.len() > 1 || !provider.candidates.is_empty() && evidence_refs.is_empty()
    {
        return Err(crate::semantic::SemanticServiceError::InvalidInput);
    }
    let candidates = provider
        .candidates
        .into_iter()
        .map(|candidate| match candidate {
            ProviderSemanticCandidate::ScenarioPatch {
                scenario_revision_id,
                current_state_delta,
                open_loop_delta,
                outcome_delta,
            } => Ok(SemanticCandidate::ScenarioPatch {
                scenario_revision_id,
                task_id: episode.task_id,
                repository_id: episode.repository_instance_id,
                worktree_id: episode.worktree_instance_id,
                current_state_delta,
                open_loop_delta,
                outcome_delta,
            }),
            ProviderSemanticCandidate::AtomCandidate {
                operation,
                target_id,
                base_revision_id,
                atom_kind,
                value,
                applicability_expr,
            } => {
                let draft = AtomDraft {
                    kind: atom_kind,
                    epistemic_status: if atom_kind.is_normative() {
                        EpistemicStatus::NotApplicable
                    } else {
                        EpistemicStatus::Unverified
                    },
                    value: value.into(),
                    scope: AtomScope::Task {
                        task_id: episode.task_id,
                    },
                    applicability_expr,
                    future_cue_lifecycle_exprs: None,
                    validity_interval: ValidityInterval {
                        valid_from_us: occurred_at_us,
                        valid_until_us: None,
                    },
                    provenance: vec![AtomProvenance::LlmDerived],
                    source_observation_refs: Vec::new(),
                    evidence_refs: evidence_refs.to_vec(),
                    supersedes_revision_refs: Vec::new(),
                    supports_revision_refs: Vec::new(),
                    contradicts_revision_refs: Vec::new(),
                };
                let payload = match operation {
                    ProviderAtomOperation::Create => AtomProposalPayload::Create { draft },
                    ProviderAtomOperation::Replace => AtomProposalPayload::Replace { draft },
                    ProviderAtomOperation::Reclassify => AtomProposalPayload::Reclassify { draft },
                };
                Ok(SemanticCandidate::AtomProposal {
                    target_id,
                    base_revision_id,
                    payload: Box::new(payload),
                })
            }
            ProviderSemanticCandidate::ProcedureCandidate {
                operation,
                target_id,
                base_revision_id,
                content,
            } => {
                let scope = match (episode.repository_instance_id, episode.worktree_instance_id) {
                    (Some(repository_id), Some(worktree_id)) => ProcedureScope::Worktree {
                        repository_id,
                        worktree_id,
                    },
                    (Some(repository_id), None) => ProcedureScope::Repository { repository_id },
                    _ => return Err(crate::semantic::SemanticServiceError::InvalidInput),
                };
                let content = *content;
                let draft = ProcedureDraft {
                    scope,
                    title: content.title,
                    summary: content.summary,
                    kind: content.procedure_kind,
                    when: content.when,
                    condition_ir_version: 1,
                    applicability_expr: content.applicability_expr,
                    avoid_expr: content.avoid_expr,
                    completion_expr: content.completion_expr,
                    actions: content.actions,
                    done: content.done,
                    pitfalls: content.pitfalls,
                    evidence_refs: evidence_refs.to_vec(),
                    support_revision_refs: Vec::new(),
                };
                let payload = match operation {
                    ProviderProcedureOperation::Create => {
                        evertrace_domain::semantic::ProcedureProposalPayload::Create { draft }
                    }
                    ProviderProcedureOperation::Replace => {
                        evertrace_domain::semantic::ProcedureProposalPayload::Replace { draft }
                    }
                };
                Ok(SemanticCandidate::ProcedureProposal {
                    target_id,
                    base_revision_id,
                    payload: Box::new(payload),
                })
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SemanticDigestApplication {
        progress_delta: provider.progress_delta,
        decision_delta: provider.decision_delta,
        failed_routes: provider.failed_routes,
        resolved_items: provider.resolved_items,
        open_loops: provider.open_loops,
        outcome_delta: provider.outcome_delta,
        omissions: provider.omissions,
        candidates,
        completeness: provider.completeness,
    })
}

fn atom_payload_scopes(
    payload: &evertrace_domain::semantic::AtomProposalPayload,
) -> Vec<&evertrace_domain::semantic::AtomScope> {
    use evertrace_domain::semantic::AtomProposalPayload as P;
    match payload {
        P::Create { draft }
        | P::Replace { draft }
        | P::Reclassify { draft }
        | P::Merge { draft, .. } => vec![&draft.scope],
        P::Split { drafts } => drafts.iter().map(|draft| &draft.scope).collect(),
        P::Deprecate { .. } => Vec::new(),
    }
}

fn proposal_payloads(
    digest: &SemanticDigest,
    snapshot: &ProjectionSnapshot,
    request: &SynthesisRequest<'_>,
    evidence_refs: &[String],
) -> Result<Vec<JournalPayload>, crate::semantic::SemanticServiceError> {
    let view = SemanticCurrentView::from_snapshot(snapshot)?;
    let service = RevisionProposalService;
    let mut payloads = Vec::new();
    for candidate in &digest.application.candidates {
        let submit = match candidate {
            SemanticCandidate::ScenarioPatch { .. } => continue,
            SemanticCandidate::AtomProposal {
                target_id,
                base_revision_id,
                payload,
            } => SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: target_id.map(ProposalTargetId::Atom),
                base_revision_id: *base_revision_id,
                operation: payload.operation(),
                payload: ProposalPayload::Atom(payload.clone()),
                evidence_refs: vec![digest.semantic_digest_id.to_string()],
                source_cohort_refs: evidence_refs.to_vec(),
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
            SemanticCandidate::ProcedureProposal {
                target_id,
                base_revision_id,
                payload,
            } => SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: target_id.map(ProposalTargetId::Procedure),
                base_revision_id: *base_revision_id,
                operation: payload.operation(),
                payload: ProposalPayload::Procedure(payload.clone()),
                evidence_refs: vec![digest.semantic_digest_id.to_string()],
                source_cohort_refs: evidence_refs.to_vec(),
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        };
        if has_unique_existing_exact_proposal(&view, &submit)? {
            continue;
        }
        match service.submit(
            &view,
            ProposalCommandContext {
                command_id: request.command_id,
                occurred_at_us: request.occurred_at_us,
                effective_config_hash: request.effective_config_hash,
                algorithm_revision: request.algorithm_revision.clone(),
            },
            submit,
        )? {
            ProposalResolution::Revision { command, .. } => {
                payloads.extend(command.events().iter().map(|event| event.payload.clone()));
            }
            ProposalResolution::NoDelta => {
                return Err(crate::semantic::SemanticServiceError::ImmutableConflict);
            }
        }
    }
    Ok(payloads)
}

fn has_unique_existing_exact_proposal(
    view: &SemanticCurrentView,
    request: &SubmitProposalRequest,
) -> Result<bool, crate::semantic::SemanticServiceError> {
    let mut matching = view.proposals.values().filter(|proposal| {
        matches!(
            proposal.status,
            evertrace_domain::semantic::ProposalStatus::Pending
                | evertrace_domain::semantic::ProposalStatus::Validating
                | evertrace_domain::semantic::ProposalStatus::Deferred
        ) && proposal.eligibility == ProposalEligibility::ManualRequired
            && proposal.created_by == ProposalCreatedBy::Agent
            && proposal.target_kind == request.target_kind
            && proposal.target_id == request.target_id
            && proposal.base_revision_id == request.base_revision_id
            && proposal.operation == request.operation
            && proposal.payload == request.payload
            && proposal.source_cohort_refs == request.source_cohort_refs
    });
    let found = matching.next().is_some();
    if matching.next().is_some() {
        return Err(crate::semantic::SemanticServiceError::ImmutableConflict);
    }
    Ok(found)
}

fn run(
    planner: &SynthesisPlanner,
    request: &SynthesisRequest<'_>,
    episode: &WorkEpisode,
    fingerprint: [u8; 32],
    status: DerivationRunStatus,
    quota_usage: DerivationQuotaUsage,
) -> SemanticDerivationRun {
    SemanticDerivationRun {
        derivation_run_id: SemanticDerivationRunId::new_v7(),
        episode_id: episode.episode_id,
        episode_revision_id: episode.revision_id,
        from_watermark: episode.semantic_watermark,
        to_watermark: episode.source_watermark,
        selected_direct_refs: request.selected_direct_refs.clone(),
        job_fingerprint: fingerprint,
        status,
        quota_usage,
        model_id: planner.llm.model.clone(),
        prompt_hash: planner.prompt_hash,
        schema_version: SEMANTIC_SCHEMA_VERSION,
        algorithm_revision: request.algorithm_revision.clone(),
        effective_config_hash: request.effective_config_hash,
        created_at_us: request.occurred_at_us,
    }
}

fn audit_resolution(
    planner: &SynthesisPlanner,
    request: &SynthesisRequest<'_>,
    episode: &WorkEpisode,
    fingerprint: [u8; 32],
    status: DerivationRunStatus,
    quota: DerivationQuotaUsage,
) -> Result<SynthesisResolution, crate::semantic::SemanticServiceError> {
    let run = run(planner, request, episode, fingerprint, status, quota);
    run.validate()
        .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
    let command = command(
        request,
        vec![JournalPayload::SemanticDerivationRunRecorded(Box::new(
            run.clone(),
        ))],
    )?;
    Ok(SynthesisResolution::Audit { run, command })
}

fn command(
    request: &SynthesisRequest<'_>,
    payloads: Vec<JournalPayload>,
) -> Result<JournalCommand, crate::semantic::SemanticServiceError> {
    let events = payloads
        .into_iter()
        .map(|payload| {
            JournalEventDraft::runtime(
                request.occurred_at_us,
                request.effective_config_hash,
                &request.algorithm_revision,
                payload,
            )
        })
        .collect();
    JournalCommand::new(request.command_id, events)
        .map_err(crate::semantic::SemanticServiceError::Store)
}

fn trigger_name(trigger: SemanticDigestTrigger) -> &'static str {
    match trigger {
        SemanticDigestTrigger::PhaseTransition => "phase_transition",
        SemanticDigestTrigger::StrategyPivot => "strategy_pivot",
        SemanticDigestTrigger::VerifierTransition => "verifier_transition",
        SemanticDigestTrigger::AdoptedDecision => "adopted_decision",
        SemanticDigestTrigger::ExperimentTerminal => "experiment_terminal",
        SemanticDigestTrigger::BudgetBackstop => "budget_backstop",
        SemanticDigestTrigger::EpisodeFinalization => "episode_finalization",
    }
}
