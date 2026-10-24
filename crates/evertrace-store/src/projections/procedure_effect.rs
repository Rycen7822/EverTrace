use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    ids::{ExperimentRunId, ProcedureUsageId},
    procedure::{
        MetricDeltaDirection, ProcedureContextAnchor, ProcedureContextEffectProjection,
        ProcedureEffect, ProcedureEffectContext, ProcedureEffectEvidenceClass, ProcedureUsagePhase,
        classify_metric_delta,
    },
    revision::RevisionId,
    semantic::{
        ConstraintBinding, ConstraintField, ConstraintState, ConstraintValue, EvidenceCompleteness,
        ParserStatus, ResultScope, VerifierStatus,
    },
    work::{
        ArtifactActor, AttemptBindingStatus, ComparisonExecutionBinding, ExperimentRun,
        RunContractValidity, RunExecutionStatus, RunObservability,
    },
};

use crate::{ObjectRow, ObjectRowClass, ObjectRowKind, StoreError};

use super::{PROJECTION_GENERATION, ProcedureEffectCurrentFacts, ProjectionSnapshot};

const KIND: &str = "procedure_context_effect";
const MAX_CONTROLLED_SIDE_RUNS: usize = 64;

pub(super) fn row(
    value: evertrace_domain::procedure::ProcedureContextEffectProjection,
    generation: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!(
            "projection:procedure_effect:{}:{}:observational",
            value.procedure_revision_id,
            hex(value.context_fingerprint_hash)
        ),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Projection),
        object_family: None,
        object_kind: Some(KIND.into()),
        object_id: None,
        current_revision_id: Some(value.procedure_revision_id.to_string()),
        lifecycle: Some("current".into()),
        epistemic: Some("observational".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: Some(value.context.task_id.to_string()),
        workstream_id: None,
        session_id: None,
        source_event_seq: value.source_watermark,
        projection_generation: generation,
        payload_json: Some(serde_json::to_string(&value).map_err(|_| StoreError::Serialization)?),
    })
}

pub(super) fn restore(
    object_row: &ObjectRow,
) -> Result<Option<evertrace_domain::procedure::ProcedureContextEffectProjection>, StoreError> {
    if object_row.object_kind.as_deref() != Some(KIND) {
        return Ok(None);
    }
    let value: evertrace_domain::procedure::ProcedureContextEffectProjection =
        serde_json::from_str(
            object_row
                .payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if row(value.clone(), PROJECTION_GENERATION)? != *object_row {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(Some(value))
}

struct PairBasis<'a> {
    context: ProcedureEffectContext,
    usage: &'a evertrace_domain::procedure::ProcedureUsageRevision,
    episode: &'a evertrace_domain::work::WorkEpisode,
    on_run: &'a ExperimentRun,
    off_run: &'a ExperimentRun,
    refs: BTreeSet<String>,
    watermark: u64,
}

struct SideBasis<'a> {
    context: ProcedureEffectContext,
    usage: &'a evertrace_domain::procedure::ProcedureUsageRevision,
    episode: &'a evertrace_domain::work::WorkEpisode,
    refs: BTreeSet<String>,
    watermark: u64,
}

struct ValidPair {
    direction: MetricDeltaDirection,
    refs: BTreeSet<String>,
    watermark: u64,
    key: ((ExperimentRunId, RevisionId), (ExperimentRunId, RevisionId)),
}

struct ControlledContextGroup {
    context: ProcedureEffectContext,
    refs: BTreeSet<String>,
    watermark: u64,
    valid: Vec<ValidPair>,
    on_sides: BTreeSet<(ExperimentRunId, RevisionId)>,
    off_sides: BTreeSet<(ExperimentRunId, RevisionId)>,
    overloaded: bool,
}

#[derive(Clone, Copy)]
struct ControlledPair {
    on_run_id: ExperimentRunId,
    on_result_revision_id: RevisionId,
    off_run_id: ExperimentRunId,
    off_result_revision_id: RevisionId,
    overloaded: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ControlledSide {
    run_id: ExperimentRunId,
    result_revision_id: RevisionId,
}

type ControlledBucketKey = ([u8; 32], [u8; 32], ProcedureUsageId, RevisionId);

pub(super) fn compile_controlled(
    snapshot: &ProjectionSnapshot,
    procedure_revision_id: RevisionId,
) -> Result<Vec<ProcedureContextEffectProjection>, StoreError> {
    let facts = snapshot.procedure_effect_current_facts()?;
    let (procedure, procedure_seq) = facts
        .procedures
        .get(&procedure_revision_id)
        .ok_or(StoreError::InvalidInput)?;
    if facts.current_procedures.get(&procedure.procedure_id) != Some(&procedure_revision_id)
        || procedure.validate().is_err()
    {
        return Err(StoreError::InvalidInput);
    }
    let fields = procedure.draft.applicability_expr.referenced_fields();
    let pairs = complete_pairs(&facts, procedure_revision_id, &fields);
    if pairs.is_empty() {
        return Err(StoreError::InvalidInput);
    }
    let mut groups = BTreeMap::<[u8; 32], ControlledContextGroup>::new();
    for pair in pairs {
        let Some(basis) = basis(&facts, procedure_revision_id, &fields, &pair) else {
            continue;
        };
        let fingerprint = basis
            .context
            .fingerprint()
            .map_err(|_| StoreError::InvalidInput)?;
        let group = groups
            .entry(fingerprint)
            .or_insert_with(|| ControlledContextGroup {
                context: basis.context.clone(),
                refs: BTreeSet::new(),
                watermark: *procedure_seq,
                valid: Vec::new(),
                on_sides: BTreeSet::new(),
                off_sides: BTreeSet::new(),
                overloaded: false,
            });
        if !basis.context.exact_compatible(&group.context, &fields) {
            return Err(StoreError::InvalidInput);
        }
        group.refs.extend(basis.refs.iter().cloned());
        group.watermark = group.watermark.max(basis.watermark);
        group
            .on_sides
            .insert((pair.on_run_id, pair.on_result_revision_id));
        group
            .off_sides
            .insert((pair.off_run_id, pair.off_result_revision_id));
        group.overloaded |= pair.overloaded;
        if let Some(value) = valid_pair(&facts, procedure_revision_id, &fields, pair, basis) {
            group.valid.push(value);
        }
    }
    if groups.is_empty() {
        return Err(StoreError::InvalidInput);
    }
    groups
        .into_iter()
        .map(|(fingerprint, mut group)| {
            let overloaded = group.overloaded
                || group.on_sides.len() > MAX_CONTROLLED_SIDE_RUNS
                || group.off_sides.len() > MAX_CONTROLLED_SIDE_RUNS;
            group.valid.sort_by_key(|value| value.key);
            group.valid.dedup_by_key(|value| value.key);
            let mut used_on = BTreeSet::new();
            let mut used_off = BTreeSet::new();
            let independent = if overloaded {
                Vec::new()
            } else {
                group
                    .valid
                    .iter()
                    .filter(|value| {
                        if used_on.contains(&value.key.0) || used_off.contains(&value.key.1) {
                            return false;
                        }
                        used_on.insert(value.key.0);
                        used_off.insert(value.key.1);
                        true
                    })
                    .collect::<Vec<_>>()
            };
            for value in &independent {
                group.refs.extend(value.refs.iter().cloned());
                group.watermark = group.watermark.max(value.watermark);
            }
            let effect = if independent.len() < 2 {
                ProcedureEffect::Insufficient
            } else if independent
                .iter()
                .all(|value| value.direction == MetricDeltaDirection::Positive)
            {
                ProcedureEffect::Positive
            } else if independent
                .iter()
                .all(|value| value.direction == MetricDeltaDirection::Negative)
            {
                ProcedureEffect::Negative
            } else {
                ProcedureEffect::Mixed
            };
            let value = ProcedureContextEffectProjection {
                procedure_revision_id,
                context_fingerprint_version: ProcedureEffectContext::FINGERPRINT_VERSION,
                context_fingerprint_hash: fingerprint,
                context: group.context,
                evidence_class: ProcedureEffectEvidenceClass::ControlledComparison,
                effect,
                valid_usage_count: 0,
                valid_pair_count: u32::try_from(independent.len())
                    .map_err(|_| StoreError::InvalidInput)?,
                practical_threshold_revision: 1,
                evidence_refs: group.refs.into_iter().collect(),
                source_watermark: group.watermark,
            };
            value.validate().map_err(|_| StoreError::InvalidInput)?;
            Ok(value)
        })
        .collect()
}

fn complete_pairs(
    facts: &ProcedureEffectCurrentFacts,
    target: RevisionId,
    fields: &BTreeSet<ConstraintField>,
) -> Vec<ControlledPair> {
    let mut results = BTreeMap::<ExperimentRunId, Vec<RevisionId>>::new();
    for revision_id in facts.current_results.values() {
        let Some((result, _)) = facts.results.get(revision_id) else {
            continue;
        };
        results
            .entry(result.experiment_run_id)
            .or_default()
            .push(*revision_id);
    }
    let mut buckets =
        BTreeMap::<ControlledBucketKey, (Vec<ControlledSide>, Vec<ControlledSide>)>::new();
    for (run, _) in facts.runs.values() {
        let Some(binding) = run.comparison_execution_binding.as_ref() else {
            continue;
        };
        let Some(result) = results
            .get(&run.run_id)
            .filter(|values| values.len() == 1)
            .map(|values| values[0])
        else {
            continue;
        };
        let Some(side) = side_basis(facts, target, fields, run) else {
            continue;
        };
        let Ok(fingerprint) = side.context.fingerprint() else {
            continue;
        };
        let bucket = buckets.entry((
            run.comparison_key,
            fingerprint,
            side.usage.procedure_usage_id,
            side.episode.revision_id,
        ));
        let values = if binding.procedure_exposure_revision_id == Some(target) {
            &mut bucket.or_default().0
        } else if binding.procedure_exposure_revision_id.is_none() {
            &mut bucket.or_default().1
        } else {
            continue;
        };
        values.push(ControlledSide {
            run_id: run.run_id,
            result_revision_id: result,
        });
    }
    expand_complete_pairs(buckets)
}

fn expand_complete_pairs(
    buckets: BTreeMap<ControlledBucketKey, (Vec<ControlledSide>, Vec<ControlledSide>)>,
) -> Vec<ControlledPair> {
    let mut pairs = Vec::new();
    for (_, (mut on_sides, mut off_sides)) in buckets {
        if on_sides.is_empty() || off_sides.is_empty() {
            continue;
        }
        on_sides.sort_unstable();
        on_sides.dedup();
        off_sides.sort_unstable();
        off_sides.dedup();
        let overloaded =
            on_sides.len() > MAX_CONTROLLED_SIDE_RUNS || off_sides.len() > MAX_CONTROLLED_SIDE_RUNS;
        for on in on_sides
            .iter()
            .take(if overloaded { 1 } else { usize::MAX })
        {
            for off in off_sides
                .iter()
                .take(if overloaded { 1 } else { usize::MAX })
            {
                pairs.push(ControlledPair {
                    on_run_id: on.run_id,
                    on_result_revision_id: on.result_revision_id,
                    off_run_id: off.run_id,
                    off_result_revision_id: off.result_revision_id,
                    overloaded,
                });
            }
        }
    }
    pairs
}

fn basis<'a>(
    facts: &'a ProcedureEffectCurrentFacts,
    target: RevisionId,
    fields: &BTreeSet<ConstraintField>,
    pair: &ControlledPair,
) -> Option<PairBasis<'a>> {
    let (on_run, on_run_seq) = facts.runs.get(&pair.on_run_id)?;
    let (off_run, off_run_seq) = facts.runs.get(&pair.off_run_id)?;
    let on = side_basis(facts, target, fields, on_run)?;
    let off = side_basis(facts, target, fields, off_run)?;
    if on.usage.procedure_usage_id != off.usage.procedure_usage_id
        || on.usage.usage_revision_id != off.usage.usage_revision_id
        || on.episode.revision_id != off.episode.revision_id
        || !on.context.exact_compatible(&off.context, fields)
    {
        return None;
    }
    let mut refs = on.refs;
    refs.extend(off.refs);
    refs.extend([
        on_run.run_id.to_string(),
        on_run.revision_id.to_string(),
        off_run.run_id.to_string(),
        off_run.revision_id.to_string(),
    ]);
    let watermark = [*on_run_seq, *off_run_seq, on.watermark, off.watermark]
        .into_iter()
        .max()?;
    Some(PairBasis {
        context: on.context,
        usage: on.usage,
        episode: on.episode,
        on_run,
        off_run,
        refs,
        watermark,
    })
}

fn side_basis<'a>(
    facts: &'a ProcedureEffectCurrentFacts,
    target: RevisionId,
    fields: &BTreeSet<ConstraintField>,
    run: &'a ExperimentRun,
) -> Option<SideBasis<'a>> {
    let binding = run.comparison_execution_binding.as_ref()?;
    if binding.procedure_exposure_revision_id.is_some()
        && binding.procedure_exposure_revision_id != Some(target)
    {
        return None;
    }
    let attempt_id = run.attempt_id?;
    let (attempt, attempt_seq) = facts.attempts.get(&attempt_id)?;
    let mut authorities = facts.usages.values().filter_map(|(usage, usage_seq)| {
        if usage.procedure_revision_id != target
            || usage.task_id != attempt.task_id
            || usage.workstream_id != attempt.workstream_id
            || !usage.validate()
        {
            return None;
        }
        let (episode, episode_seq) = facts.episodes.get(&usage.exposure_episode_revision_id)?;
        if episode.task_id != attempt.task_id
            || episode.workstream_id != attempt.workstream_id
            || !episode.attempt_ids.contains(&attempt_id)
            || binding.procedure_exposure_revision_id == Some(target)
                && !usage.attempt_ids.contains(&attempt_id)
        {
            return None;
        }
        Some((usage, *usage_seq, episode, *episode_seq))
    });
    let (usage, usage_seq, episode, episode_seq) = authorities.next()?;
    if authorities.next().is_some() {
        return None;
    }
    let mut refs = BTreeSet::from([
        usage.procedure_usage_id.to_string(),
        usage.usage_revision_id.to_string(),
        usage.exposure_episode_revision_id.to_string(),
        attempt_id.to_string(),
    ]);
    let (anchor, anchor_seq) = match (
        usage.local_context.repository_id,
        usage.local_context.worktree_id,
    ) {
        (Some(repository_id), Some(worktree_id)) => {
            if episode.repository_instance_id != Some(repository_id)
                || episode.worktree_instance_id != Some(worktree_id)
            {
                return None;
            }
            let snapshot_id = episode.entry_worktree_snapshot_id?;
            let (snapshot, snapshot_seq) = facts.snapshots.get(&snapshot_id)?;
            let (worktree, worktree_seq) = facts.worktrees.get(&worktree_id)?;
            if snapshot.worktree_instance_id != worktree_id
                || worktree.repository_instance_id != repository_id
            {
                return None;
            }
            refs.extend([
                repository_id.to_string(),
                worktree_id.to_string(),
                snapshot_id.to_string(),
            ]);
            (
                ProcedureContextAnchor::Repository {
                    repository_id,
                    worktree_id,
                    worktree_snapshot_id: snapshot_id,
                    worktree_lineage: worktree_id.to_string(),
                },
                (*snapshot_seq).max(*worktree_seq),
            )
        }
        (None, None) => {
            if episode.repository_instance_id.is_some() || episode.worktree_instance_id.is_some() {
                return None;
            }
            let fixture_refs = non_repository_anchor_refs(facts, episode)?;
            refs.extend(fixture_refs.iter().cloned());
            (ProcedureContextAnchor::NonRepository { fixture_refs }, 0)
        }
        _ => return None,
    };
    let mut operands = Vec::new();
    if fields.contains(&ConstraintField::Phase) {
        operands.push(ConstraintBinding {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text(phase(usage.local_context.phase).into()),
        });
    }
    if fields.contains(&ConstraintField::FailureSignature)
        && let Some(value) = &usage.local_context.failure_signature
    {
        operands.push(ConstraintBinding {
            field: ConstraintField::FailureSignature,
            value: ConstraintValue::Text(value.clone()),
        });
    }
    operands.sort_by_key(|value| value.field);
    let context = ProcedureEffectContext::compile(
        target,
        usage.task_id,
        anchor,
        fields,
        &ConstraintState { bindings: operands },
        usage.local_context.phase,
        usage.local_context.failure_signature.clone(),
        binding.toolchain_revision.clone(),
        binding.model_revision.clone(),
        binding.harness_revision.clone(),
        binding.algorithm_revision.clone(),
        binding.budget,
        attempt.strategy_contract.acceptance_boundary_ref.clone(),
    )
    .ok()?;
    Some(SideBasis {
        context,
        usage,
        episode,
        refs,
        watermark: [*attempt_seq, usage_seq, episode_seq, anchor_seq]
            .into_iter()
            .max()?,
    })
}

fn valid_pair(
    facts: &ProcedureEffectCurrentFacts,
    target: RevisionId,
    fields: &BTreeSet<ConstraintField>,
    pair: ControlledPair,
    mut basis: PairBasis<'_>,
) -> Option<ValidPair> {
    if !basis.context.complete_for(fields) {
        return None;
    }
    let on_attempt_id = basis.on_run.attempt_id?;
    let off_attempt_id = basis.off_run.attempt_id?;
    let (on_attempt, on_attempt_seq) = facts.attempts.get(&on_attempt_id)?;
    let (off_attempt, off_attempt_seq) = facts.attempts.get(&off_attempt_id)?;
    let (on_result, on_result_seq) = facts.results.get(&pair.on_result_revision_id)?;
    let (off_result, off_result_seq) = facts.results.get(&pair.off_result_revision_id)?;
    let target_ref = target.to_string();
    if facts.current_results.get(&on_result.result_evidence_id) != Some(&on_result.revision_id)
        || facts.current_results.get(&off_result.result_evidence_id)
            != Some(&off_result.revision_id)
        || on_attempt_id == off_attempt_id
        || on_attempt.task_id != off_attempt.task_id
        || on_attempt.task_id != basis.usage.task_id
        || on_attempt.workstream_id != off_attempt.workstream_id
        || on_attempt.strategy_contract != off_attempt.strategy_contract
        || on_attempt.strategy_contract.search_policy_ref.as_deref() != Some(target_ref.as_str())
        || on_attempt.strategy_contract.acceptance_boundary_ref != basis.usage.decision_boundary_ref
        || !basis.episode.attempt_ids.contains(&on_attempt_id)
        || !basis.episode.attempt_ids.contains(&off_attempt_id)
        || basis.episode.task_id != on_attempt.task_id
        || basis.episode.workstream_id != on_attempt.workstream_id
        || !facts.tasks.contains_key(&on_attempt.task_id)
        || on_attempt.validate().is_err()
        || off_attempt.validate().is_err()
        || !run_ready(basis.on_run, on_attempt_id)
        || !run_ready(basis.off_run, off_attempt_id)
        || !same_run_contract(basis.on_run, basis.off_run)
        || !result_ready(on_result, basis.on_run.run_id, basis.on_run.revision_id)
        || !result_ready(off_result, basis.off_run.run_id, basis.off_run.revision_id)
    {
        return None;
    }
    let on_binding = basis.on_run.comparison_execution_binding.as_ref()?;
    let off_binding = basis.off_run.comparison_execution_binding.as_ref()?;
    if on_binding.procedure_exposure_revision_id != Some(target)
        || off_binding.procedure_exposure_revision_id.is_some()
        || !same_binding(on_binding, off_binding)
        || basis.on_run.comparison_key != basis.off_run.comparison_key
        || !all_fixed(basis.on_run)
        || !all_fixed(basis.off_run)
    {
        return None;
    }
    match &basis.context.anchor {
        ProcedureContextAnchor::Repository {
            worktree_id,
            worktree_snapshot_id,
            ..
        } => {
            let snapshot = &facts.snapshots.get(worktree_snapshot_id)?.0;
            if on_attempt.repository_instance_id != basis.usage.local_context.repository_id
                || off_attempt.repository_instance_id != basis.usage.local_context.repository_id
                || !on_attempt.worktree_instance_ids.contains(worktree_id)
                || !off_attempt.worktree_instance_ids.contains(worktree_id)
                || basis.on_run.code_snapshot_id != *worktree_snapshot_id
                || basis.off_run.code_snapshot_id != *worktree_snapshot_id
                || snapshot.toolchain_fingerprint.as_deref()
                    != Some(on_binding.toolchain_revision.as_str())
            {
                return None;
            }
        }
        ProcedureContextAnchor::NonRepository { fixture_refs } => {
            if on_attempt.repository_instance_id.is_some()
                || off_attempt.repository_instance_id.is_some()
                || !on_attempt.worktree_instance_ids.is_empty()
                || !off_attempt.worktree_instance_ids.is_empty()
            {
                return None;
            }
            let on_refs = side_refs(facts, basis.episode, basis.on_run, on_result);
            let off_refs = side_refs(facts, basis.episode, basis.off_run, off_result);
            if on_refs.is_empty()
                || off_refs.is_empty()
                || !on_refs
                    .iter()
                    .chain(&off_refs)
                    .all(|value| fixture_refs.contains(value))
            {
                return None;
            }
        }
    }
    let on_metric = on_result.parsed_metric.as_ref()?;
    let off_metric = off_result.parsed_metric.as_ref()?;
    if on_metric.unit != on_binding.metric_unit
        || off_metric.unit != on_binding.metric_unit
        || on_metric.uncertainty_decimal.is_some()
        || off_metric.uncertainty_decimal.is_some()
    {
        return None;
    }
    let direction = classify_metric_delta(on_binding, &on_metric.decimal, &off_metric.decimal)?;
    basis.refs.extend(
        facts
            .tasks
            .get(&on_attempt.task_id)?
            .0
            .request_root_refs
            .iter()
            .cloned(),
    );
    basis.refs.extend([
        on_result.result_evidence_id.to_string(),
        on_result.revision_id.to_string(),
        off_result.result_evidence_id.to_string(),
        off_result.revision_id.to_string(),
        format!("comparison_key:{}", hex(basis.on_run.comparison_key)),
    ]);
    let on = (basis.on_run.run_id, on_result.revision_id);
    let off = (basis.off_run.run_id, off_result.revision_id);
    Some(ValidPair {
        direction,
        refs: basis.refs,
        watermark: [
            basis.watermark,
            *on_attempt_seq,
            *off_attempt_seq,
            *on_result_seq,
            *off_result_seq,
        ]
        .into_iter()
        .max()?,
        key: (on, off),
    })
}

fn run_ready(run: &ExperimentRun, attempt_id: evertrace_domain::ids::AttemptId) -> bool {
    run.attempt_id == Some(attempt_id)
        && run.attempt_binding_status == AttemptBindingStatus::Resolved
        && run.observability == RunObservability::Full
        && run.execution_status == RunExecutionStatus::Completed
        && run.contract_validity == RunContractValidity::Valid
        && run.validate().is_ok()
}

fn result_ready(
    result: &evertrace_domain::semantic::ResultEvidence,
    run: ExperimentRunId,
    revision: RevisionId,
) -> bool {
    result.experiment_run_id == run
        && result.experiment_run_revision_id == revision
        && result.result_scope == ResultScope::Complete
        && result.completeness == EvidenceCompleteness::Complete
        && result.parser_receipt.status == ParserStatus::Parsed
        && result
            .verifier_receipt
            .as_ref()
            .is_some_and(|value| value.status == VerifierStatus::Passed)
        && result.failure.is_none()
        && result.parsed_metric.is_some()
        && result.validate().is_ok()
}

fn same_run_contract(left: &ExperimentRun, right: &ExperimentRun) -> bool {
    left.workstream_id == right.workstream_id
        && left.strategy_contract_fingerprint == right.strategy_contract_fingerprint
        && left.code_snapshot_id == right.code_snapshot_id
        && left.data_fingerprint == right.data_fingerprint
        && left.normalized_config == right.normalized_config
        && left.variable_declaration == right.variable_declaration
        && left.seed_policy == right.seed_policy
        && left.seed_values == right.seed_values
        && left.nondeterministic == right.nondeterministic
        && left.metric_definition == right.metric_definition
        && left.metric_extractor_version == right.metric_extractor_version
        && left.multi_cas_metric_policy == right.multi_cas_metric_policy
        && left.environment_fingerprint == right.environment_fingerprint
}

fn same_binding(left: &ComparisonExecutionBinding, right: &ComparisonExecutionBinding) -> bool {
    left.binding_version == right.binding_version
        && left.toolchain_revision == right.toolchain_revision
        && left.model_revision == right.model_revision
        && left.harness_revision == right.harness_revision
        && left.algorithm_revision == right.algorithm_revision
        && left.budget == right.budget
        && left.metric_direction == right.metric_direction
        && left.metric_unit == right.metric_unit
        && left.positive_delta_threshold == right.positive_delta_threshold
        && left.negative_delta_threshold == right.negative_delta_threshold
}

fn all_fixed(run: &ExperimentRun) -> bool {
    run.variable_declaration.varied.is_empty()
        && run.variable_declaration.uncontrolled.is_empty()
        && run.variable_declaration.fixed
            == run
                .normalized_config
                .iter()
                .map(|value| value.name.clone())
                .collect::<Vec<_>>()
}

fn non_repository_anchor_refs(
    facts: &ProcedureEffectCurrentFacts,
    episode: &evertrace_domain::work::WorkEpisode,
) -> Option<Vec<String>> {
    let mut values = BTreeSet::new();
    values.extend(
        episode_refs(episode)
            .filter(|reference| {
                reference.parse::<RevisionId>().is_ok_and(|revision| {
                    facts.results.contains_key(&revision) || facts.artifacts.contains_key(&revision)
                })
            })
            .cloned(),
    );
    let actor = ArtifactActor::WorkEpisode(episode.episode_id);
    for revision_id in facts.current_artifacts.values() {
        let Some((artifact, _)) = facts.artifacts.get(revision_id) else {
            continue;
        };
        if artifact.revision.produced_by_refs.contains(&actor)
            || artifact.revision.consumed_by_refs.contains(&actor)
        {
            values.insert(revision_id.to_string());
        }
    }
    (!values.is_empty()).then(|| values.into_iter().collect())
}

fn side_refs(
    facts: &ProcedureEffectCurrentFacts,
    episode: &evertrace_domain::work::WorkEpisode,
    run: &ExperimentRun,
    result: &evertrace_domain::semantic::ResultEvidence,
) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    if episode_refs(episode).any(|value| value == &result.revision_id.to_string()) {
        values.insert(result.revision_id.to_string());
    }
    for artifact_id in run
        .work_artifact_refs
        .iter()
        .chain(&result.raw_artifact_refs)
    {
        let Some(revision_id) = facts.current_artifacts.get(artifact_id) else {
            continue;
        };
        let Some((artifact, _)) = facts.artifacts.get(revision_id) else {
            continue;
        };
        let actor = ArtifactActor::WorkEpisode(episode.episode_id);
        if artifact.revision.produced_by_refs.contains(&actor)
            || artifact.revision.consumed_by_refs.contains(&actor)
        {
            values.insert(revision_id.to_string());
        }
    }
    values
}

fn episode_refs(episode: &evertrace_domain::work::WorkEpisode) -> impl Iterator<Item = &String> {
    episode
        .completed_outcome_refs
        .iter()
        .chain(&episode.selected_outcome_refs)
        .chain(&episode.verification_refs)
        .chain(&episode.semantic_digest_refs)
}

fn phase(value: ProcedureUsagePhase) -> &'static str {
    match value {
        ProcedureUsagePhase::BeforeEntry => "before_entry",
        ProcedureUsagePhase::AtEntry => "at_entry",
        ProcedureUsagePhase::InProgress => "in_progress",
        ProcedureUsagePhase::RecoverableDeviation => "recoverable_deviation",
        ProcedureUsagePhase::AlreadyCompleted => "already_completed",
        ProcedureUsagePhase::Incompatible => "incompatible",
    }
}

fn hex(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn side() -> ControlledSide {
        ControlledSide {
            run_id: ExperimentRunId::new_v7(),
            result_revision_id: RevisionId::new_v7(),
        }
    }

    #[test]
    fn side_limit_is_isolated_after_context_grouping() {
        let usage = ProcedureUsageId::new_v7();
        let episode = RevisionId::new_v7();
        let valid_on = vec![side(), side()];
        let valid_off = vec![side(), side()];
        let valid_ids = valid_on
            .iter()
            .chain(&valid_off)
            .map(|value| value.run_id)
            .collect::<BTreeSet<_>>();
        let mut buckets =
            BTreeMap::from([(([1; 32], [1; 32], usage, episode), (valid_on, valid_off))]);
        buckets.insert(
            (
                [1; 32],
                [2; 32],
                ProcedureUsageId::new_v7(),
                RevisionId::new_v7(),
            ),
            ((0..65).map(|_| side()).collect(), vec![side()]),
        );

        let pairs = expand_complete_pairs(buckets);
        assert_eq!(pairs.len(), 5);
        assert_eq!(pairs.iter().filter(|pair| pair.overloaded).count(), 1);
        assert_eq!(
            pairs
                .iter()
                .filter(|pair| {
                    valid_ids.contains(&pair.on_run_id) && valid_ids.contains(&pair.off_run_id)
                })
                .count(),
            4
        );
        assert!(
            pairs
                .iter()
                .filter(|pair| {
                    valid_ids.contains(&pair.on_run_id) && valid_ids.contains(&pair.off_run_id)
                })
                .all(|pair| !pair.overloaded)
        );
    }
}
