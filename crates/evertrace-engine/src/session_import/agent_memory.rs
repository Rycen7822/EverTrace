//! Frozen AgentMemory v0.9.29 export mapping into L0 evidence and pending proposals.

use evertrace_capture::{CaptureOutcome, CaptureRecordInput, CaptureRuntime, RuntimeSnapshot};
use evertrace_codex::session_import::{
    AgentMemoryExport, AgentMemoryGraphEdge, AgentMemoryGraphNode,
    AgentMemoryImportError as ParseError, AgentMemoryMemory, AgentMemoryObservation,
    parse_agent_memory_export,
};
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceInstanceId,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, hex,
        payload_fingerprint, source_observation_id,
    },
    ids::{CommandId, SourceObservationId},
    semantic::{
        ApplicabilityExpr, AtomDraft, AtomKind, AtomProposalPayload, AtomProvenance, AtomScope,
        AtomValue, EpistemicStatus, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalTargetKind, ValidityInterval,
    },
};
use evertrace_store::{JournalCommand, JournalPayload, SemanticCurrentView};
use serde::Serialize;
use thiserror::Error;

use crate::{
    EvidenceIngestor, WriterHandle,
    semantic::{
        ProposalCommandContext, ProposalResolution, RevisionProposalService, SubmitProposalRequest,
    },
};

const SOURCE_INSTANCE: &str = "agentmemory-export-v0.9.29";
const ADAPTER_REVISION: &str = "agentmemory-export-v0.9.29";
const INGEST_BATCH: usize = 256;
const PROPOSAL_BATCH: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentMemoryProvenance {
    pub graph_ref: String,
    pub source_observation_refs: Vec<SourceObservationId>,
    pub dangling: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentMemoryImportOutcome {
    pub observations: usize,
    pub memory_evidence: usize,
    pub proposals: usize,
    pub graph_provenance: Vec<AgentMemoryProvenance>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AgentMemoryImportError {
    #[error("AgentMemory export is unavailable or unsupported")]
    Unsupported,
    #[error("AgentMemory migration persistence failed")]
    Persistence,
}

#[derive(Clone)]
pub struct AgentMemoryMigrationService {
    writer: WriterHandle,
    runtime: RuntimeSnapshot,
}

impl AgentMemoryMigrationService {
    pub fn new(
        writer: WriterHandle,
        runtime: RuntimeSnapshot,
    ) -> Result<Self, AgentMemoryImportError> {
        runtime
            .validate()
            .map_err(|_| AgentMemoryImportError::Persistence)?;
        Ok(Self { writer, runtime })
    }

    pub async fn import_export(
        &self,
        bytes: &[u8],
        occurred_at_us: i64,
    ) -> Result<AgentMemoryImportOutcome, AgentMemoryImportError> {
        if occurred_at_us < 0 {
            return Err(AgentMemoryImportError::Unsupported);
        }
        let export = parse_agent_memory_export(bytes).map_err(map_parse)?;
        let diagnostics = export.dangling_refs.clone();
        let fingerprint =
            payload_fingerprint(1, bytes, None).map_err(|_| AgentMemoryImportError::Unsupported)?;
        let revision = SourceRevision::parse(hex(&fingerprint))
            .map_err(|_| AgentMemoryImportError::Unsupported)?;
        let mut existing = existing_observations(&self.writer).await?;
        let previous = current_revision(&self.writer, &revision).await?;
        let mut observation_map = std::collections::BTreeMap::new();
        let mut memory_map = std::collections::BTreeMap::new();
        let mut graph_map = std::collections::BTreeMap::new();
        let ingestor = EvidenceIngestor::new(
            self.runtime.clone(),
            self.writer.clone(),
            self.runtime.effective_config_hash,
            ADAPTER_REVISION,
        )
        .map_err(|_| AgentMemoryImportError::Persistence)?;
        let mut records = export
            .observations
            .iter()
            .map(MigrationRecord::Observation)
            .chain(export.memories.iter().map(MigrationRecord::Memory))
            .chain(export.graph_nodes.iter().map(MigrationRecord::Node))
            .chain(export.graph_edges.iter().map(MigrationRecord::Edge))
            .enumerate();
        loop {
            let batch = records.by_ref().take(INGEST_BATCH).collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            let replay_ids = batch
                .iter()
                .map(|(_, record)| record.observation_id(&revision))
                .collect::<Result<Vec<_>, _>>()?;
            ingestor
                .drain_observations_once(&replay_ids)
                .await
                .map_err(|_| AgentMemoryImportError::Persistence)?;
            existing.extend(existing_observations(&self.writer).await?);
            let ids = {
                let mut runtime = CaptureRuntime::open(self.runtime.clone())
                    .map_err(|_| AgentMemoryImportError::Persistence)?;
                let mut capture = AgentMemoryCapture {
                    runtime: &mut runtime,
                    existing: &existing,
                    revision: &revision,
                    previous: previous.as_ref(),
                };
                let mut ids = Vec::new();
                for (ordinal, record) in batch {
                    let ordinal =
                        u64::try_from(ordinal).map_err(|_| AgentMemoryImportError::Unsupported)?;
                    let (id, captured) = record.capture(&mut capture, ordinal)?;
                    record.remember(id, &mut observation_map, &mut memory_map, &mut graph_map);
                    if captured {
                        ids.push(id);
                    }
                }
                ids
            };
            if !ids.is_empty() {
                ingestor
                    .drain_observations_once(&ids)
                    .await
                    .map_err(|_| AgentMemoryImportError::Persistence)?;
            }
        }
        let proposals = self
            .submit_memories(&export, &observation_map, &memory_map, occurred_at_us)
            .await?;
        let graph_provenance = graph_provenance(&export, &observation_map, &graph_map);
        Ok(AgentMemoryImportOutcome {
            observations: export.observations.len(),
            memory_evidence: export.memories.len(),
            proposals,
            graph_provenance,
            diagnostics,
        })
    }

    async fn submit_memories(
        &self,
        export: &AgentMemoryExport,
        observations: &std::collections::BTreeMap<String, SourceObservationId>,
        memories: &std::collections::BTreeMap<String, SourceObservationId>,
        occurred_at_us: i64,
    ) -> Result<usize, AgentMemoryImportError> {
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| AgentMemoryImportError::Persistence)?;
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| AgentMemoryImportError::Persistence)?;
        let mut created = 0;
        let mut seen = std::collections::BTreeSet::new();
        let mut pending_events = Vec::new();
        for memory in &export.memories {
            if memory
                .source_observation_ids
                .iter()
                .flatten()
                .any(|id| !observations.contains_key(id))
            {
                continue;
            }
            let Some(memory_evidence) = memories.get(&memory.id).copied() else {
                return Err(AgentMemoryImportError::Persistence);
            };
            let mut source_refs = memory
                .source_observation_ids
                .iter()
                .flatten()
                .filter_map(|id| observations.get(id).copied())
                .collect::<Vec<_>>();
            source_refs.push(memory_evidence);
            source_refs.sort();
            source_refs.dedup();
            let text = format!("{}\n\n{}", memory.title, memory.content);
            if text.is_empty() || text.len() > 16 * 1024 {
                continue;
            }
            if !seen.insert((text.clone(), source_refs.clone())) {
                continue;
            }
            let request = SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: AtomDraft {
                        kind: AtomKind::Annotation,
                        epistemic_status: EpistemicStatus::Unverified,
                        value: AtomValue {
                            text,
                            subject: "agentmemory_import".into(),
                            predicate: "legacy_memory_claim".into(),
                            object: None,
                            qualifiers: Vec::new(),
                            critical_revision_refs: Vec::new(),
                        },
                        scope: AtomScope::Global,
                        applicability_expr: ApplicabilityExpr::Always,
                        future_cue_lifecycle_exprs: None,
                        validity_interval: ValidityInterval {
                            valid_from_us: 0,
                            valid_until_us: None,
                        },
                        provenance: vec![AtomProvenance::AgentClaimed],
                        source_observation_refs: source_refs.clone(),
                        evidence_refs: source_refs.iter().map(ToString::to_string).collect(),
                        supersedes_revision_refs: Vec::new(),
                        supports_revision_refs: Vec::new(),
                        contradicts_revision_refs: Vec::new(),
                    },
                })),
                evidence_refs: vec![memory_evidence.to_string()],
                source_cohort_refs: source_refs.iter().map(ToString::to_string).collect(),
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            };
            let resolution = RevisionProposalService.submit(
                &view,
                ProposalCommandContext {
                    command_id: CommandId::new_v7(),
                    occurred_at_us,
                    effective_config_hash: self.runtime.effective_config_hash,
                    algorithm_revision: ADAPTER_REVISION.into(),
                },
                request,
            );
            match resolution.map_err(|_| AgentMemoryImportError::Persistence)? {
                ProposalResolution::NoDelta => {}
                ProposalResolution::Revision { command, .. } => {
                    pending_events.extend_from_slice(command.events());
                    created += 1;
                    if pending_events.len() >= PROPOSAL_BATCH {
                        self.commit_proposal_batch(&mut pending_events, occurred_at_us)
                            .await?;
                    }
                }
            }
        }
        self.commit_proposal_batch(&mut pending_events, occurred_at_us)
            .await?;
        Ok(created)
    }

    async fn commit_proposal_batch(
        &self,
        events: &mut Vec<evertrace_store::JournalEventDraft>,
        occurred_at_us: i64,
    ) -> Result<(), AgentMemoryImportError> {
        if events.is_empty() {
            return Ok(());
        }
        let command = JournalCommand::new(CommandId::new_v7(), std::mem::take(events))
            .map_err(|_| AgentMemoryImportError::Persistence)?;
        self.writer
            .commit(command, occurred_at_us)
            .await
            .map_err(|_| AgentMemoryImportError::Persistence)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum MigrationRecord<'a> {
    Observation(&'a AgentMemoryObservation),
    Memory(&'a AgentMemoryMemory),
    Node(&'a AgentMemoryGraphNode),
    Edge(&'a AgentMemoryGraphEdge),
}

impl MigrationRecord<'_> {
    fn observation_id(
        self,
        revision: &SourceRevision,
    ) -> Result<SourceObservationId, AgentMemoryImportError> {
        let identity = match self {
            Self::Observation(value) => format!("observation:{}", value.id),
            Self::Memory(value) => format!("memory:{}", value.id),
            Self::Node(value) => format!("graph-node:{}", value.id),
            Self::Edge(value) => format!("graph-edge:{}", value.id),
        };
        source_observation_id(
            &SourceInstanceId::parse(SOURCE_INSTANCE)
                .map_err(|_| AgentMemoryImportError::Unsupported)?,
            revision,
            &SourceRecordIdentity::parse(identity)
                .map_err(|_| AgentMemoryImportError::Unsupported)?,
        )
        .map_err(|_| AgentMemoryImportError::Unsupported)
    }

    fn capture(
        self,
        capture: &mut AgentMemoryCapture<'_>,
        ordinal: u64,
    ) -> Result<(SourceObservationId, bool), AgentMemoryImportError> {
        match self {
            Self::Observation(value) => capture.capture(
                ordinal,
                format!("observation:{}", value.id),
                value,
                &value.session_id,
            ),
            Self::Memory(value) => capture.capture(
                ordinal,
                format!("memory:{}", value.id),
                value,
                value
                    .session_ids
                    .first()
                    .map_or("agentmemory-export", String::as_str),
            ),
            Self::Node(value) => capture.capture(
                ordinal,
                format!("graph-node:{}", value.id),
                value,
                "agentmemory-export",
            ),
            Self::Edge(value) => capture.capture(
                ordinal,
                format!("graph-edge:{}", value.id),
                value,
                "agentmemory-export",
            ),
        }
    }

    fn remember(
        self,
        id: SourceObservationId,
        observations: &mut std::collections::BTreeMap<String, SourceObservationId>,
        memories: &mut std::collections::BTreeMap<String, SourceObservationId>,
        graph: &mut std::collections::BTreeMap<String, SourceObservationId>,
    ) {
        match self {
            Self::Observation(value) => {
                observations.insert(value.id.clone(), id);
            }
            Self::Memory(value) => {
                memories.insert(value.id.clone(), id);
            }
            Self::Node(value) => {
                graph.insert(format!("node:{}", value.id), id);
            }
            Self::Edge(value) => {
                graph.insert(format!("edge:{}", value.id), id);
            }
        }
    }
}

struct AgentMemoryCapture<'a> {
    runtime: &'a mut CaptureRuntime,
    existing: &'a std::collections::BTreeSet<String>,
    revision: &'a SourceRevision,
    previous: Option<&'a SourceRevision>,
}

impl AgentMemoryCapture<'_> {
    fn capture<T: Serialize>(
        &mut self,
        ordinal: u64,
        record_identity: String,
        record: &T,
        session: &str,
    ) -> Result<(SourceObservationId, bool), AgentMemoryImportError> {
        let raw = serde_json::to_vec(record).map_err(|_| AgentMemoryImportError::Unsupported)?;
        let source_instance = SourceInstanceId::parse(SOURCE_INSTANCE)
            .map_err(|_| AgentMemoryImportError::Unsupported)?;
        let identity = SourceRecordIdentity::parse(record_identity.clone())
            .map_err(|_| AgentMemoryImportError::Unsupported)?;
        let id = source_observation_id(&source_instance, self.revision, &identity)
            .map_err(|_| AgentMemoryImportError::Unsupported)?;
        if self.existing.contains(&id.to_string()) {
            return Ok((id, false));
        }
        let replacement = ordinal == 0 && self.previous.is_some();
        let outcome = self
            .runtime
            .capture(CaptureRecordInput {
                spool_record_id: Some(format!("agentmemory-{record_identity}")),
                source_observation_id_hint: None,
                source_instance_id: SOURCE_INSTANCE.into(),
                source_revision: self.revision.as_str().into(),
                source_record_identity: Some(record_identity),
                identity_strength: Some(IdentityStrength::StableSourceSequence),
                source_kind: EvidenceSourceKind::Other,
                identity_domain: "agentmemory-export-v0.9.29".into(),
                source_ref: "agentmemory:export".into(),
                session_ref: session.into(),
                turn_ref: None,
                tool_ref: None,
                source_sequence: ordinal + 1,
                source_sequence_origin: None,
                task_id: None,
                repository_instance_id: None,
                worktree_instance_id: None,
                source_byte_range: None,
                source_revision_mode: if replacement {
                    SourceRevisionMode::Replacement
                } else {
                    SourceRevisionMode::Append
                },
                previous_source_revision: if replacement {
                    self.previous.map(|value| value.as_str().into())
                } else {
                    None
                },
                close_watermark: None,
                observation_role: ObservationRole::Other,
                correlation: HostCorrelationEvidence {
                    occurrence_schema_version: 1,
                    host_instance_id: None,
                    host_trace_lineage_id: None,
                    host_lane_key: None,
                    canonical_event_family: None,
                    native_request_id: None,
                    physical_execution_ordinal: None,
                    pairing_role: ObservationRole::Other,
                    field_provenance: Vec::new(),
                    adapter_manifest_ref: ADAPTER_REVISION.into(),
                    adapter_revision: 1,
                    strong_gate_receipt_ref: None,
                    admission: CorrelationAdmission::Unavailable,
                    partial_correlation_ref: None,
                    possible_duplicate_group_id: None,
                },
                scope_effect_claims: Vec::new(),
                lifecycle: None,
                unsupported_record_classification: None,
                source_role: SourceRole::Imported,
                content_trust: ContentTrust::ImportedClaim,
                capture_completeness: CaptureCompleteness::Complete,
                surface_eligible: false,
                adapter_revision: 1,
                adapter_manifest_ref: ADAPTER_REVISION.into(),
                eligible_event_manifest_ref: "agentmemory-export-records-v1".into(),
                parser_revision: 1,
                canonicalization_revision: 1,
                event_time_us: None,
                raw_payload: raw,
            })
            .map_err(|_| AgentMemoryImportError::Persistence)?;
        if !matches!(outcome, CaptureOutcome::Durable { .. }) {
            return Err(AgentMemoryImportError::Persistence);
        }
        Ok((id, true))
    }
}

async fn existing_observations(
    writer: &WriterHandle,
) -> Result<std::collections::BTreeSet<String>, AgentMemoryImportError> {
    let snapshot = writer
        .project()
        .await
        .map_err(|_| AgentMemoryImportError::Persistence)?;
    Ok(snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
        .filter_map(|row| row.object_id.clone())
        .collect())
}

async fn current_revision(
    writer: &WriterHandle,
    revision: &SourceRevision,
) -> Result<Option<SourceRevision>, AgentMemoryImportError> {
    let snapshot = writer
        .project()
        .await
        .map_err(|_| AgentMemoryImportError::Persistence)?;
    let mut current = None;
    for row in snapshot.data_rows() {
        let Some(json) = row.payload_json.as_deref() else {
            continue;
        };
        let Ok(JournalPayload::SourceIngestWatermark(value)) = serde_json::from_str(json) else {
            continue;
        };
        if value.source_instance_id.as_str() == SOURCE_INSTANCE {
            current = Some(value.source_revision);
        }
    }
    Ok(current.filter(|value| value != revision))
}

fn graph_provenance(
    export: &AgentMemoryExport,
    observations: &std::collections::BTreeMap<String, SourceObservationId>,
    graph: &std::collections::BTreeMap<String, SourceObservationId>,
) -> Vec<AgentMemoryProvenance> {
    let node_ids = export
        .graph_nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let nodes = export
        .graph_nodes
        .iter()
        .map(|node: &AgentMemoryGraphNode| {
            (
                format!("node:{}", node.id),
                &node.source_observation_ids,
                false,
            )
        });
    let edges = export
        .graph_edges
        .iter()
        .map(|edge: &AgentMemoryGraphEdge| {
            (
                format!("edge:{}", edge.id),
                &edge.source_observation_ids,
                !node_ids.contains(edge.source_node_id.as_str())
                    || !node_ids.contains(edge.target_node_id.as_str()),
            )
        });
    nodes
        .chain(edges)
        .filter_map(|(key, refs, missing_node)| {
            graph.get(&key).map(|record| {
                let mut sources = refs
                    .iter()
                    .filter_map(|id| observations.get(id).copied())
                    .collect::<Vec<_>>();
                sources.push(*record);
                sources.sort();
                sources.dedup();
                AgentMemoryProvenance {
                    graph_ref: key,
                    source_observation_refs: sources,
                    dangling: missing_node || refs.iter().any(|id| !observations.contains_key(id)),
                }
            })
        })
        .collect()
}

fn map_parse(_: ParseError) -> AgentMemoryImportError {
    AgentMemoryImportError::Unsupported
}
