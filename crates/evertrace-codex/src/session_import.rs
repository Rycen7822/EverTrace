//! Frozen AgentMemory v0.9.29 one-shot export adapter.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize, de::IgnoredAny};
use thiserror::Error;

pub const AGENT_MEMORY_EXPORT_VERSION: &str = "0.9.29";
pub const AGENT_MEMORY_MAX_BYTES: usize = 15 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AgentMemoryImportError {
    #[error("AgentMemory export is oversized")]
    Oversized,
    #[error("AgentMemory export format is unsupported")]
    Unsupported,
    #[error("AgentMemory export contains duplicate or inconsistent identities")]
    Inconsistent,
}

const MAX_RECORDS: usize = 100_000;
const MAX_TEXT_BYTES: usize = 1 << 20;
const MAX_REFS: usize = 16_384;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMemorySession {
    pub id: String,
    pub project: String,
    pub cwd: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "endedAt")]
    pub ended_at: Option<String>,
    pub status: AgentMemorySessionStatus,
    #[serde(rename = "observationCount")]
    pub observation_count: u64,
    pub model: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(rename = "firstPrompt")]
    pub first_prompt: Option<String>,
    pub summary: Option<String>,
    #[serde(rename = "commitShas")]
    pub commit_shas: Option<Vec<String>>,
    #[serde(rename = "agentId")]
    pub agent_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMemorySessionStatus {
    Active,
    Completed,
    Abandoned,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMemoryObservation {
    pub id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub timestamp: String,
    #[serde(rename = "type")]
    pub observation_type: AgentMemoryObservationType,
    pub title: String,
    pub subtitle: Option<String>,
    pub facts: Vec<String>,
    pub narrative: String,
    pub concepts: Vec<String>,
    pub files: Vec<String>,
    pub importance: f64,
    pub confidence: Option<f64>,
    #[serde(rename = "imageRef")]
    pub image_ref: Option<String>,
    #[serde(rename = "imageData")]
    pub image_data: Option<String>,
    #[serde(rename = "imageDescription")]
    pub image_description: Option<String>,
    pub modality: Option<AgentMemoryModality>,
    #[serde(rename = "agentId")]
    pub agent_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMemoryObservationType {
    FileRead,
    FileWrite,
    FileEdit,
    CommandRun,
    Search,
    WebFetch,
    Conversation,
    Error,
    Decision,
    Discovery,
    Subagent,
    Notification,
    Task,
    Image,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMemoryModality {
    Text,
    Image,
    Mixed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMemoryMemory {
    pub id: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "type")]
    pub memory_type: AgentMemoryMemoryType,
    pub title: String,
    pub content: String,
    pub concepts: Vec<String>,
    pub files: Vec<String>,
    #[serde(rename = "sessionIds")]
    pub session_ids: Vec<String>,
    pub strength: f64,
    pub version: u64,
    #[serde(rename = "parentId")]
    pub parent_id: Option<String>,
    pub supersedes: Option<Vec<String>>,
    #[serde(rename = "relatedIds")]
    pub related_ids: Option<Vec<String>>,
    #[serde(rename = "sourceObservationIds")]
    pub source_observation_ids: Option<Vec<String>>,
    #[serde(rename = "isLatest")]
    pub is_latest: bool,
    #[serde(rename = "forgetAfter")]
    pub forget_after: Option<String>,
    #[serde(rename = "imageRef")]
    pub image_ref: Option<String>,
    #[serde(rename = "imageData")]
    pub image_data: Option<String>,
    #[serde(rename = "agentId")]
    pub agent_id: Option<String>,
    pub project: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMemoryMemoryType {
    Pattern,
    Preference,
    Architecture,
    Bug,
    Workflow,
    Fact,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMemoryGraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: AgentMemoryGraphNodeType,
    pub name: String,
    pub properties: BTreeMap<String, serde_json::Value>,
    #[serde(rename = "sourceObservationIds")]
    pub source_observation_ids: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub stale: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMemoryGraphNodeType {
    File,
    Function,
    Concept,
    Error,
    Decision,
    Pattern,
    Library,
    Person,
    Project,
    Preference,
    Location,
    Organization,
    Event,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMemoryGraphEdge {
    pub id: String,
    #[serde(rename = "type")]
    pub edge_type: AgentMemoryGraphEdgeType,
    #[serde(rename = "sourceNodeId")]
    pub source_node_id: String,
    #[serde(rename = "targetNodeId")]
    pub target_node_id: String,
    pub weight: f64,
    #[serde(rename = "sourceObservationIds")]
    pub source_observation_ids: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub tcommit: Option<String>,
    pub tvalid: Option<String>,
    #[serde(rename = "tvalidEnd")]
    pub tvalid_end: Option<String>,
    pub context: Option<AgentMemoryEdgeContext>,
    pub version: Option<u64>,
    #[serde(rename = "supersededBy")]
    pub superseded_by: Option<String>,
    #[serde(rename = "isLatest")]
    pub is_latest: Option<bool>,
    pub stale: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMemoryGraphEdgeType {
    Uses,
    Imports,
    Modifies,
    Causes,
    Fixes,
    DependsOn,
    RelatedTo,
    WorksAt,
    Prefers,
    BlockedBy,
    CausedBy,
    OptimizesFor,
    Rejected,
    Avoids,
    LocatedIn,
    SucceededBy,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMemoryEdgeContext {
    pub reasoning: Option<String>,
    pub sentiment: Option<String>,
    pub alternatives: Option<Vec<String>>,
    #[serde(rename = "situationalFactors")]
    pub situational_factors: Option<Vec<String>>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportData {
    version: String,
    #[serde(rename = "exportedAt")]
    exported_at: String,
    sessions: Vec<AgentMemorySession>,
    observations: BTreeMap<String, Vec<AgentMemoryObservation>>,
    memories: Vec<AgentMemoryMemory>,
    summaries: Vec<IgnoredAny>,
    profiles: Option<Vec<IgnoredAny>>,
    #[serde(rename = "graphNodes")]
    graph_nodes: Option<Vec<AgentMemoryGraphNode>>,
    #[serde(rename = "graphEdges")]
    graph_edges: Option<Vec<AgentMemoryGraphEdge>>,
    #[serde(rename = "semanticMemories")]
    semantic_memories: Option<Vec<IgnoredAny>>,
    #[serde(rename = "proceduralMemories")]
    procedural_memories: Option<Vec<IgnoredAny>>,
    actions: Option<Vec<IgnoredAny>>,
    #[serde(rename = "actionEdges")]
    action_edges: Option<Vec<IgnoredAny>>,
    routines: Option<Vec<IgnoredAny>>,
    signals: Option<Vec<IgnoredAny>>,
    checkpoints: Option<Vec<IgnoredAny>>,
    sentinels: Option<Vec<IgnoredAny>>,
    sketches: Option<Vec<IgnoredAny>>,
    crystals: Option<Vec<IgnoredAny>>,
    facets: Option<Vec<IgnoredAny>>,
    lessons: Option<Vec<IgnoredAny>>,
    insights: Option<Vec<IgnoredAny>>,
    #[serde(rename = "accessLogs")]
    access_logs: Option<Vec<IgnoredAny>>,
}

#[derive(Debug, PartialEq)]
pub struct AgentMemoryExport {
    pub exported_at: String,
    pub sessions: Vec<AgentMemorySession>,
    pub observations: Vec<AgentMemoryObservation>,
    pub memories: Vec<AgentMemoryMemory>,
    pub graph_nodes: Vec<AgentMemoryGraphNode>,
    pub graph_edges: Vec<AgentMemoryGraphEdge>,
    pub dangling_refs: Vec<String>,
}

pub fn parse_agent_memory_export(
    bytes: &[u8],
) -> Result<AgentMemoryExport, AgentMemoryImportError> {
    if bytes.len() > AGENT_MEMORY_MAX_BYTES {
        return Err(AgentMemoryImportError::Oversized);
    }
    let value: ExportData =
        serde_json::from_slice(bytes).map_err(|_| AgentMemoryImportError::Unsupported)?;
    if value.version != AGENT_MEMORY_EXPORT_VERSION {
        return Err(AgentMemoryImportError::Unsupported);
    }
    if value.sessions.len() > MAX_RECORDS
        || value.memories.len() > MAX_RECORDS
        || value
            .graph_nodes
            .as_ref()
            .is_some_and(|v| v.len() > MAX_RECORDS)
        || value
            .graph_edges
            .as_ref()
            .is_some_and(|v| v.len() > MAX_RECORDS)
        || !valid_text(&value.exported_at)
    {
        return Err(AgentMemoryImportError::Inconsistent);
    }
    let _ = (
        &value.summaries,
        &value.profiles,
        &value.semantic_memories,
        &value.procedural_memories,
        &value.actions,
        &value.action_edges,
        &value.routines,
        &value.signals,
        &value.checkpoints,
        &value.sentinels,
        &value.sketches,
        &value.crystals,
        &value.facets,
        &value.lessons,
        &value.insights,
        &value.access_logs,
    );
    let session_ids = unique(value.sessions.iter().map(|item| item.id.as_str()))?;
    for session in &value.sessions {
        if !valid_text(&session.project)
            || !valid_text(&session.cwd)
            || !valid_text(&session.started_at)
            || session.ended_at.as_deref().is_some_and(|v| !valid_text(v))
            || !bounded_texts(session.tags.as_deref().unwrap_or_default())
            || !bounded_texts(session.commit_shas.as_deref().unwrap_or_default())
            || u64::try_from(value.observations.get(&session.id).map_or(0, Vec::len)).ok()
                != Some(session.observation_count)
        {
            return Err(AgentMemoryImportError::Inconsistent);
        }
    }
    let mut observations = Vec::new();
    for (bucket, items) in value.observations {
        if !session_ids.contains(bucket.as_str())
            || observations.len().saturating_add(items.len()) > MAX_RECORDS
            || items.iter().any(|item| item.session_id != bucket)
        {
            return Err(AgentMemoryImportError::Inconsistent);
        }
        for item in &items {
            if !item.importance.is_finite()
                || item.confidence.is_some_and(|v| !v.is_finite())
                || !valid_text(&item.timestamp)
                || !valid_text(&item.title)
                || !valid_text(&item.narrative)
                || !bounded_texts(&item.facts)
                || !bounded_texts(&item.concepts)
                || !bounded_texts(&item.files)
            {
                return Err(AgentMemoryImportError::Inconsistent);
            }
        }
        observations.extend(items);
    }
    let observation_ids = unique(observations.iter().map(|item| item.id.as_str()))?;
    let memory_ids = unique(value.memories.iter().map(|item| item.id.as_str()))?;
    for memory in &value.memories {
        if !memory.strength.is_finite()
            || memory.version == 0
            || !valid_text(&memory.created_at)
            || !valid_text(&memory.updated_at)
            || !valid_text(&memory.title)
            || !valid_text(&memory.content)
            || !bounded_texts(&memory.concepts)
            || !bounded_texts(&memory.files)
            || !bounded_texts(&memory.session_ids)
            || memory
                .session_ids
                .iter()
                .any(|id| !session_ids.contains(id.as_str()))
        {
            return Err(AgentMemoryImportError::Inconsistent);
        }
    }
    let graph_nodes = value.graph_nodes.unwrap_or_default();
    let node_ids = unique(graph_nodes.iter().map(|item| item.id.as_str()))?;
    if graph_nodes.iter().any(|node| {
        !valid_text(&node.name)
            || !node.properties.values().all(valid_json_value)
            || !bounded_texts(&node.source_observation_ids)
            || !bounded_texts(node.aliases.as_deref().unwrap_or_default())
    }) {
        return Err(AgentMemoryImportError::Inconsistent);
    }
    let graph_edges = value.graph_edges.unwrap_or_default();
    unique(graph_edges.iter().map(|item| item.id.as_str()))?;
    if graph_edges.iter().any(|edge| {
        !edge.weight.is_finite()
            || !bounded_texts(&edge.source_observation_ids)
            || edge.context.as_ref().is_some_and(|context| {
                context.confidence.is_some_and(|v| !v.is_finite())
                    || !bounded_texts(context.alternatives.as_deref().unwrap_or_default())
                    || !bounded_texts(context.situational_factors.as_deref().unwrap_or_default())
            })
    }) {
        return Err(AgentMemoryImportError::Inconsistent);
    }
    let mut dangling = BTreeSet::new();
    for memory in &value.memories {
        for id in memory.source_observation_ids.iter().flatten() {
            if !observation_ids.contains(id.as_str()) {
                dangling.insert(format!("observation:{id}"));
            }
        }
        for id in memory
            .parent_id
            .iter()
            .chain(memory.supersedes.iter().flatten())
            .chain(memory.related_ids.iter().flatten())
        {
            if !memory_ids.contains(id.as_str()) {
                dangling.insert(format!("memory:{id}"));
            }
        }
    }
    for node in &graph_nodes {
        for id in &node.source_observation_ids {
            if !observation_ids.contains(id.as_str()) {
                dangling.insert(format!("observation:{id}"));
            }
        }
    }
    for edge in &graph_edges {
        if !node_ids.contains(edge.source_node_id.as_str()) {
            dangling.insert(format!("node:{}", edge.source_node_id));
        }
        if !node_ids.contains(edge.target_node_id.as_str()) {
            dangling.insert(format!("node:{}", edge.target_node_id));
        }
        for id in &edge.source_observation_ids {
            if !observation_ids.contains(id.as_str()) {
                dangling.insert(format!("observation:{id}"));
            }
        }
    }
    Ok(AgentMemoryExport {
        exported_at: value.exported_at,
        sessions: value.sessions,
        observations,
        memories: value.memories,
        graph_nodes,
        graph_edges,
        dangling_refs: dangling.into_iter().collect(),
    })
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

fn bounded_texts(values: &[String]) -> bool {
    values.len() <= MAX_REFS && values.iter().all(|value| valid_text(value))
}

fn valid_json_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => true,
        serde_json::Value::Number(value) => value.as_f64().is_some_and(f64::is_finite),
        serde_json::Value::Array(values) => {
            values.len() <= MAX_REFS && values.iter().all(valid_json_value)
        }
        serde_json::Value::Object(values) => {
            values.len() <= MAX_REFS
                && values.keys().all(|key| valid_text(key))
                && values.values().all(valid_json_value)
        }
    }
}

fn unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<&'a str>, AgentMemoryImportError> {
    let mut result = BTreeSet::new();
    for value in values {
        if value.is_empty() || !result.insert(value) {
            return Err(AgentMemoryImportError::Inconsistent);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn export() -> Value {
        json!({
            "version": "0.9.29",
            "exportedAt": "2026-08-30T00:00:00Z",
            "sessions": [{
                "id": "session-a", "project": "project-a", "cwd": "/repo",
                "startedAt": "2026-08-30T00:00:00Z", "status": "completed",
                "observationCount": 1
            }],
            "observations": {"session-a": [{
                "id": "observation-a", "sessionId": "session-a",
                "timestamp": "2026-08-30T00:00:01Z", "type": "decision",
                "title": "decision", "facts": ["fact"], "narrative": "narrative",
                "concepts": ["concept"], "files": ["file"], "importance": 0.8
            }]},
            "memories": [{
                "id": "memory-a", "createdAt": "2026-08-30T00:00:02Z",
                "updatedAt": "2026-08-30T00:00:02Z", "type": "fact",
                "title": "memory", "content": "content", "concepts": ["concept"],
                "files": ["file"], "sessionIds": ["session-a"], "strength": 0.7,
                "version": 1, "isLatest": true,
                "sourceObservationIds": ["observation-a"]
            }],
            "summaries": [],
            "graphNodes": [{
                "id": "node-a", "type": "concept", "name": "concept",
                "properties": {}, "sourceObservationIds": ["observation-a"],
                "createdAt": "2026-08-30T00:00:03Z"
            }],
            "graphEdges": []
        })
    }

    #[test]
    fn parses_exact_complete_v0_9_29_export() {
        let bytes = serde_json::to_vec(&export()).unwrap();
        let parsed = parse_agent_memory_export(&bytes).unwrap();
        assert_eq!(parsed.sessions.len(), 1);
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(parsed.memories.len(), 1);
        assert!(parsed.dangling_refs.is_empty());
    }

    #[test]
    fn rejects_version_pagination_unknown_and_error_envelopes() {
        for mut value in [
            json!({"success": false, "error": "failed"}),
            export(),
            export(),
            export(),
        ] {
            if value.get("version").is_some() && value.get("pagination").is_none() {
                value.as_object_mut().unwrap().insert(
                    "pagination".into(),
                    json!({"offset": 0, "limit": 1, "total": 1, "hasMore": false}),
                );
            }
            assert_eq!(
                parse_agent_memory_export(&serde_json::to_vec(&value).unwrap()),
                Err(AgentMemoryImportError::Unsupported)
            );
        }
        let mut wrong = export();
        wrong["version"] = json!("0.9.28");
        assert_eq!(
            parse_agent_memory_export(&serde_json::to_vec(&wrong).unwrap()),
            Err(AgentMemoryImportError::Unsupported)
        );
        let mut unknown = export();
        unknown["futureCollection"] = json!([]);
        assert_eq!(
            parse_agent_memory_export(&serde_json::to_vec(&unknown).unwrap()),
            Err(AgentMemoryImportError::Unsupported)
        );
        let mut wrong_collection = export();
        wrong_collection["profiles"] = json!("not-an-array");
        assert_eq!(
            parse_agent_memory_export(&serde_json::to_vec(&wrong_collection).unwrap()),
            Err(AgentMemoryImportError::Unsupported)
        );
    }

    #[test]
    fn rejects_duplicate_and_bucket_session_mismatch_and_reports_dangling_graph() {
        let mut duplicate = export();
        duplicate["sessions"] = json!([
            duplicate["sessions"][0].clone(),
            duplicate["sessions"][0].clone()
        ]);
        assert_eq!(
            parse_agent_memory_export(&serde_json::to_vec(&duplicate).unwrap()),
            Err(AgentMemoryImportError::Inconsistent)
        );

        let mut mismatch = export();
        mismatch["observations"]["session-a"][0]["sessionId"] = json!("session-b");
        assert_eq!(
            parse_agent_memory_export(&serde_json::to_vec(&mismatch).unwrap()),
            Err(AgentMemoryImportError::Inconsistent)
        );

        let mut dangling = export();
        dangling["graphEdges"] = json!([{
            "id": "edge-a", "type": "related_to", "sourceNodeId": "node-a",
            "targetNodeId": "missing", "weight": 1.0,
            "sourceObservationIds": ["missing-observation"],
            "createdAt": "2026-08-30T00:00:04Z"
        }]);
        let parsed = parse_agent_memory_export(&serde_json::to_vec(&dangling).unwrap()).unwrap();
        assert_eq!(
            parsed.dangling_refs,
            ["node:missing", "observation:missing-observation"]
        );
    }

    #[test]
    fn rejects_oversized_without_parsing() {
        let bytes = vec![b' '; AGENT_MEMORY_MAX_BYTES + 1];
        assert_eq!(
            parse_agent_memory_export(&bytes),
            Err(AgentMemoryImportError::Oversized)
        );
    }
}
