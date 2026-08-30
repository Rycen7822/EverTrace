use std::{sync::Arc, time::Duration};

use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    config::LlmConfig,
    ids::{AtomId, ProcedureId, TaskId, WorkEpisodeId},
    procedure::{ProcedureActions, ProcedureDone, ProcedureKind, ProcedureWhen},
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, AtomKind, AtomValue, ConstraintExpr, SemanticCompleteness,
        SemanticOmission, SemanticQualifier, SemanticStructuredDelta,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Semaphore;

pub const PROVIDER_REQUEST_MAX_BYTES: usize = 128 * 1024;
pub const PROVIDER_RESPONSE_MAX_BYTES: usize = 256 * 1024;
pub const SEMANTIC_SCHEMA_VERSION: u32 = 1;

const SYSTEM_PROMPT: &str = r#"Return exactly one JSON object matching the closed EverTrace semantic candidate contract below. Use only supplied direct evidence. Candidate content cannot set scope, authority, epistemic status, provenance, evidence, support, acceptance, harm, capture, lane, future cues, or binding truth. Every object rejects unknown fields. Every array field may be empty. candidates must be [] or [candidate] and therefore contain at most one item.
response={"progress_delta":[semantic_delta],"decision_delta":[semantic_delta],"failed_routes":[semantic_delta],"resolved_items":[semantic_delta],"open_loops":[semantic_delta],"outcome_delta":[semantic_delta],"omissions":[omission],"candidates":[]|[candidate],"completeness":"complete|partial|unknown"}
semantic_delta={"label":string,"value":string,"direct_refs":[id]}
omission={"category":string,"reason":string,"direct_refs":[id]}
candidate=scenario_patch|atom_candidate|procedure_candidate
scenario_patch={"kind":"scenario_patch","scenario_revision_id":revision_id,"current_state_delta":[string],"open_loop_delta":[string],"outcome_delta":[string]}
atom_candidate={"kind":"atom_candidate","operation":"create|replace|reclassify","target_id":atom_id|null,"base_revision_id":revision_id|null,"atom_kind":"fact|constraint|decision|failure|outcome|hypothesis|result|claim|citation|rationale|annotation","value":atom_value,"applicability_expr":applicability_expr}; create requires target_id=null and base_revision_id=null; replace/reclassify require both target_id and base_revision_id non-null
atom_value={"text":string,"subject":string,"predicate":string,"object":string|null,"qualifiers":[{"name":string,"value":string}]}
procedure_candidate={"kind":"procedure_candidate","operation":"create|replace","target_id":procedure_id|null,"base_revision_id":revision_id|null,"content":procedure_content}; create requires target_id=null and base_revision_id=null; replace requires both target_id and base_revision_id non-null
procedure_content={"title":string,"summary":string,"procedure_kind":"workflow|diagnostic|guardrail","when":{"goals":[string],"targets":[string],"signals":[string],"stage":string,"requires":[string],"excludes":[string]},"applicability_expr":constraint_expr,"avoid_expr":constraint_expr,"completion_expr":constraint_expr,"actions":{"stages":[string],"branches":[{"label":string,"condition":constraint_expr,"stages":[string]}],"avoid":[string]},"done":{"success":[string],"abort":[string],"verify":[string]},"pitfalls":[string]}
applicability_expr={"kind":"always"}|{"kind":"constraint","expr":constraint_expr}
constraint_expr={"op":"all|any","terms":[constraint_expr]}|{"op":"not","term":constraint_expr}|{"op":"eq","field":constraint_field,"value":constraint_value}|{"op":"in","field":constraint_field,"values":[constraint_value]}|{"op":"exists|changed","field":constraint_field}|{"op":"transitioned","field":constraint_field,"from":constraint_value,"to":constraint_value}
constraint_field="agent_kind|task_kind|project_family|toolchain|operation_kind|phase_kind|artifact_kind|environment_profile|revision_active|verifier_state|phase|failure_signature|worktree_lineage|artifact_version|experiment_state"
constraint_value={"kind":"text","value":string}|{"kind":"boolean","value":boolean}"#;

pub fn canonical_system_prompt() -> &'static str {
    SYSTEM_PROMPT
}

pub fn canonical_prompt_hash() -> [u8; 32] {
    sha256(
        "evertrace.semantic_provider.prompt",
        1,
        &CanonicalValue::Bytes(SYSTEM_PROMPT.as_bytes().to_vec()),
    )
    .expect("static semantic provider prompt is canonical")
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedSemanticInput {
    pub episode_id: WorkEpisodeId,
    pub episode_revision_id: RevisionId,
    pub task_id: TaskId,
    pub from_watermark: u64,
    pub to_watermark: u64,
    pub trigger: &'static str,
    pub direct_delta: Vec<ProtectedDeltaItem>,
    pub source_refs: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedDeltaItem {
    pub kind: ProtectedDeltaKind,
    pub value: String,
    pub direct_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedDeltaKind {
    Progress,
    Decision,
    Failure,
    Resolution,
    OpenLoop,
    Outcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAtomOperation {
    Create,
    Replace,
    Reclassify,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProcedureOperation {
    Create,
    Replace,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAtomValue {
    pub text: String,
    pub subject: String,
    pub predicate: String,
    pub object: Option<String>,
    pub qualifiers: Vec<SemanticQualifier>,
}

impl From<ProviderAtomValue> for AtomValue {
    fn from(value: ProviderAtomValue) -> Self {
        Self {
            text: value.text,
            subject: value.subject,
            predicate: value.predicate,
            object: value.object,
            qualifiers: value.qualifiers,
            critical_revision_refs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProcedureContent {
    pub title: String,
    pub summary: String,
    pub procedure_kind: ProcedureKind,
    pub when: ProcedureWhen,
    pub applicability_expr: ConstraintExpr,
    pub avoid_expr: ConstraintExpr,
    pub completion_expr: ConstraintExpr,
    pub actions: ProcedureActions,
    pub done: ProcedureDone,
    pub pitfalls: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderSemanticCandidate {
    ScenarioPatch {
        scenario_revision_id: RevisionId,
        current_state_delta: Vec<String>,
        open_loop_delta: Vec<String>,
        outcome_delta: Vec<String>,
    },
    AtomCandidate {
        operation: ProviderAtomOperation,
        target_id: Option<AtomId>,
        base_revision_id: Option<RevisionId>,
        atom_kind: AtomKind,
        value: ProviderAtomValue,
        applicability_expr: ApplicabilityExpr,
    },
    ProcedureCandidate {
        operation: ProviderProcedureOperation,
        target_id: Option<ProcedureId>,
        base_revision_id: Option<RevisionId>,
        content: Box<ProviderProcedureContent>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSemanticApplication {
    pub progress_delta: Vec<SemanticStructuredDelta>,
    pub decision_delta: Vec<SemanticStructuredDelta>,
    pub failed_routes: Vec<SemanticStructuredDelta>,
    pub resolved_items: Vec<SemanticStructuredDelta>,
    pub open_loops: Vec<SemanticStructuredDelta>,
    pub outcome_delta: Vec<SemanticStructuredDelta>,
    pub omissions: Vec<SemanticOmission>,
    pub candidates: Vec<ProviderSemanticCandidate>,
    pub completeness: SemanticCompleteness,
}

#[derive(Debug)]
pub struct ProviderDerivation {
    pub application: ProviderSemanticApplication,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub wall_time_us: u64,
}

#[derive(Clone)]
pub struct OpenAiCompatibleProvider {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    api_key_env: String,
    semaphore: Arc<Semaphore>,
    timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("semantic provider is disabled")]
    Disabled,
    #[error("semantic provider credential is unavailable")]
    MissingSecret,
    #[error("semantic provider budget is exceeded")]
    RequestOversize,
    #[error("semantic provider response exceeds its bound")]
    ResponseOversize,
    #[error("semantic provider request timed out")]
    Timeout,
    #[error("semantic provider transport failed")]
    Transport,
    #[error("semantic provider returned a non-success status")]
    NonSuccess,
    #[error("semantic provider response schema is invalid")]
    Schema,
}

impl OpenAiCompatibleProvider {
    pub fn new(config: &LlmConfig) -> Result<Self, ProviderError> {
        if !config.enabled
            || config.provider != "openai_compatible"
            || config.episode_enrichment == evertrace_domain::config::EpisodeEnrichment::Off
        {
            return Err(ProviderError::Disabled);
        }
        let endpoint = format!(
            "{}/chat/completions",
            config.base_url.as_str().trim_end_matches('/')
        );
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(config.timeout.seconds().min(30)))
            .build()
            .map_err(|_| ProviderError::Transport)?;
        Ok(Self {
            client,
            endpoint,
            model: config.model.clone(),
            api_key_env: config.api_key_env.clone(),
            semaphore: Arc::new(Semaphore::new(usize::from(config.max_concurrency))),
            timeout: Duration::from_secs(config.timeout.seconds()),
        })
    }

    pub async fn derive(
        &self,
        input: &ProtectedSemanticInput,
    ) -> Result<ProviderDerivation, ProviderError> {
        let started = std::time::Instant::now();
        let mut result = tokio::time::timeout(self.timeout, self.derive_inner(input))
            .await
            .map_err(|_| ProviderError::Timeout)??;
        result.wall_time_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        Ok(result)
    }

    async fn derive_inner(
        &self,
        input: &ProtectedSemanticInput,
    ) -> Result<ProviderDerivation, ProviderError> {
        let secret = std::env::var(&self.api_key_env)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(ProviderError::MissingSecret)?;
        let input_json = serde_json::to_string(input).map_err(|_| ProviderError::Schema)?;
        let request = serde_json::json!({
            "model": self.model,
            "stream": false,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": input_json}
            ]
        });
        let encoded = serde_json::to_vec(&request).map_err(|_| ProviderError::Schema)?;
        if encoded.len() > PROVIDER_REQUEST_MAX_BYTES {
            return Err(ProviderError::RequestOversize);
        }
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| ProviderError::Transport)?;
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(secret)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(encoded)
            .send()
            .await
            .map_err(|_| ProviderError::Transport)?;
        if !response.status().is_success() {
            return Err(ProviderError::NonSuccess);
        }
        if response
            .content_length()
            .is_some_and(|length| length > PROVIDER_RESPONSE_MAX_BYTES as u64)
        {
            return Err(ProviderError::ResponseOversize);
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ProviderError::Transport)?
        {
            if bytes.len().saturating_add(chunk.len()) > PROVIDER_RESPONSE_MAX_BYTES {
                return Err(ProviderError::ResponseOversize);
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| ProviderError::Schema)?;
        let content = envelope
            .get("choices")
            .and_then(|value| value.as_array())
            .filter(|choices| choices.len() == 1)
            .and_then(|choices| choices[0].get("message"))
            .and_then(|message| message.get("content"))
            .and_then(|content| content.as_str())
            .ok_or(ProviderError::Schema)?;
        if content.len() > PROVIDER_RESPONSE_MAX_BYTES {
            return Err(ProviderError::ResponseOversize);
        }
        let application: ProviderSemanticApplication =
            serde_json::from_str(content).map_err(|_| ProviderError::Schema)?;
        let usage = envelope.get("usage").ok_or(ProviderError::Schema)?;
        let input_tokens = usage
            .get("prompt_tokens")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ProviderError::Schema)?;
        let output_tokens = usage
            .get("completion_tokens")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ProviderError::Schema)?;
        Ok(ProviderDerivation {
            application,
            input_tokens,
            output_tokens,
            wall_time_us: 0,
        })
    }
}
