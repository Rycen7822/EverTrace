use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ids::{CasId, ExperimentRunId, ResultEvidenceId, WorkArtifactId},
    revision::RevisionId,
};

const MAX_REFS: usize = 256;
const MAX_TEXT: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultScope {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompleteness {
    Complete,
    Incomplete,
    Unavailable,
}

impl EvidenceCompleteness {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserStatus {
    Parsed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserFailureCode {
    MetricParseFailed,
    AmbiguousMetricInput,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierStatus {
    Passed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierFailureCode {
    DeterministicReparseMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "code", rename_all = "snake_case")]
pub enum ResultFailure {
    Parser(ParserFailureCode),
    Verifier(VerifierFailureCode),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricValue {
    pub decimal: String,
    pub unit: String,
    pub uncertainty_decimal: Option<String>,
}

impl MetricValue {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if !valid_decimal(&self.decimal)
            || !valid_text(&self.unit)
            || self
                .uncertainty_decimal
                .as_deref()
                .is_some_and(|value| !valid_decimal(value))
        {
            return Err(SemanticError::InvalidResultEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParserReceipt {
    pub parser_version: String,
    pub input_artifact_refs: Vec<WorkArtifactId>,
    pub input_cas_refs: Vec<CasId>,
    pub status: ParserStatus,
    pub failure_code: Option<ParserFailureCode>,
}

impl ParserReceipt {
    fn validate(&self) -> Result<(), SemanticError> {
        if !valid_text(&self.parser_version)
            || self.input_artifact_refs.is_empty() && self.input_cas_refs.is_empty()
            || !canonical(&self.input_artifact_refs)
            || !canonical(&self.input_cas_refs)
            || (self.status == ParserStatus::Failed) != self.failure_code.is_some()
        {
            return Err(SemanticError::InvalidResultEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierReceipt {
    pub verifier_version: String,
    pub status: VerifierStatus,
    pub failure_code: Option<VerifierFailureCode>,
}

impl VerifierReceipt {
    fn validate(&self) -> Result<(), SemanticError> {
        if !valid_text(&self.verifier_version)
            || (self.status == VerifierStatus::Failed) != self.failure_code.is_some()
        {
            return Err(SemanticError::InvalidResultEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultEvidence {
    pub result_evidence_id: ResultEvidenceId,
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub experiment_run_id: ExperimentRunId,
    pub experiment_run_revision_id: RevisionId,
    pub result_scope: ResultScope,
    pub raw_artifact_refs: Vec<WorkArtifactId>,
    pub raw_cas_refs: Vec<CasId>,
    pub parsed_metric: Option<MetricValue>,
    pub parser_receipt: ParserReceipt,
    pub verifier_receipt: Option<VerifierReceipt>,
    pub completeness: EvidenceCompleteness,
    pub failure: Option<ResultFailure>,
    pub created_at_us: i64,
}

impl ResultEvidence {
    pub fn validate(&self) -> Result<(), SemanticError> {
        self.parser_receipt.validate()?;
        if let Some(receipt) = &self.verifier_receipt {
            receipt.validate()?;
        }
        if self.created_at_us < 0
            || self.raw_artifact_refs.is_empty() && self.raw_cas_refs.is_empty()
            || !canonical(&self.raw_artifact_refs)
            || !canonical(&self.raw_cas_refs)
            || self.parser_receipt.input_artifact_refs != self.raw_artifact_refs
            || self.parser_receipt.input_cas_refs != self.raw_cas_refs
            || self.parser_receipt.status == ParserStatus::Failed && self.parsed_metric.is_some()
            || self.parser_receipt.status == ParserStatus::Parsed && self.parsed_metric.is_none()
            || self.completeness == EvidenceCompleteness::Complete
                && !(self.parser_receipt.status == ParserStatus::Parsed
                    && self.parsed_metric.is_some()
                    && self
                        .verifier_receipt
                        .as_ref()
                        .is_some_and(|receipt| receipt.status == VerifierStatus::Passed))
            || self.failure
                != match (
                    self.parser_receipt.failure_code,
                    self.verifier_receipt
                        .as_ref()
                        .and_then(|value| value.failure_code),
                ) {
                    (Some(code), _) => Some(ResultFailure::Parser(code)),
                    (None, Some(code)) => Some(ResultFailure::Verifier(code)),
                    (None, None) => None,
                }
        {
            return Err(SemanticError::InvalidResultEvidence);
        }
        if let Some(metric) = &self.parsed_metric {
            metric.validate()?;
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), SemanticError> {
        next.validate()?;
        let raw_progress = strict_superset(&self.raw_artifact_refs, &next.raw_artifact_refs)
            || strict_superset(&self.raw_cas_refs, &next.raw_cas_refs);
        let parser_compatible = self.parser_receipt.parser_version
            == next.parser_receipt.parser_version
            && contains_all(
                &next.parser_receipt.input_artifact_refs,
                &self.parser_receipt.input_artifact_refs,
            )
            && contains_all(
                &next.parser_receipt.input_cas_refs,
                &self.parser_receipt.input_cas_refs,
            );
        let parser_progress = raw_progress
            && parser_compatible
            && (self.parser_receipt.status == next.parser_receipt.status
                || self.parser_receipt.status == ParserStatus::Failed
                    && next.parser_receipt.status == ParserStatus::Parsed);
        let evidence_progress = raw_progress
            || self.verifier_receipt != next.verifier_receipt
            || self.completeness != next.completeness
            || self.failure != next.failure;
        if self.result_evidence_id != next.result_evidence_id
            || next.parent_revision_id != Some(self.revision_id)
            || self.experiment_run_id != next.experiment_run_id
            || self.experiment_run_revision_id != next.experiment_run_revision_id
            || self.result_scope != next.result_scope
            || !contains_all(&next.raw_artifact_refs, &self.raw_artifact_refs)
            || !contains_all(&next.raw_cas_refs, &self.raw_cas_refs)
            || self.parsed_metric.is_some() && self.parsed_metric != next.parsed_metric
            || self.parser_receipt != next.parser_receipt && !parser_progress
            || next.created_at_us < self.created_at_us
            || self.verifier_receipt.is_some()
                && self.verifier_receipt != next.verifier_receipt
                && !raw_progress
            || !completeness_progress(self.completeness, next.completeness)
            || !evidence_progress
        {
            return Err(SemanticError::InvalidResultSuccessor);
        }
        Ok(())
    }
}

fn completeness_progress(current: EvidenceCompleteness, next: EvidenceCompleteness) -> bool {
    match current {
        EvidenceCompleteness::Incomplete => true,
        EvidenceCompleteness::Complete => next == EvidenceCompleteness::Complete,
        EvidenceCompleteness::Unavailable => next == EvidenceCompleteness::Unavailable,
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

fn valid_decimal(value: &str) -> bool {
    valid_text(value) && value.parse::<f64>().is_ok_and(f64::is_finite)
}

fn canonical<T: Ord>(values: &[T]) -> bool {
    values.len() <= MAX_REFS && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn contains_all<T: Eq>(values: &[T], required: &[T]) -> bool {
    required.iter().all(|value| values.contains(value))
}

fn strict_superset<T: Eq>(current: &[T], next: &[T]) -> bool {
    next.len() > current.len() && contains_all(next, current)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SemanticError {
    #[error("result evidence contract is invalid")]
    InvalidResultEvidence,
    #[error("result evidence successor does not add compatible evidence")]
    InvalidResultSuccessor,
}
