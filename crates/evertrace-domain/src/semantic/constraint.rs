use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::SemanticError;

const MAX_EXPR_DEPTH: usize = 12;
const MAX_EXPR_NODES: usize = 128;
const MAX_BOOLEAN_TERMS: usize = 32;
const MAX_IN_VALUES: usize = 64;
const MAX_FIELD_VALUE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintField {
    AgentKind,
    TaskKind,
    ProjectFamily,
    Toolchain,
    OperationKind,
    PhaseKind,
    ArtifactKind,
    EnvironmentProfile,
    RevisionActive,
    VerifierState,
    Phase,
    FailureSignature,
    WorktreeLineage,
    ArtifactVersion,
    ExperimentState,
}

impl ConstraintField {
    const fn supports_transition(self) -> bool {
        matches!(
            self,
            Self::PhaseKind
                | Self::RevisionActive
                | Self::VerifierState
                | Self::Phase
                | Self::WorktreeLineage
                | Self::ArtifactVersion
                | Self::ExperimentState
        )
    }

    const fn accepts(self, value: &ConstraintValue) -> bool {
        matches!(
            (self, value),
            (Self::RevisionActive, ConstraintValue::Boolean(_))
                | (
                    Self::AgentKind
                        | Self::TaskKind
                        | Self::ProjectFamily
                        | Self::Toolchain
                        | Self::OperationKind
                        | Self::PhaseKind
                        | Self::ArtifactKind
                        | Self::EnvironmentProfile
                        | Self::VerifierState
                        | Self::Phase
                        | Self::FailureSignature
                        | Self::WorktreeLineage
                        | Self::ArtifactVersion
                        | Self::ExperimentState,
                    ConstraintValue::Text(_)
                )
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ConstraintValue {
    Text(String),
    Boolean(bool),
}

impl ConstraintValue {
    fn validate(&self) -> Result<(), SemanticError> {
        match self {
            Self::Text(value)
                if value.is_empty()
                    || value.len() > MAX_FIELD_VALUE_BYTES
                    || value.chars().any(char::is_control) =>
            {
                Err(SemanticError::InvalidConstraintExpr)
            }
            Self::Text(_) | Self::Boolean(_) => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintBinding {
    pub field: ConstraintField,
    pub value: ConstraintValue,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintState {
    pub bindings: Vec<ConstraintBinding>,
}

impl ConstraintState {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.bindings.len() > MAX_EXPR_NODES
            || !self
                .bindings
                .windows(2)
                .all(|pair| pair[0].field < pair[1].field)
        {
            return Err(SemanticError::InvalidConstraintState);
        }
        for binding in &self.bindings {
            binding.value.validate()?;
            if !binding.field.accepts(&binding.value) {
                return Err(SemanticError::InvalidConstraintState);
            }
        }
        Ok(())
    }

    fn values(&self) -> Result<BTreeMap<ConstraintField, &ConstraintValue>, SemanticError> {
        self.validate()?;
        Ok(self
            .bindings
            .iter()
            .map(|binding| (binding.field, &binding.value))
            .collect())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConstraintExpr {
    All {
        terms: Vec<Self>,
    },
    Any {
        terms: Vec<Self>,
    },
    Not {
        term: Box<Self>,
    },
    Eq {
        field: ConstraintField,
        value: ConstraintValue,
    },
    In {
        field: ConstraintField,
        values: Vec<ConstraintValue>,
    },
    Exists {
        field: ConstraintField,
    },
    Changed {
        field: ConstraintField,
    },
    Transitioned {
        field: ConstraintField,
        from: ConstraintValue,
        to: ConstraintValue,
    },
}

impl ConstraintExpr {
    pub fn validate(&self) -> Result<(), SemanticError> {
        let mut nodes = 0;
        self.validate_inner(1, &mut nodes)
    }

    fn validate_inner(&self, depth: usize, nodes: &mut usize) -> Result<(), SemanticError> {
        *nodes = nodes
            .checked_add(1)
            .ok_or(SemanticError::InvalidConstraintExpr)?;
        if depth > MAX_EXPR_DEPTH || *nodes > MAX_EXPR_NODES {
            return Err(SemanticError::InvalidConstraintExpr);
        }
        match self {
            Self::All { terms } | Self::Any { terms } => {
                if terms.is_empty() || terms.len() > MAX_BOOLEAN_TERMS {
                    return Err(SemanticError::InvalidConstraintExpr);
                }
                for term in terms {
                    term.validate_inner(depth + 1, nodes)?;
                }
            }
            Self::Not { term } => term.validate_inner(depth + 1, nodes)?,
            Self::Eq { field, value } => {
                value.validate()?;
                if !field.accepts(value) {
                    return Err(SemanticError::InvalidConstraintExpr);
                }
            }
            Self::In { field, values } => {
                if values.is_empty()
                    || values.len() > MAX_IN_VALUES
                    || !values.windows(2).all(|pair| pair[0] < pair[1])
                {
                    return Err(SemanticError::InvalidConstraintExpr);
                }
                for value in values {
                    value.validate()?;
                    if !field.accepts(value) {
                        return Err(SemanticError::InvalidConstraintExpr);
                    }
                }
            }
            Self::Exists { .. } | Self::Changed { .. } => {}
            Self::Transitioned { field, from, to } => {
                from.validate()?;
                to.validate()?;
                if !field.supports_transition()
                    || !field.accepts(from)
                    || !field.accepts(to)
                    || from == to
                {
                    return Err(SemanticError::InvalidConstraintExpr);
                }
            }
        }
        Ok(())
    }

    pub fn evaluate(
        &self,
        current: &ConstraintState,
        previous: Option<&ConstraintState>,
    ) -> ConstraintTruth {
        if self.validate().is_err() {
            return ConstraintTruth::Unknown;
        }
        let Ok(current) = current.values() else {
            return ConstraintTruth::Unknown;
        };
        let previous = match previous.map(ConstraintState::values).transpose() {
            Ok(value) => value,
            Err(_) => return ConstraintTruth::Unknown,
        };
        self.evaluate_inner(&current, previous.as_ref())
    }

    fn evaluate_inner(
        &self,
        current: &BTreeMap<ConstraintField, &ConstraintValue>,
        previous: Option<&BTreeMap<ConstraintField, &ConstraintValue>>,
    ) -> ConstraintTruth {
        match self {
            Self::All { terms } => terms.iter().fold(ConstraintTruth::True, |value, term| {
                value.and(term.evaluate_inner(current, previous))
            }),
            Self::Any { terms } => terms.iter().fold(ConstraintTruth::False, |value, term| {
                value.or(term.evaluate_inner(current, previous))
            }),
            Self::Not { term } => term.evaluate_inner(current, previous).not(),
            Self::Eq { field, value } => current
                .get(field)
                .map_or(ConstraintTruth::Unknown, |observed| {
                    ConstraintTruth::from(**observed == *value)
                }),
            Self::In { field, values } => current
                .get(field)
                .map_or(ConstraintTruth::Unknown, |observed| {
                    ConstraintTruth::from(values.contains(observed))
                }),
            Self::Exists { field } => {
                if current.contains_key(field) {
                    ConstraintTruth::True
                } else {
                    ConstraintTruth::Unknown
                }
            }
            Self::Changed { field } => {
                let Some(previous) = previous else {
                    return ConstraintTruth::Unknown;
                };
                match (previous.get(field), current.get(field)) {
                    (Some(before), Some(after)) => ConstraintTruth::from(before != after),
                    _ => ConstraintTruth::Unknown,
                }
            }
            Self::Transitioned { field, from, to } => {
                if !field.supports_transition() || from == to {
                    return ConstraintTruth::Unknown;
                }
                let Some(previous) = previous else {
                    return ConstraintTruth::Unknown;
                };
                match (previous.get(field), current.get(field)) {
                    (Some(before), Some(after)) => {
                        ConstraintTruth::from(**before == *from && **after == *to)
                    }
                    _ => ConstraintTruth::Unknown,
                }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "expr",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ApplicabilityExpr {
    Always,
    Constraint(ConstraintExpr),
}

impl ApplicabilityExpr {
    pub fn validate(&self) -> Result<(), SemanticError> {
        match self {
            Self::Always => Ok(()),
            Self::Constraint(expr) => expr.validate(),
        }
    }

    pub fn evaluate(
        &self,
        current: &ConstraintState,
        previous: Option<&ConstraintState>,
    ) -> ConstraintTruth {
        match self {
            Self::Always => ConstraintTruth::True,
            Self::Constraint(expr) => expr.evaluate(current, previous),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintTruth {
    True,
    False,
    Unknown,
}

impl ConstraintTruth {
    pub const fn allows_enforcement(self) -> bool {
        matches!(self, Self::True)
    }

    const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }

    const fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

impl From<bool> for ConstraintTruth {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}
