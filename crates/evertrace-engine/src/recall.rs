use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use evertrace_domain::{
    ids::{RepositoryId, TaskId, WorktreeId},
    recall::{FutureCueContract, FutureCueDiagnostic, compile_atom_future_cue},
    semantic::{AtomScope, ConstraintField, ConstraintState, ConstraintTruth},
};
use evertrace_store::{
    ObjectRowClass, StoreError,
    projections::{
        ProjectionSnapshot, RECALL_TRIGGER_INDEX_KIND, SemanticCurrentView, recall_trigger_contract,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutureCueCompilationDiagnostic {
    pub source_revision_id: String,
    pub diagnostic: FutureCueDiagnostic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutureCueCompilationReport {
    pub frontier: u64,
    pub contracts: Vec<FutureCueContract>,
    pub diagnostics: Vec<FutureCueCompilationDiagnostic>,
}

pub struct FutureCueCompiler;

impl FutureCueCompiler {
    pub fn compile(
        snapshot: &ProjectionSnapshot,
    ) -> Result<FutureCueCompilationReport, StoreError> {
        let current = SemanticCurrentView::from_snapshot(snapshot)?;
        let source_rows = snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("atom_revision"))
            .map(|row| {
                let revision = row
                    .current_revision_id
                    .clone()
                    .ok_or(StoreError::StoreCorrupt)?;
                Ok((revision, row.source_event_seq))
            })
            .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
        let mut contracts = Vec::new();
        let mut diagnostics = Vec::new();
        for atom in current
            .atoms
            .values()
            .filter(|atom| atom.kind.is_normative())
        {
            let source_revision_id = atom.revision_id.to_string();
            let watermark = source_rows
                .get(&source_revision_id)
                .copied()
                .ok_or(StoreError::StoreCorrupt)?;
            match compile_atom_future_cue(atom, true, watermark) {
                Ok(contract) => contracts.push(contract),
                Err(diagnostic) => diagnostics.push(FutureCueCompilationDiagnostic {
                    source_revision_id,
                    diagnostic,
                }),
            }
        }
        contracts.sort_by_key(|contract| contract.future_cue_contract_id);
        diagnostics.sort_by(|left, right| left.source_revision_id.cmp(&right.source_revision_id));
        Ok(FutureCueCompilationReport {
            frontier: snapshot.frontier,
            contracts,
            diagnostics,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallTriggerEntry {
    pub contract: FutureCueContract,
    pub scope: AtomScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallTriggerIndex {
    pub frontier: u64,
    pub entries: Vec<RecallTriggerEntry>,
    field_entries: BTreeMap<ConstraintField, Vec<usize>>,
}

impl RecallTriggerIndex {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut ids = BTreeSet::new();
        let mut sources = BTreeSet::new();
        let mut entries = Vec::new();
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some(RECALL_TRIGGER_INDEX_KIND))
        {
            if row.row_class != Some(ObjectRowClass::Projection)
                || row.source_event_seq > snapshot.frontier
            {
                return Err(StoreError::StoreCorrupt);
            }
            let contract = recall_trigger_contract(row)?.ok_or(StoreError::StoreCorrupt)?;
            if !ids.insert(contract.future_cue_contract_id)
                || !sources.insert(contract.source_revision_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
            entries.push(RecallTriggerEntry {
                contract,
                scope: row_scope(row)?,
            });
        }
        entries.sort_by_key(|entry| entry.contract.future_cue_contract_id);
        let field_entries = field_entries(&entries);
        Ok(Self {
            frontier: snapshot.frontier,
            entries,
            field_entries,
        })
    }

    pub fn evaluate(
        &self,
        current: &ConstraintState,
        previous: Option<&ConstraintState>,
    ) -> Vec<FutureCueCandidateCondition> {
        if current.validate().is_err() || previous.is_some_and(|state| state.validate().is_err()) {
            return Vec::new();
        }
        let mut candidate_indices = BTreeSet::new();
        for field in current
            .bindings
            .iter()
            .chain(previous.into_iter().flat_map(|state| state.bindings.iter()))
        {
            if let Some(indices) = self.field_entries.get(&field.field) {
                candidate_indices.extend(indices.iter().copied());
            }
        }
        candidate_indices
            .into_iter()
            .map(|index| {
                let entry = &self.entries[index];
                FutureCueCandidateCondition {
                    future_cue_contract_id: entry.contract.future_cue_contract_id,
                    match_truth: entry.contract.evaluate_match(current, previous),
                    suppress_truth: entry.contract.evaluate_suppress(current, previous),
                    resolve_truth: entry.contract.evaluate_resolve(current, previous),
                }
            })
            .collect()
    }
}

fn field_entries(entries: &[RecallTriggerEntry]) -> BTreeMap<ConstraintField, Vec<usize>> {
    let mut result = BTreeMap::<_, Vec<_>>::new();
    for (index, entry) in entries.iter().enumerate() {
        let mut fields = entry.contract.match_expr.referenced_fields();
        fields.extend(entry.contract.suppress_expr.referenced_fields());
        fields.extend(entry.contract.resolve_expr.referenced_fields());
        for field in fields {
            result.entry(field).or_default().push(index);
        }
    }
    result
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutureCueCandidateCondition {
    pub future_cue_contract_id: [u8; 32],
    pub match_truth: ConstraintTruth,
    pub suppress_truth: ConstraintTruth,
    pub resolve_truth: ConstraintTruth,
}

fn row_scope(row: &evertrace_store::ObjectRow) -> Result<AtomScope, StoreError> {
    match (
        row.task_id.as_deref(),
        row.repository_id.as_deref(),
        row.worktree_id.as_deref(),
    ) {
        (Some(task), None, None) => Ok(AtomScope::Task {
            task_id: TaskId::from_str(task).map_err(|_| StoreError::StoreCorrupt)?,
        }),
        (None, Some(repository), Some(worktree)) => Ok(AtomScope::Worktree {
            repository_instance_id: RepositoryId::from_str(repository)
                .map_err(|_| StoreError::StoreCorrupt)?,
            worktree_instance_id: WorktreeId::from_str(worktree)
                .map_err(|_| StoreError::StoreCorrupt)?,
        }),
        (None, Some(repository), None) => Ok(AtomScope::Repository {
            repository_instance_id: RepositoryId::from_str(repository)
                .map_err(|_| StoreError::StoreCorrupt)?,
        }),
        _ => Err(StoreError::StoreCorrupt),
    }
}

#[cfg(test)]
mod tests {
    use evertrace_domain::{
        ids::TaskId,
        recall::{FUTURE_CUE_COMPILER_VERSION, FUTURE_CUE_FIELD_REGISTRY_VERSION, TriggerFamily},
        revision::RevisionId,
        semantic::{ConstraintBinding, ConstraintExpr, ConstraintValue},
    };

    use super::*;

    fn entry(id: u8, match_expr: ConstraintExpr) -> RecallTriggerEntry {
        RecallTriggerEntry {
            contract: FutureCueContract {
                future_cue_contract_id: [id; 32],
                source_revision_id: RevisionId::new_v7(),
                trigger_family: TriggerFamily::ProspectiveObligation,
                condition_ir_version: 1,
                match_expr: match_expr.clone(),
                suppress_expr: match_expr.clone(),
                resolve_expr: match_expr,
                field_registry_version: FUTURE_CUE_FIELD_REGISTRY_VERSION,
                global_support_dependency_generation: None,
                compiler_version: FUTURE_CUE_COMPILER_VERSION,
                source_watermark: 1,
            },
            scope: AtomScope::Task {
                task_id: TaskId::new_v7(),
            },
        }
    }

    fn index(entries: Vec<RecallTriggerEntry>) -> RecallTriggerIndex {
        let field_entries = field_entries(&entries);
        RecallTriggerIndex {
            frontier: 1,
            entries,
            field_entries,
        }
    }

    #[test]
    fn structured_fields_bound_candidate_evaluation() {
        let index = index(vec![
            entry(
                1,
                ConstraintExpr::Eq {
                    field: ConstraintField::Phase,
                    value: ConstraintValue::Text("build".into()),
                },
            ),
            entry(
                2,
                ConstraintExpr::Eq {
                    field: ConstraintField::Phase,
                    value: ConstraintValue::Text("test".into()),
                },
            ),
            entry(
                3,
                ConstraintExpr::Eq {
                    field: ConstraintField::ArtifactKind,
                    value: ConstraintValue::Text("binary".into()),
                },
            ),
            entry(
                4,
                ConstraintExpr::Changed {
                    field: ConstraintField::VerifierState,
                },
            ),
            entry(
                5,
                ConstraintExpr::Transitioned {
                    field: ConstraintField::PhaseKind,
                    from: ConstraintValue::Text("build".into()),
                    to: ConstraintValue::Text("verify".into()),
                },
            ),
        ]);
        let phase = ConstraintState {
            bindings: vec![ConstraintBinding {
                field: ConstraintField::Phase,
                value: ConstraintValue::Text("build".into()),
            }],
        };
        let candidates = index.evaluate(&phase, None);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].match_truth, ConstraintTruth::True);
        assert_eq!(candidates[1].match_truth, ConstraintTruth::False);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.future_cue_contract_id != [3; 32])
        );

        let previous = ConstraintState {
            bindings: vec![
                ConstraintBinding {
                    field: ConstraintField::PhaseKind,
                    value: ConstraintValue::Text("build".into()),
                },
                ConstraintBinding {
                    field: ConstraintField::VerifierState,
                    value: ConstraintValue::Text("blocked".into()),
                },
            ],
        };
        let previous_only = index.evaluate(&ConstraintState::default(), Some(&previous));
        assert_eq!(previous_only.len(), 2);
        assert_eq!(previous_only[0].future_cue_contract_id, [4; 32]);
        assert_eq!(previous_only[0].match_truth, ConstraintTruth::Unknown);
        assert_eq!(previous_only[1].future_cue_contract_id, [5; 32]);
        assert_eq!(previous_only[1].match_truth, ConstraintTruth::Unknown);

        let unrelated = ConstraintState {
            bindings: vec![ConstraintBinding {
                field: ConstraintField::TaskKind,
                value: ConstraintValue::Text("implementation".into()),
            }],
        };
        assert!(index.evaluate(&unrelated, None).is_empty());

        let invalid = ConstraintState {
            bindings: vec![
                ConstraintBinding {
                    field: ConstraintField::Phase,
                    value: ConstraintValue::Text("build".into()),
                },
                ConstraintBinding {
                    field: ConstraintField::Phase,
                    value: ConstraintValue::Text("test".into()),
                },
            ],
        };
        assert!(index.evaluate(&invalid, None).is_empty());
    }
}
