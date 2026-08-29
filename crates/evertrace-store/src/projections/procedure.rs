use std::collections::BTreeMap;

use evertrace_domain::{
    ids::ProcedureId,
    procedure::{
        ProcedurePublicationState, ProcedureRevision, ProcedureScope, ProcedureStateEvent,
    },
    revision::RevisionId,
};

use crate::{JournalPayload, ObjectFamily, ObjectRow, ObjectRowClass, ObjectRowKind, StoreError};

#[derive(Clone, Default)]
pub(super) struct ProcedureState {
    procedures: BTreeMap<ProcedureId, (ProcedureRevision, u64)>,
    revisions: BTreeMap<RevisionId, (ProcedureRevision, u64)>,
    events: BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
    current_publication: BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
}

impl ProcedureState {
    pub(super) fn contains_revision_ref(&self, reference: &str) -> bool {
        reference
            .parse::<RevisionId>()
            .is_ok_and(|revision_id| self.revisions.contains_key(&revision_id))
    }

    pub(super) fn apply(&mut self, payload: JournalPayload, seq: u64) -> Result<bool, StoreError> {
        match payload {
            JournalPayload::ProcedureRevisionRecorded(value) => {
                let value = *value;
                if let Some((current, _)) = self.procedures.get(&value.procedure_id) {
                    current
                        .validate_successor(&value)
                        .map_err(|_| StoreError::StoreCorrupt)?;
                } else if value.parent_revision_id.is_some() || value.revision_generation != 1 {
                    return Err(StoreError::StoreCorrupt);
                }
                if self
                    .revisions
                    .insert(value.revision_id, (value.clone(), seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.procedures.insert(value.procedure_id, (value, seq));
                Ok(true)
            }
            JournalPayload::ProcedureStateRecorded(value) => {
                let value = *value;
                validate_publication_event(
                    &self.revisions,
                    &self.events,
                    &self.current_publication,
                    &value,
                )?;
                if self
                    .events
                    .insert(value.state_event_id, (value.clone(), seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.current_publication
                    .insert(value.procedure_revision_id, (value, seq));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn restore(&mut self, payload: JournalPayload, seq: u64) -> Result<(), StoreError> {
        match payload {
            JournalPayload::ProcedureRevisionRecorded(value) => {
                let value = *value;
                if self
                    .revisions
                    .insert(value.revision_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::ProcedureStateRecorded(value) => {
                let value = *value;
                if self
                    .events
                    .insert(value.state_event_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            _ => return Err(StoreError::StoreCorrupt),
        }
        Ok(())
    }

    pub(super) fn rebuild(&mut self) -> Result<(), StoreError> {
        self.procedures.clear();
        let mut revisions = self.revisions.values().cloned().collect::<Vec<_>>();
        revisions.sort_by_key(|(value, _)| (value.procedure_id, value.revision_generation));
        for (value, seq) in revisions {
            value.validate().map_err(|_| StoreError::StoreCorrupt)?;
            if let Some((current, current_seq)) = self.procedures.get(&value.procedure_id) {
                current
                    .validate_successor(&value)
                    .map_err(|_| StoreError::StoreCorrupt)?;
                if seq <= *current_seq {
                    return Err(StoreError::StoreCorrupt);
                }
            } else if value.revision_generation != 1 || value.parent_revision_id.is_some() {
                return Err(StoreError::StoreCorrupt);
            }
            self.procedures.insert(value.procedure_id, (value, seq));
        }
        self.current_publication.clear();
        let mut applied_events = BTreeMap::new();
        let mut events = self.events.values().cloned().collect::<Vec<_>>();
        events.sort_by_key(|(_, seq)| *seq);
        for (event, seq) in events {
            let (_, revision_seq) = self
                .revisions
                .get(&event.procedure_revision_id)
                .ok_or(StoreError::StoreCorrupt)?;
            let previous = self.current_publication.get(&event.procedure_revision_id);
            if seq <= *revision_seq || previous.is_some_and(|entry| seq <= entry.1) {
                return Err(StoreError::StoreCorrupt);
            }
            validate_publication_event(
                &self.revisions,
                &applied_events,
                &self.current_publication,
                &event,
            )?;
            self.current_publication
                .insert(event.procedure_revision_id, (event.clone(), seq));
            applied_events.insert(event.state_event_id, (event, seq));
        }
        if self
            .revisions
            .keys()
            .any(|revision_id| !self.current_publication.contains_key(revision_id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    pub(super) fn rows(
        &self,
        generation: u64,
        support: &super::s23::S23State,
    ) -> Result<Vec<ObjectRow>, StoreError> {
        let mut rows = Vec::new();
        let support_states = support.successor_support_states();
        for (revision_id, (value, seq)) in &self.revisions {
            let payload = JournalPayload::ProcedureRevisionRecorded(Box::new(value.clone()));
            let (repository_id, worktree_id) = scope_columns(value.draft.scope);
            rows.push(ObjectRow {
                row_id: format!("object:procedure:{}:{revision_id}", value.procedure_id),
                row_kind: ObjectRowKind::Data,
                row_class: Some(ObjectRowClass::Object),
                object_family: Some(ObjectFamily::Procedure),
                object_kind: Some("procedure_revision".into()),
                object_id: Some(value.procedure_id.to_string()),
                current_revision_id: Some(revision_id.to_string()),
                lifecycle: Some("active".into()),
                epistemic: None,
                authority: None,
                publication_state: self
                    .current_publication
                    .get(revision_id)
                    .map(|entry| publication(entry.0.to_state).into()),
                support_state: support_states
                    .get(&revision_id.to_string())
                    .map(|state| (*state).to_owned()),
                project_id: None,
                repository_id,
                worktree_id,
                task_id: None,
                workstream_id: None,
                session_id: None,
                payload_json: Some(payload.canonical_json()?),
                source_event_seq: *seq,
                projection_generation: generation,
            });
        }
        for (event_id, (event, seq)) in &self.events {
            let revision = self
                .revisions
                .get(&event.procedure_revision_id)
                .ok_or(StoreError::StoreCorrupt)?;
            let payload = JournalPayload::ProcedureStateRecorded(Box::new(event.clone()));
            let (repository_id, worktree_id) = scope_columns(revision.0.draft.scope);
            rows.push(ObjectRow {
                row_id: format!("object:procedure_state:{event_id}"),
                row_kind: ObjectRowKind::Data,
                row_class: Some(ObjectRowClass::Object),
                object_family: Some(ObjectFamily::Procedure),
                object_kind: Some("procedure_state_event".into()),
                object_id: Some(format!("procedure_state:{}", event.procedure_revision_id)),
                current_revision_id: Some(event_id.to_string()),
                lifecycle: Some("active".into()),
                epistemic: None,
                authority: None,
                publication_state: Some(publication(event.to_state).into()),
                support_state: None,
                project_id: None,
                repository_id,
                worktree_id,
                task_id: None,
                workstream_id: None,
                session_id: None,
                payload_json: Some(payload.canonical_json()?),
                source_event_seq: *seq,
                projection_generation: generation,
            });
        }
        Ok(rows)
    }
}

fn validate_publication_event(
    revisions: &BTreeMap<RevisionId, (ProcedureRevision, u64)>,
    history: &BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
    current_publication: &BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
    event: &ProcedureStateEvent,
) -> Result<(), StoreError> {
    event.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if !revisions.contains_key(&event.procedure_revision_id)
        || event.from_state
            != current_publication
                .get(&event.procedure_revision_id)
                .map(|entry| entry.0.to_state)
        || event.to_state == ProcedurePublicationState::ActiveProbationary
            && history.values().any(|(prior, _)| {
                prior.procedure_revision_id == event.procedure_revision_id
                    && prior.reason
                        == evertrace_domain::procedure::ProcedureStateReason::ConfirmedHarm
            })
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn scope_columns(scope: ProcedureScope) -> (Option<String>, Option<String>) {
    match scope {
        ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => (
            Some(repository_id.to_string()),
            Some(worktree_id.to_string()),
        ),
        ProcedureScope::Repository { repository_id } => (Some(repository_id.to_string()), None),
        ProcedureScope::Global => (None, None),
    }
}

pub(super) const fn publication(state: ProcedurePublicationState) -> &'static str {
    match state {
        ProcedurePublicationState::ActiveProbationary => "active_probationary",
        ProcedurePublicationState::ReviewHold => "review_hold",
        ProcedurePublicationState::ActiveStable => "active_stable",
        ProcedurePublicationState::Suspended => "suspended",
        ProcedurePublicationState::RolledBack => "rolled_back",
        ProcedurePublicationState::Superseded => "superseded",
    }
}

#[cfg(test)]
mod tests {
    use evertrace_domain::{
        procedure::{
            ProcedureActions, ProcedureDone, ProcedureDraft, ProcedureKind, ProcedureStateReason,
            ProcedureWhen,
        },
        semantic::{ConstraintExpr, ConstraintField},
    };

    use super::*;

    fn revision(generation: u32, parent: Option<RevisionId>) -> ProcedureRevision {
        ProcedureRevision {
            procedure_id: ProcedureId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: parent,
            revision_generation: generation,
            draft: ProcedureDraft {
                scope: ProcedureScope::Global,
                title: "title".into(),
                summary: "summary".into(),
                kind: ProcedureKind::Workflow,
                when: ProcedureWhen {
                    goals: vec!["goal".into()],
                    targets: vec!["target".into()],
                    signals: vec!["signal".into()],
                    stage: "stage".into(),
                    requires: Vec::new(),
                    excludes: Vec::new(),
                },
                condition_ir_version: 1,
                applicability_expr: ConstraintExpr::Exists {
                    field: ConstraintField::Phase,
                },
                avoid_expr: ConstraintExpr::Exists {
                    field: ConstraintField::FailureSignature,
                },
                completion_expr: ConstraintExpr::Exists {
                    field: ConstraintField::VerifierState,
                },
                actions: ProcedureActions {
                    stages: vec!["stage".into()],
                    branches: Vec::new(),
                    avoid: Vec::new(),
                },
                done: ProcedureDone {
                    success: vec!["success".into()],
                    abort: vec!["abort".into()],
                    verify: vec!["verify".into()],
                },
                pitfalls: Vec::new(),
                evidence_refs: vec!["evidence".into()],
                support_revision_refs: vec![RevisionId::new_v7()],
            },
            source_watermark: 1,
            created_at_us: 1,
        }
    }

    fn state_event(
        revision_id: RevisionId,
        from_state: Option<ProcedurePublicationState>,
        to_state: ProcedurePublicationState,
        reason: ProcedureStateReason,
        created_at_us: i64,
    ) -> ProcedureStateEvent {
        ProcedureStateEvent {
            state_event_id: RevisionId::new_v7(),
            procedure_revision_id: revision_id,
            from_state,
            to_state,
            reason,
            resume_state: None,
            evidence_refs: vec!["evidence".into()],
            created_at_us,
        }
    }

    fn state_with_initial() -> (ProcedureState, ProcedureRevision) {
        let root = revision(1, None);
        let mut state = ProcedureState::default();
        state
            .apply(
                JournalPayload::ProcedureRevisionRecorded(Box::new(root.clone())),
                1,
            )
            .unwrap();
        state
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    None,
                    ProcedurePublicationState::ActiveProbationary,
                    ProcedureStateReason::Accepted,
                    1,
                ))),
                2,
            )
            .unwrap();
        (state, root)
    }

    #[test]
    fn restore_rebuild_rejects_orphan_revision_and_missing_initial_publication() {
        let mut state = ProcedureState::default();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(revision(
                    2,
                    Some(RevisionId::new_v7()),
                ))),
                1,
            )
            .unwrap();
        assert!(state.rebuild().is_err());

        let root = revision(1, None);
        let mut state = ProcedureState::default();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(root.clone())),
                1,
            )
            .unwrap();
        assert!(state.rebuild().is_err());
        state
            .restore(
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: RevisionId::new_v7(),
                    procedure_revision_id: root.revision_id,
                    from_state: None,
                    to_state: ProcedurePublicationState::ActiveProbationary,
                    reason: ProcedureStateReason::Accepted,
                    resume_state: None,
                    evidence_refs: vec!["evidence".into()],
                    created_at_us: 1,
                })),
                2,
            )
            .unwrap();
        state.rebuild().unwrap();
    }

    #[test]
    fn restore_rebuild_rejects_child_revision_before_parent() {
        let root = revision(1, None);
        let mut child = root.clone();
        child.revision_id = RevisionId::new_v7();
        child.parent_revision_id = Some(root.revision_id);
        child.revision_generation = 2;
        child.draft.summary = "changed summary".into();
        child.source_watermark = 2;
        child.created_at_us = 2;
        let mut state = ProcedureState::default();
        state
            .restore(JournalPayload::ProcedureRevisionRecorded(Box::new(root)), 2)
            .unwrap();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(child)),
                1,
            )
            .unwrap();
        assert!(state.rebuild().is_err());
    }

    #[test]
    fn restore_rebuild_rejects_initial_state_before_revision() {
        let root = revision(1, None);
        let mut state = ProcedureState::default();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(root.clone())),
                2,
            )
            .unwrap();
        state
            .restore(
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: RevisionId::new_v7(),
                    procedure_revision_id: root.revision_id,
                    from_state: None,
                    to_state: ProcedurePublicationState::ActiveProbationary,
                    reason: ProcedureStateReason::Accepted,
                    resume_state: None,
                    evidence_refs: vec!["evidence".into()],
                    created_at_us: 1,
                })),
                1,
            )
            .unwrap();
        assert!(state.rebuild().is_err());
    }

    #[test]
    fn restore_rebuild_rejects_non_increasing_state_sequence() {
        let root = revision(1, None);
        let first_event_id = "018f0000-0000-7000-8000-000000000001".parse().unwrap();
        let second_event_id = "018f0000-0000-7000-8000-000000000002".parse().unwrap();
        let mut state = ProcedureState::default();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(root.clone())),
                1,
            )
            .unwrap();
        state
            .restore(
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: first_event_id,
                    procedure_revision_id: root.revision_id,
                    from_state: None,
                    to_state: ProcedurePublicationState::ActiveProbationary,
                    reason: ProcedureStateReason::Accepted,
                    resume_state: None,
                    evidence_refs: vec!["evidence".into()],
                    created_at_us: 2,
                })),
                2,
            )
            .unwrap();
        state
            .restore(
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: second_event_id,
                    procedure_revision_id: root.revision_id,
                    from_state: Some(ProcedurePublicationState::ActiveProbationary),
                    to_state: ProcedurePublicationState::ActiveStable,
                    reason: ProcedureStateReason::ObjectiveSuccesses,
                    resume_state: None,
                    evidence_refs: vec!["evidence".into()],
                    created_at_us: 3,
                })),
                2,
            )
            .unwrap();
        assert!(state.rebuild().is_err());
    }

    #[test]
    fn rollback_restores_non_harm_revision_and_harm_history_never_reactivates() {
        let (mut rollback, root) = state_with_initial();
        rollback
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::ActiveProbationary),
                    ProcedurePublicationState::Superseded,
                    ProcedureStateReason::Replaced,
                    2,
                ))),
                3,
            )
            .unwrap();
        rollback
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::Superseded),
                    ProcedurePublicationState::ActiveProbationary,
                    ProcedureStateReason::Rollback,
                    3,
                ))),
                4,
            )
            .unwrap();

        let (mut restored, root) = state_with_initial();
        restored
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::ActiveProbationary),
                    ProcedurePublicationState::Suspended,
                    ProcedureStateReason::SupportPending,
                    2,
                ))),
                3,
            )
            .unwrap();
        restored
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::Suspended),
                    ProcedurePublicationState::ActiveProbationary,
                    ProcedureStateReason::SupportRestored,
                    3,
                ))),
                4,
            )
            .unwrap();

        let (mut harmed, root) = state_with_initial();
        harmed
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::ActiveProbationary),
                    ProcedurePublicationState::Suspended,
                    ProcedureStateReason::ConfirmedHarm,
                    2,
                ))),
                3,
            )
            .unwrap();
        assert!(
            harmed
                .apply(
                    JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                        root.revision_id,
                        Some(ProcedurePublicationState::Suspended),
                        ProcedurePublicationState::ActiveProbationary,
                        ProcedureStateReason::SupportRestored,
                        3,
                    ))),
                    4,
                )
                .is_err()
        );
        harmed
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::Suspended),
                    ProcedurePublicationState::Superseded,
                    ProcedureStateReason::Replaced,
                    4,
                ))),
                5,
            )
            .unwrap();
        assert!(
            harmed
                .apply(
                    JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                        root.revision_id,
                        Some(ProcedurePublicationState::Superseded),
                        ProcedurePublicationState::ActiveProbationary,
                        ProcedureStateReason::Rollback,
                        5,
                    ))),
                    6,
                )
                .is_err()
        );
    }

    #[test]
    fn rebuild_rejects_reactivation_after_confirmed_harm() {
        let root = revision(1, None);
        let events = [
            state_event(
                root.revision_id,
                None,
                ProcedurePublicationState::ActiveProbationary,
                ProcedureStateReason::Accepted,
                1,
            ),
            state_event(
                root.revision_id,
                Some(ProcedurePublicationState::ActiveProbationary),
                ProcedurePublicationState::Suspended,
                ProcedureStateReason::ConfirmedHarm,
                2,
            ),
            state_event(
                root.revision_id,
                Some(ProcedurePublicationState::Suspended),
                ProcedurePublicationState::ActiveProbationary,
                ProcedureStateReason::SupportRestored,
                3,
            ),
        ];
        let mut state = ProcedureState::default();
        state
            .restore(JournalPayload::ProcedureRevisionRecorded(Box::new(root)), 1)
            .unwrap();
        for (offset, event) in events.into_iter().enumerate() {
            state
                .restore(
                    JournalPayload::ProcedureStateRecorded(Box::new(event)),
                    offset as u64 + 2,
                )
                .unwrap();
        }
        assert!(state.rebuild().is_err());
    }
}
