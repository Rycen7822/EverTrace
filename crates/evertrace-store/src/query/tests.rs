#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use evertrace_domain::ids::CommandId;

    use super::super::projection::{checkpoint_relation, checkpoint_search};
    use super::*;
    use crate::{
        DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload,
        MigrationApplied, ObjectRow, ObjectRowClass, ObjectRowKind, ProjectionWorker,
        projections::ProjectionJournalDelta, sqlite_state::SqliteHandle,
    };

    fn relation_rows(sqlite: &SqliteHandle) -> Vec<RelationProjectionRow> {
        sqlite.lock().unwrap().relation_rows().unwrap()
    }

    fn commit_current(sqlite: &SqliteHandle, rows: &[RelationProjectionRow]) {
        let current = relation_rows(sqlite);
        commit_relation_rows(sqlite, &current, rows).unwrap();
    }

    async fn open_search(root: &std::path::Path) -> lancedb::Table {
        let connection = lancedb::connect(crate::connection::native_root(root).to_str().unwrap())
            .execute()
            .await
            .unwrap();
        connection
            .open_table(crate::SEARCH_TABLE)
            .execute()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn relation_and_search_commit_faults_do_not_advance_their_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = crate::JournalWriter::open(&root).await.unwrap();
        writer.project().await.unwrap();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476aff").unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "projection-fault-proof",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: "projection-fault-proof".into(),
                }),
            )],
        )
        .unwrap();
        writer.commit(&command, 1).await.unwrap();

        let sqlite = writer.projection_handle();
        let search = open_search(&root).await;
        let (snapshot, _, delta) = ProjectionWorker::new(sqlite.clone())
            .catch_up_validated(None, None)
            .await
            .unwrap();
        let delta = delta.unwrap();
        let journal_epoch = sqlite.lock().unwrap().stamp().unwrap().journal_epoch;
        assert!(delta.clone().at_epoch(journal_epoch).is_some());
        assert!(delta.clone().at_epoch(journal_epoch + 1).is_none());
        let worker = L0002ProjectionWorker::new(sqlite.clone(), search.clone());
        let before_relations = checkpoint_relation(&relation_rows(&sqlite)).unwrap();
        let before_search = checkpoint_search(&read_search_rows(&search).await.unwrap()).unwrap();
        assert!(delta.rows_after(before_relations).is_some());
        assert!(delta.rows_after(snapshot.frontier).is_none());

        let mut ahead = snapshot.clone();
        ahead.frontier += 1;
        assert_eq!(
            worker.catch_up_validated_proof(&ahead, Some(delta.clone())).await,
            Err(StoreError::StoreCorrupt)
        );

        assert_eq!(
            worker.catch_up_with_fault(&snapshot, Some(delta.clone()), true, false).await,
            Err(StoreError::Projection)
        );
        assert_eq!(
            checkpoint_relation(&relation_rows(&sqlite)).unwrap(),
            before_relations
        );
        assert_eq!(
            checkpoint_search(&read_search_rows(&search).await.unwrap()).unwrap(),
            before_search
        );

        assert_eq!(
            worker.catch_up_with_fault(&snapshot, Some(delta.clone()), false, true).await,
            Err(StoreError::Projection)
        );
        assert_eq!(
            checkpoint_relation(&relation_rows(&sqlite)).unwrap(),
            snapshot.frontier
        );
        assert_eq!(
            checkpoint_search(&read_search_rows(&search).await.unwrap()).unwrap(),
            before_search
        );
        assert_eq!(
            worker.catch_up_validated_proof(&snapshot, Some(delta.clone())).await.unwrap().0.frontier,
            snapshot.frontier
        );

        // A later journal commit invalidates the handoff even when the
        // previously completed projections still have matching checkpoints.
        let later = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "projection-later-commit",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: "projection-later-commit".into(),
                }),
            )],
        )
        .unwrap();
        let relations_epoch = {
            let mut state = sqlite.lock().unwrap();
            state.stamp().unwrap().relations_epoch
        };
        let search_version = search.version().await.unwrap();
        writer.commit(&later, 2).await.unwrap();
        assert_eq!(
            worker.catch_up_validated_proof(&snapshot, Some(delta)).await,
            Err(StoreError::StoreCorrupt)
        );
        let relations_epoch_after = {
            let mut state = sqlite.lock().unwrap();
            state.stamp().unwrap().relations_epoch
        };
        assert_eq!(relations_epoch_after, relations_epoch);
        assert_eq!(search.version().await.unwrap(), search_version);
        assert_eq!(writer.project().await.unwrap().frontier, snapshot.frontier + 1);

        // The closed capture delta path shares this persisted fault boundary:
        // the L0002 commit must not repair or advance a checkpoint on failure,
        // and the next independent request recovers through the full path.
        let base = writer.project().await.unwrap().frontier;
        let dirty = JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::EvidenceSurface,
            target_id: evertrace_domain::ids::SourceObservationId::from_digest([7; 32]).to_string(),
            algorithm_revision: "capture-delta-proof".into(),
            source_watermark: 1,
        });
        let capture = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "capture-delta-proof",
                dirty.clone(),
            )],
        )
        .unwrap();
        writer.commit(&capture, 3).await.unwrap();
        let (journal_epoch, frontier) = {
            let mut state = sqlite.lock().unwrap();
            let stamp = state.stamp().unwrap();
            (stamp.journal_epoch, stamp.frontier)
        };
        assert_eq!(frontier, base + 1);
        let appended = sqlite.lock().unwrap().rows_after(base).unwrap();
        let changed = ObjectRow {
            row_id: "runtime:dirty:capture-delta-proof".into(),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Runtime),
            object_family: None,
            object_kind: None,
            object_id: None,
            current_revision_id: None,
            lifecycle: None,
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: None,
            workstream_id: None,
            session_id: None,
            payload_json: Some(dirty.canonical_json().unwrap()),
            source_event_seq: frontier,
            projection_generation: 1,
        };
        assert_eq!(checkpoint_relation(&relation_rows(&sqlite)).unwrap(), base);
        assert_eq!(
            checkpoint_search(&read_search_rows(&search).await.unwrap()).unwrap(),
            base
        );
        assert!(matches!(
            worker
                .catch_up_capture_delta_with_fault(
                    frontier,
                    base,
                    std::slice::from_ref(&changed),
                    ProjectionJournalDelta::for_test(journal_epoch, base, appended.clone()),
                    true,
                    false,
                )
                .await,
            Err(StoreError::Projection)
        ));
        assert_eq!(checkpoint_relation(&relation_rows(&sqlite)).unwrap(), base);
        assert_eq!(
            checkpoint_search(&read_search_rows(&search).await.unwrap()).unwrap(),
            base
        );
        assert!(matches!(
            worker
                .catch_up_capture_delta_with_fault(
                    frontier,
                    base,
                    std::slice::from_ref(&changed),
                    ProjectionJournalDelta::for_test(journal_epoch, base, appended),
                    false,
                    true,
                )
                .await,
            Err(StoreError::Projection)
        ));
        assert_eq!(
            checkpoint_relation(&relation_rows(&sqlite)).unwrap(),
            frontier
        );
        assert_eq!(
            checkpoint_search(&read_search_rows(&search).await.unwrap()).unwrap(),
            base
        );
        let objects = ProjectionWorker::new(sqlite.clone())
            .catch_up()
            .await
            .unwrap();
        assert_eq!(objects.frontier, frontier);
        worker.catch_up(&objects).await.unwrap();
        let expected = crate::query::derive_l0002_projections(&objects).unwrap();
        assert_eq!(relation_rows(&sqlite), expected.relations);
        assert_eq!(read_search_rows(&search).await.unwrap(), expected.search);
        // Reopening must not repair or grow the persisted family frontiers.
        drop(writer);
        let reopened = crate::JournalWriter::open(&root).await.unwrap();
        assert_eq!(reopened.project().await.unwrap().frontier, frontier);
    }

    #[tokio::test]
    async fn changed_row_merge_keeps_untouched_rows_and_deletes_only_removed_rows() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let writer = crate::JournalWriter::open(&root).await.unwrap();
        let sqlite = writer.projection_handle();
        let keep = RelationProjectionRow::edge(
            "repository_to_worktree",
            1,
            "repository-a".into(),
            "worktree-a".into(),
        );
        let remove = RelationProjectionRow::edge(
            "repository_to_worktree",
            1,
            "repository-a".into(),
            "worktree-b".into(),
        );
        let mut initial = vec![RelationProjectionRow::checkpoint(1), keep.clone(), remove];
        initial.sort();
        commit_current(&sqlite, &initial);
        // Only the checkpoint is in the merge source. The unchanged edge must
        // survive while the explicitly absent edge is deleted atomically.
        let mut expected = vec![RelationProjectionRow::checkpoint(2), keep];
        expected.sort();
        commit_relation_rows(&sqlite, &initial, &expected).unwrap();
        assert_eq!(relation_rows(&sqlite), expected);
        let epoch = {
            let mut state = sqlite.lock().unwrap();
            state.stamp().unwrap().relations_epoch
        };
        commit_relation_rows(&sqlite, &expected, &expected).unwrap();
        let epoch_after = {
            let mut state = sqlite.lock().unwrap();
            state.stamp().unwrap().relations_epoch
        };
        assert_eq!(epoch_after, epoch);
    }

    #[test]
    fn canonical_hashes_cover_every_persisted_semantic_column() {
        let relation =
            RelationProjectionRow::edge("atom_supports", 7, "source".into(), "target".into());
        let relation_hash = canonical_hash(
            "evertrace_relations_projection",
            relation_values(std::slice::from_ref(&relation)),
        )
        .unwrap();
        macro_rules! relation_change {
            ($field:ident, $value:expr) => {{
                let mut changed = relation.clone();
                changed.$field = $value;
                assert_ne!(
                    canonical_hash(
                        "evertrace_relations_projection",
                        relation_values(&[changed])
                    )
                    .unwrap(),
                    relation_hash
                );
            }};
        }
        relation_change!(row_id, "different".into());
        relation_change!(relation_kind, Some("atom_contradicts".into()));
        relation_change!(source_id, Some("different-source".into()));
        relation_change!(target_id, Some("different-target".into()));
        relation_change!(source_event_seq, 8);
        relation_change!(projection_generation, 2);

        let search = SearchProjectionRow {
            row_id: "search:test".into(),
            row_variant: "evidence_surface".into(),
            candidate_id: Some("candidate".into()),
            source_ref: Some("source".into()),
            source_kind: Some("evidence_surface".into()),
            text: "text".into(),
            source_role: Some("user".into()),
            content_trust: Some("user_statement".into()),
            capture_completeness: Some("complete".into()),
            instruction_authority: "none".into(),
            object_kind: None,
            currentness: None,
            lifecycle: None,
            epistemic: None,
            authority: None,
            task_id: Some("task".into()),
            repository_id: Some("repository".into()),
            worktree_id: Some("worktree".into()),
            event_time_us: 1,
            recorded_at_us: 2,
            source_sequence: 3,
            time_domain: "event_time".into(),
            retrieval_completeness: "complete".into(),
            suppression_ref_hash: Some("a".repeat(64)),
            source_event_seq: 4,
            projection_generation: 1,
        };
        let search_hash = canonical_hash(
            "evertrace_search_projection",
            search_values(std::slice::from_ref(&search)),
        )
        .unwrap();
        macro_rules! search_change {
            ($field:ident, $value:expr) => {{
                let mut changed = search.clone();
                changed.$field = $value;
                assert_ne!(
                    canonical_hash("evertrace_search_projection", search_values(&[changed]))
                        .unwrap(),
                    search_hash
                );
            }};
        }
        search_change!(row_id, "different".into());
        search_change!(row_variant, "object".into());
        search_change!(candidate_id, Some("different".into()));
        search_change!(source_ref, Some("different".into()));
        search_change!(source_kind, Some("different".into()));
        search_change!(text, "different".into());
        search_change!(source_role, Some("host".into()));
        search_change!(content_trust, Some("observed".into()));
        search_change!(capture_completeness, Some("partial".into()));
        search_change!(instruction_authority, "different".into());
        search_change!(object_kind, Some("atom_revision".into()));
        search_change!(currentness, Some("current".into()));
        search_change!(lifecycle, Some("active".into()));
        search_change!(epistemic, Some("supported".into()));
        search_change!(authority, Some("objective_evidence".into()));
        search_change!(task_id, Some("different".into()));
        search_change!(repository_id, Some("different".into()));
        search_change!(worktree_id, Some("different".into()));
        search_change!(event_time_us, 2);
        search_change!(recorded_at_us, 3);
        search_change!(source_sequence, 4);
        search_change!(time_domain, "source_sequence".into());
        search_change!(retrieval_completeness, "partial".into());
        search_change!(suppression_ref_hash, Some("b".repeat(64)));
        search_change!(source_event_seq, 5);
        search_change!(projection_generation, 2);
    }

    #[tokio::test]
    async fn l0002_checkpoint_ahead_mid_command_and_current_row_forgery_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = crate::JournalWriter::open(&root).await.unwrap();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476afe").unwrap(),
            vec![
                JournalEventDraft::runtime(
                    0,
                    [0; 32],
                    "mid-command-proof",
                    JournalPayload::MigrationApplied(MigrationApplied {
                        migration_id: "mid-command-one".into(),
                    }),
                ),
                JournalEventDraft::runtime(
                    0,
                    [0; 32],
                    "mid-command-proof",
                    JournalPayload::MigrationApplied(MigrationApplied {
                        migration_id: "mid-command-two".into(),
                    }),
                ),
            ],
        )
        .unwrap();
        writer.commit(&command, 1).await.unwrap();
        let sqlite = writer.projection_handle();
        let search = open_search(&root).await;
        let snapshot = ProjectionWorker::new(sqlite.clone()).catch_up().await.unwrap();
        let worker = L0002ProjectionWorker::new(sqlite.clone(), search.clone());

        let mut rows = relation_rows(&sqlite);
        rows.iter_mut()
            .find(|row| row.row_id == crate::RELATIONS_CHECKPOINT_ID)
            .unwrap()
            .source_event_seq = snapshot.frontier - 1;
        commit_current(&sqlite, &rows);
        assert_eq!(
            worker.catch_up(&snapshot).await,
            Err(StoreError::StoreCorrupt)
        );

        let mut rows = relation_rows(&sqlite);
        rows.iter_mut()
            .find(|row| row.row_id == crate::RELATIONS_CHECKPOINT_ID)
            .unwrap()
            .source_event_seq = snapshot.frontier + 1;
        commit_current(&sqlite, &rows);
        assert_eq!(
            worker.catch_up(&snapshot).await,
            Err(StoreError::StoreCorrupt)
        );

        let mut rows = relation_rows(&sqlite);
        rows.iter_mut()
            .find(|row| row.row_id == crate::RELATIONS_CHECKPOINT_ID)
            .unwrap()
            .source_event_seq = snapshot.frontier;
        commit_current(&sqlite, &rows);
        worker.catch_up(&snapshot).await.unwrap();
        let relation_epoch = {
            let mut state = sqlite.lock().unwrap();
            state.stamp().unwrap().relations_epoch
        };
        let search_version = search.version().await.unwrap();
        let mut derive_would_fail = snapshot.clone();
        derive_would_fail
            .rows
            .iter_mut()
            .find(|row| row.row_kind == crate::ObjectRowKind::Checkpoint)
            .unwrap()
            .source_event_seq = 0;
        assert!(derive_l0002_projections(&derive_would_fail).is_err());
        worker.catch_up(&derive_would_fail).await.unwrap();
        let relation_epoch_after = {
            let mut state = sqlite.lock().unwrap();
            state.stamp().unwrap().relations_epoch
        };
        assert_eq!(relation_epoch_after, relation_epoch);
        assert_eq!(search.version().await.unwrap(), search_version);
        let stable_relations = relation_rows(&sqlite)
            .into_iter()
            .filter(|row| row.row_id != crate::RELATIONS_CHECKPOINT_ID)
            .collect::<Vec<_>>();
        let stable_search = read_search_rows(&search)
            .await
            .unwrap()
            .into_iter()
            .filter(|row| row.row_id != crate::SEARCH_CHECKPOINT_ID)
            .collect::<Vec<_>>();
        let unrelated = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476afd").unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "unrelated-frontier-proof",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: "unrelated-frontier-proof".into(),
                }),
            )],
        )
        .unwrap();
        writer.commit(&unrelated, 2).await.unwrap();
        let snapshot = ProjectionWorker::new(sqlite.clone()).catch_up().await.unwrap();
        worker.catch_up(&snapshot).await.unwrap();
        assert_eq!(
            relation_rows(&sqlite)
                .into_iter()
                .filter(|row| row.row_id != crate::RELATIONS_CHECKPOINT_ID)
                .collect::<Vec<_>>(),
            stable_relations
        );
        assert_eq!(
            read_search_rows(&search)
                .await
                .unwrap()
                .into_iter()
                .filter(|row| row.row_id != crate::SEARCH_CHECKPOINT_ID)
                .collect::<Vec<_>>(),
            stable_search
        );
        let mut search_rows = read_search_rows(&search).await.unwrap();
        search_rows.push(SearchProjectionRow {
            row_id: "search:object:forged".into(),
            row_variant: "object".into(),
            candidate_id: Some("stable-forged".into()),
            source_ref: Some("stable-forged".into()),
            source_kind: Some("object_projection".into()),
            text: "forged".into(),
            source_role: None,
            content_trust: None,
            capture_completeness: None,
            instruction_authority: "none".into(),
            object_kind: Some("forged".into()),
            currentness: Some("current".into()),
            lifecycle: Some("active".into()),
            epistemic: None,
            authority: None,
            task_id: None,
            repository_id: None,
            worktree_id: None,
            event_time_us: 0,
            recorded_at_us: 0,
            source_sequence: 0,
            time_domain: "none".into(),
            retrieval_completeness: "complete".into(),
            suppression_ref_hash: None,
            source_event_seq: snapshot.frontier,
            projection_generation: 1,
        });
        search_rows.sort();
        assert_eq!(
            commit_search_rows(
                &search,
                &read_search_rows(&search).await.unwrap(),
                &search_rows,
                false
            )
            .await,
            Err(StoreError::StoreCorrupt)
        );
    }
}
