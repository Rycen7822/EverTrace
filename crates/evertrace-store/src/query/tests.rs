#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use evertrace_domain::ids::CommandId;

    use super::super::projection::{checkpoint_relation, checkpoint_search};
    use super::*;
    use crate::{
        DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload,
        MigrationApplied, ObjectRow, ObjectRowClass, ObjectRowKind,
        ProjectionWorker, projections::ProjectionJournalDelta, sqlite_state::SqliteHandle,
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
    #[test]
    fn keyed_tie_breaks_follow_physical_row_id_order() {
        let mut latest = BTreeMap::new();
        super::latest_insert(&mut latest, "k", 1u64, 5, "object:b");
        super::latest_insert(&mut latest, "k", 2u64, 5, "object:a");
        assert_eq!(latest["k"].value, 2, "equal seq: smaller row_id wins");
        super::latest_insert(&mut latest, "k", 3u64, 4, "object:c");
        assert_eq!(latest["k"].value, 2, "older seq never replaces");
        super::latest_insert(&mut latest, "k", 4u64, 6, "object:d");
        assert_eq!(latest["k"].value, 4, "strictly newer seq wins");

        let mut replaced = BTreeMap::new();
        super::replace_insert(&mut replaced, "k", 1u64, 9, "object:a");
        super::replace_insert(&mut replaced, "k", 2u64, 1, "object:b");
        assert_eq!(replaced["k"].value, 2, "unconditional insert: last row_id wins");
        super::replace_insert(&mut replaced, "k", 3u64, 9, "object:b");
        assert_eq!(replaced["k"].value, 3, "equal row_id replaced by the later visit");
        super::replace_insert(&mut replaced, "k", 4u64, 9, "object:a");
        assert_eq!(replaced["k"].value, 3, "smaller row_id never replaces");

        let mut current = BTreeMap::new();
        super::current_revision_insert(&mut current, "o", "rev-b", 5, "object:b");
        super::current_revision_insert(&mut current, "o", "rev-a", 5, "object:a");
        assert_eq!(current["o"].1, "rev-a", "equal seq: first row_id wins");
        super::current_revision_insert(&mut current, "o", "rev-c", 4, "object:c");
        assert_eq!(current["o"].1, "rev-a", "older seq never replaces");
        super::current_revision_insert(&mut current, "o", "rev-d", 6, "object:d");
        assert_eq!(current["o"].1, "rev-d", "strictly newer seq wins");
    }

    #[tokio::test]
    async fn fused_handoff_noop_never_exposes_staged_derive_error() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = crate::JournalWriter::open(&root).await.unwrap();
        writer.project().await.unwrap();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476c20").unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "v1",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: "noop-proof".into(),
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
        let worker = L0002ProjectionWorker::new(sqlite.clone(), search.clone());
        let (_, versions, derived) = worker
            .catch_up_validated_proof(&snapshot, Some(delta.clone()))
            .await
            .unwrap();
        assert!(derived);
        let relations_before = relation_rows(&sqlite);
        let search_before = read_search_rows(&search).await.unwrap();
        let journal_epoch = sqlite.lock().unwrap().stamp().unwrap().journal_epoch;
        let delta = delta.at_epoch(journal_epoch).unwrap();

        // A checkpoint-complete handoff is a legal NoOp: even a sink holding
        // a staged derive error must not fail or commit anything.
        let mut sink = L0002RowAccumulator::default();
        let mut forged = snapshot.clone();
        forged
            .rows
            .iter_mut()
            .find(|row| row.row_kind == ObjectRowKind::Data)
            .unwrap()
            .payload_json = Some("{".into());
        for row in &forged.rows {
            sink.consume_row(row);
        }
        let (noop_versions, derived) = worker
            .catch_up_fused_handoff(snapshot.frontier, Some(delta.clone()), Box::new(sink))
            .await
            .unwrap();
        assert!(!derived);
        assert_eq!(noop_versions, versions);
        assert_eq!(relation_rows(&sqlite), relations_before);
        assert_eq!(read_search_rows(&search).await.unwrap(), search_before);
    }

    #[tokio::test]
    async fn staged_derive_error_precedes_commit_but_not_native_handoff() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = crate::JournalWriter::open(&root).await.unwrap();
        writer.project().await.unwrap();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476c30").unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "v1",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: "staged-proof".into(),
                }),
            )],
        )
        .unwrap();
        writer.commit(&command, 1).await.unwrap();
        let sqlite = writer.projection_handle();
        let search = open_search(&root).await;
        let worker_l1 = ProjectionWorker::new(sqlite.clone());
        let (_, _, _) = worker_l1.catch_up_validated(None, None).await.unwrap();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476c31").unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "v1",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: "staged-proof-second".into(),
                }),
            )],
        )
        .unwrap();
        writer.commit(&command, 2).await.unwrap();
        let stamp = sqlite.lock().unwrap().stamp().unwrap();
        let frontier = stamp.frontier;
        let base_frontier = stamp.object_checkpoint;
        let delta = sqlite
            .lock()
            .unwrap()
            .rows_after(base_frontier)
            .unwrap();
        let (snapshot, _, _) = worker_l1
            .catch_up_validated(
                Some((stamp.objects_epoch, stamp.object_checkpoint, frontier)),
                Some(&delta),
            )
            .await
            .unwrap();
        let worker = L0002ProjectionWorker::new(sqlite.clone(), search.clone());
        let relations_before = relation_rows(&sqlite);
        let search_before = read_search_rows(&search).await.unwrap();
        let journal_epoch = stamp.journal_epoch;

        // A native handoff failure (wrong epoch delta) wins over the staged
        // derive error and commits nothing.
        let mut sink = L0002RowAccumulator::default();
        let mut forged = snapshot.clone();
        forged
            .rows
            .iter_mut()
            .find(|row| row.row_kind == ObjectRowKind::Data)
            .unwrap()
            .payload_json = Some("{".into());
        for row in &forged.rows {
            sink.consume_row(row);
        }
        let wrong_epoch = super::ProjectionJournalDelta {
            journal_epoch: journal_epoch + 1,
            checkpoint: 0,
            rows: Vec::new(),
        };
        assert_eq!(
            worker
                .catch_up_fused_handoff(snapshot.frontier, Some(wrong_epoch), Box::new(sink))
                .await,
            Err(StoreError::StoreCorrupt)
        );
        assert_eq!(relation_rows(&sqlite), relations_before);
        assert_eq!(read_search_rows(&search).await.unwrap(), search_before);

        // With a valid handoff that really needs derivation, the staged
        // derive error surfaces before any relation/search commit.
        let mut sink = L0002RowAccumulator::default();
        for row in &forged.rows {
            sink.consume_row(row);
        }
        let valid = super::ProjectionJournalDelta {
            journal_epoch,
            checkpoint: base_frontier,
            rows: delta,
        };
        // finish owns header-before-body priority; the handoff must not
        // extract staged body errors separately and bypass that ordering.
        let mut bad_header = Box::<L0002RowAccumulator>::default();
        bad_header.staged_body = Some(StoreError::Projection);
        assert_eq!(
            worker.catch_up_fused_handoff(snapshot.frontier, Some(valid.clone()), bad_header).await,
            Err(StoreError::StoreCorrupt),
        );
        assert_eq!(
            worker
                .catch_up_fused_handoff(snapshot.frontier, Some(valid), Box::new(sink))
                .await,
            Err(StoreError::StoreCorrupt)
        );
        assert_eq!(relation_rows(&sqlite), relations_before);
        assert_eq!(read_search_rows(&search).await.unwrap(), search_before);

        // A clean sink over the same rows derives and commits normally.
        let mut sink = L0002RowAccumulator::default();
        for row in &snapshot.rows {
            sink.consume_row(row);
        }
        let valid = super::ProjectionJournalDelta {
            journal_epoch,
            checkpoint: base_frontier,
            rows: sqlite
                .lock()
                .unwrap()
                .rows_after(base_frontier)
                .unwrap(),
        };
        let (_, derived) = worker
            .catch_up_fused_handoff(snapshot.frontier, Some(valid), Box::new(sink))
            .await
            .unwrap();
        assert!(derived);
        assert_ne!(relation_rows(&sqlite), relations_before);
    }
    // ---- r185: independent ORIGINAL-HEAD oracle proof and real-consumer proof ----

    use evertrace_domain::evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceObservation,
        SourceReceipt, SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
        hex, payload_fingerprint, source_observation_id, source_receipt_id,
    };
    use evertrace_domain::evidence::SourceInstanceId;
    use evertrace_domain::ids::{AtomId, JobId};
    use evertrace_domain::revision::RevisionId;
    use evertrace_domain::semantic::{
        ApplicabilityExpr, Atom, AtomAuthority, AtomKind, AtomLifecycleStatus, AtomProvenance,
        AtomScope, AtomValue, EpistemicStatus, ValidityInterval,
    };

    fn r185_atom(
        atom_id: AtomId,
        revision_id: RevisionId,
        parent_revision_id: Option<RevisionId>,
        supersedes_revision_refs: Vec<RevisionId>,
        evidence_refs: Vec<String>,
        created_at_us: i64,
    ) -> Atom {
        Atom {
            atom_id,
            revision_id,
            parent_revision_id,
            kind: AtomKind::Fact,
            epistemic_status: EpistemicStatus::Unverified,
            lifecycle_status: AtomLifecycleStatus::Active,
            authority: AtomAuthority::AgentInferred,
            value: AtomValue {
                text: "writer lineage records bounded evidence across revisions".into(),
                subject: "writer-lineage".into(),
                predicate: "records".into(),
                object: Some("bounded-evidence".into()),
                qualifiers: Vec::new(),
                critical_revision_refs: Vec::new(),
            },
            scope: AtomScope::Global,
            condition_ir_version: 1,
            applicability_expr: ApplicabilityExpr::Constraint(
                evertrace_domain::semantic::ConstraintExpr::Exists {
                    field: evertrace_domain::semantic::ConstraintField::AgentKind,
                },
            ),
            future_cue_lifecycle_exprs: None,
            validity_interval: ValidityInterval {
                valid_from_us: 0,
                valid_until_us: None,
            },
            provenance: vec![AtomProvenance::LlmDerived],
            user_authorization_provenance: None,
            policy_authority_provenance: None,
            source_observation_refs: Vec::new(),
            evidence_refs,
            supersedes_revision_refs,
            supports_revision_refs: Vec::new(),
            contradicts_revision_refs: Vec::new(),
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us,
        }
    }

    fn r185_job(job_id_value: &str, key: &str) -> crate::command::DurableJob {
        crate::command::DurableJob {
            job_id: JobId::from_str(job_id_value).unwrap(),
            idempotency_key: key.into(),
            target_revision: "a".repeat(64),
            target_watermark: 9,
            target_generation: 1,
            kind: "projection_rebuild".into(),
            algorithm_revision: "v1".into(),
            model_id: None,
            priority: 1,
            state: crate::JobStatus::Queued,
            attempt: 1,
            backoff_until_us: None,
            config_hash: [7; 32],
            budget: crate::command::JobBudget {
                max_items: 1,
                max_bytes: None,
                max_input_tokens: None,
                max_output_tokens: None,
                max_calls: None,
                max_wall_time_ms: 250,
            },
            terminal: None,
            lease_until_us: None,
        }
    }

    fn r185_atom_command(command: &str, occurred_at_us: i64, atom: Atom) -> crate::JournalCommand {
        JournalCommand::new(
            CommandId::from_str(command).unwrap(),
            vec![JournalEventDraft::runtime(
                occurred_at_us,
                [9; 32],
                "r185-v1",
                JournalPayload::AtomRecorded(Box::new(atom)),
            )],
        )
        .unwrap()
    }

    /// One real source receipt + observation pair (verbatim field shape from
    /// the established fixtures), admitted through the real writer.
    fn r185_source() -> (SourceReceipt, SourceObservation) {
        let instance = SourceInstanceId::parse("r185-src").unwrap();
        let revision = SourceRevision::parse("revision-1").unwrap();
        let record = SourceRecordIdentity::parse("record-r185").unwrap();
        let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
        let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
        let digest = hex(&payload_fingerprint(1, b"r185 payload", None).unwrap());
        let receipt = SourceReceipt {
            protected_presentation: None,
            source_receipt_id: receipt_id,
            source_observation_id: observation_id,
            source_instance_id: instance.clone(),
            source_kind: EvidenceSourceKind::CodexSessionJsonl,
            identity_domain: "codex-session-v1".into(),
            source_ref: "source-ref-r185".into(),
            source_session_ref: "session-r185".into(),
            source_revision: revision.clone(),
            source_record_identity: record.clone(),
            identity_strength: IdentityStrength::StableNative,
            source_sequence: 1,
            source_sequence_origin: None,
            task_id: None,
            repository_instance_id: None,
            worktree_instance_id: None,
            source_byte_range: None,
            spool_byte_range: EvidenceByteRange { start: 1, end: 2 },
            source_revision_mode: SourceRevisionMode::Append,
            previous_source_revision: None,
            close_watermark: Some(1),
            observation_role: ObservationRole::Message,
            unsupported_record_classification: None,
            capture_completeness: CaptureCompleteness::Complete,
            archive_mode: SourceArchiveMode::Exact,
            cas_ref: digest.clone(),
            protected_length: 12,
            original_length: 12,
            protected_secret_digest: None,
            redaction_spans: vec![],
            adapter_revision: 1,
            adapter_manifest_ref: "adapter-r185".into(),
            eligible_event_manifest_ref: "eligible-r185".into(),
            parser_revision: 1,
            canonicalization_revision: 1,
            detector_revision: 1,
            redaction_revision: 1,
            protection_key_generation: 1,
            event_time_us: 1,
            recorded_at_us: 1,
            lifecycle: None,
        };
        let observation = SourceObservation {
            source_local_evidence: None,
            source_observation_id: observation_id,
            source_instance_id: instance.clone(),
            source_revision: revision.clone(),
            source_record_identity: record.clone(),
            observation_role: ObservationRole::Message,
            identity_strength: IdentityStrength::StableNative,
            payload_fingerprint: digest,
            source_receipt_ref: receipt_id,
            source_role: SourceRole::User,
            content_trust: ContentTrust::UserStatement,
            capture_completeness: CaptureCompleteness::Complete,
            adapter_revision: 1,
            parser_revision: 1,
            canonicalization_revision: 1,
            detector_revision: 1,
            redaction_revision: 1,
            correlation: HostCorrelationEvidence {
                occurrence_schema_version: 1,
                host_instance_id: None,
                host_trace_lineage_id: None,
                host_lane_key: None,
                canonical_event_family: None,
                native_request_id: None,
                physical_execution_ordinal: None,
                pairing_role: ObservationRole::Message,
                field_provenance: vec![],
                adapter_manifest_ref: "adapter-r185".into(),
                adapter_revision: 1,
                strong_gate_receipt_ref: None,
                admission: CorrelationAdmission::Unavailable,
                partial_correlation_ref: None,
                possible_duplicate_group_id: None,
            },
            scope_effect_claims: vec![],
        };
        receipt.validate().unwrap();
        observation.validate().unwrap();
        (receipt, observation)
    }

    /// Commits: one real source receipt/observation pair (physical family);
    /// atom revision 1; atom revision 2 superseding it (history/currentness);
    /// one queued job (runtime rows). Returns the opened writer.
    async fn r185_nonempty_seed() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        crate::JournalWriter,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = crate::JournalWriter::open(&root).await.unwrap();
        let (receipt, observation) = r185_source();
        let source_command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476d0f").unwrap(),
            vec![
                JournalEventDraft::runtime(
                    0,
                    [9; 32],
                    "r185-v1",
                    JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
                ),
                JournalEventDraft::runtime(
                    1,
                    [9; 32],
                    "r185-v1",
                    JournalPayload::SourceObservationRecorded(Box::new(observation.clone())),
                ),
                JournalEventDraft::runtime(
                    2,
                    [9; 32],
                    "r185-v1",
                    JournalPayload::EvidenceSurfaceRecorded(Box::new(
                        crate::search::build_evidence_surface(&receipt, &observation, b"r185 payload", true)
                            .unwrap().unwrap(),
                    )),
                ),
                JournalEventDraft::runtime(
                    2,
                    [9; 32],
                    "r185-v1",
                    JournalPayload::SourceIngestWatermark(crate::SourceIngestWatermark {
                        source_instance_id: receipt.source_instance_id.clone(),
                        source_revision: receipt.source_revision.clone(),
                        source_sequence: receipt.source_sequence,
                        confirmed_prefix_digest: None,
                    }),
                ),
                JournalEventDraft::runtime(
                    3,
                    [9; 32],
                    "r185-v1",
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::EvidenceSurface,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "r185-v1".into(),
                        source_watermark: receipt.source_sequence,
                    }),
                ),
                JournalEventDraft::runtime(
                    4,
                    [9; 32],
                    "r185-v1",
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "r185-v1".into(),
                        source_watermark: receipt.source_sequence,
                    }),
                ),
            ],
        )
        .unwrap();
        writer.commit(&source_command, 100).await.unwrap();
        // Fixed identities so the twin arms compare byte-for-byte.
        let atom_id = AtomId::from_str("atom:01890f47-6a4a-7cc1-98b9-01890f476e00").unwrap();
        let revision_one = RevisionId::from_str("01890f47-6a4a-7cc1-98b9-01890f476e01").unwrap();
        let revision_two = RevisionId::from_str("01890f47-6a4a-7cc1-98b9-01890f476e02").unwrap();
        let evidence_one = vec![receipt.source_receipt_id.to_string()];
        let mut evidence_two = evidence_one.clone();
        evidence_two.push(observation.source_observation_id.to_string());
        evidence_two.sort();
        let atom_one = r185_atom(atom_id, revision_one, None, Vec::new(), evidence_one, 10);
        let atom_two = r185_atom(
            atom_id,
            revision_two,
            Some(revision_one),
            vec![revision_one],
            evidence_two,
            20,
        );
        let cmd = r185_atom_command("01890f47-6a4a-7cc1-98b9-01890f476d10", 1, atom_one.clone());
        writer.commit(&cmd, 100).await.unwrap();
        writer
            .commit(
                &r185_atom_command("01890f47-6a4a-7cc1-98b9-01890f476d11", 2, atom_two),
                200,
            )
            .await
            .unwrap();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476d12").unwrap(),
            vec![JournalEventDraft::runtime(
                3,
                [9; 32],
                "r185-v1",
                JournalPayload::JobState(r185_job(
                    "01890f47-6a4a-7cc1-98b9-01890f476d13",
                    "r185-job-key",
                )),
            )],
        )
        .unwrap();
        writer.commit(&command, 300).await.unwrap();
        (temp, root, writer)
    }

    fn r185_migration_command(command: &str, occurred_at_us: i64, id: &str) -> crate::JournalCommand {
        JournalCommand::new(
            CommandId::from_str(command).unwrap(),
            vec![JournalEventDraft::runtime(
                occurred_at_us,
                [9; 32],
                "r185-v1",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: id.into(),
                }),
            )],
        )
        .unwrap()
    }

    /// Persists a REAL pending deletion ledger row (byte shape of the
    /// complete algorithm's ledger_row) so an ALREADY-present ledger exists in
    /// the objects state before the unrelated ordinary command. Uses the real
    /// preview/pending_object_deletion producers and the existing test row
    /// inserter; no admission-side command replay is needed for this path.
    async fn r185_insert_existing_ledger(sqlite: &SqliteHandle) {
        let snapshot = {
            let worker = ProjectionWorker::new(sqlite.clone());
            worker.catch_up_validated(None, None).await.unwrap().0
        };
        let atom_row = snapshot
            .rows
            .iter()
            .find(|row| {
                row.object_kind.as_deref() == Some("atom_revision")
                    && row.current_revision_id.as_deref()
                        == Some("01890f47-6a4a-7cc1-98b9-01890f476e02")
            })
            .expect("seed has the current atom row");
        let payload: JournalPayload =
            serde_json::from_str(atom_row.payload_json.as_deref().unwrap()).unwrap();
        let JournalPayload::AtomRecorded(atom) = payload else {
            panic!("atom row must carry an AtomRecorded payload");
        };
        let preview = crate::purge::derive_object_deletion_preview(
            evertrace_domain::purge::ObjectDeletionTarget::Atom {
                atom_id: atom.atom_id,
            },
            vec![crate::purge::ObjectDeletionRevisionFact {
                revision_id: atom.revision_id,
                canonical_payload: "r185-canonical".into(),
                semantic_kind: "r185-kind".into(),
                scope_identity: "r185-scope".into(),
                source_derivation_refs: vec!["r185-source".into()],
                current: true,
            }],
            vec!["r185-source".into()],
            crate::purge::ObjectDeletionSourceContext {
                other_live_source_refs: &std::collections::BTreeSet::new(),
                source_observations: &std::collections::BTreeMap::new(),
                source_receipts: &std::collections::BTreeMap::new(),
                evidence_surfaces: &std::collections::BTreeMap::new(),
            },
            Vec::new(),
            Vec::new(),
            1,
        )
        .unwrap();
        let (ledger_event, _job) =
            crate::purge::pending_object_deletion(
                &preview,
                JobId::from_str("01890f47-6a4a-7cc1-98b9-01890f476e10").unwrap(),
                1,
                1,
                [9; 32],
            )
                .unwrap();
        let row = ObjectRow {
            row_id: format!(
                "projection:object_deletion:{}",
                ledger_event.target.object_ref()
            ),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Projection),
            object_family: None,
            object_kind: Some(crate::purge::OBJECT_DELETION_LEDGER_KIND.into()),
            object_id: None,
            current_revision_id: Some(format!(
                "deletion-generation-{}",
                ledger_event.deletion_generation
            )),
            lifecycle: Some("purge_pending".into()),
            epistemic: None,
            authority: Some("human".into()),
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: None,
            workstream_id: None,
            session_id: None,
            payload_json: Some(
                JournalPayload::ObjectDeletionLedgerRecorded(Box::new(ledger_event))
                    .canonical_json()
                    .unwrap(),
            ),
            source_event_seq: snapshot.frontier,
            projection_generation: 1,
        };
        let atom_row_ids = {
            let mut sqlite = sqlite.lock().unwrap();
            sqlite.insert_object_row_for_test(&row).unwrap();
            // A real purge command's reconcile write also removes the deleted
            // product rows; mirror that so the persisted set stays consistent.
            let atom_ref = ledger_target_atom_ref(&row);
            sqlite
                .object_rows()
                .unwrap()
                .into_iter()
                .filter(|existing| {
                    existing.object_kind.as_deref() == Some("atom_revision")
                        && existing.object_id.as_deref() == Some(atom_ref.as_str())
                })
                .map(|existing| existing.row_id)
                .collect::<Vec<_>>()
        };
        let mut sqlite = sqlite.lock().unwrap();
        for row_id in atom_row_ids {
            sqlite.delete_object_row_for_test(&row_id).unwrap();
        }
    }

    fn ledger_target_atom_ref(row: &ObjectRow) -> String {
        let Some(payload_json) = row.payload_json.as_deref() else {
            return String::new();
        };
        let Ok(JournalPayload::ObjectDeletionLedgerRecorded(event)) =
            serde_json::from_str::<JournalPayload>(payload_json)
        else {
            return String::new();
        };
        match event.target {
            evertrace_domain::purge::ObjectDeletionTarget::Atom { atom_id } => atom_id.to_string(),
            _ => String::new(),
        }
    }

    #[tokio::test]
    async fn writer_sync_frontier_fused_physical_state_matches_oracle_before_repair() {
        // Arm A: the real JournalWriter consumer; sync_frontier selects the
        // fused path. Arm B: the original complete algorithm on an identical
        // store. Every physical field is compared before any repair can run.
        let (_temp_a, root_a, mut writer_a) = r185_nonempty_seed().await;
        writer_a.project().await.unwrap();
        let before = writer_a.fused_delta_selections();
        let stamp_after_project = writer_a
            .projection_handle()
            .lock()
            .unwrap()
            .stamp()
            .unwrap();
        writer_a
            .commit(
                &r185_migration_command(
                    "01890f47-6a4a-7cc1-98b9-01890f476d20",
                    4,
                    "r185-arm-a",
                ),
                400,
            )
            .await
            .unwrap();
        let frontier_a = writer_a.sync_frontier().await.unwrap();
        assert_eq!(
            writer_a.fused_delta_selections(),
            before + 1,
            "the real writer consumer must select the fused path"
        );
        // Physical state before any project/rebuild/doctor can repair it.
        let sqlite_a = writer_a.projection_handle();
        let objects_a = sqlite_a.lock().unwrap().object_rows().unwrap();
        let relations_a = relation_rows(&sqlite_a);
        let stamp_a = sqlite_a.lock().unwrap().stamp().unwrap();
        let search_a = {
            let search = open_search(&root_a).await;
            read_search_rows(&search).await.unwrap()
        };

        // Arm B: identical seed, original complete algorithm for the delta.
        let (_temp_b, _root_b, mut writer_b) = r185_nonempty_seed().await;
        let sqlite_b = writer_b.projection_handle();
        let worker_b = ProjectionWorker::new(sqlite_b.clone());
        let (snap_b0, _, _) = worker_b.catch_up_validated(None, None).await.unwrap();
        let epoch_b0 = sqlite_b.lock().unwrap().stamp().unwrap().objects_epoch;
        writer_b
            .commit(
                &r185_migration_command(
                    "01890f47-6a4a-7cc1-98b9-01890f476d20",
                    4,
                    "r185-arm-a",
                ),
                400,
            )
            .await
            .unwrap();
        let frontier_b = sqlite_b.lock().unwrap().stamp().unwrap().frontier;
        let delta_b = sqlite_b
            .lock()
            .unwrap()
            .rows_after(snap_b0.frontier)
            .unwrap();
        let (snap_b, _, _) = worker_b
            .catch_up_validated(
                Some((epoch_b0, snap_b0.frontier, frontier_b)),
                Some(&delta_b),
            )
            .await
            .unwrap();
        assert_eq!(frontier_a, snap_b.frontier);
        assert_eq!(frontier_a, stamp_after_project.frontier + 1);
        assert_eq!(stamp_a.object_checkpoint, snap_b.frontier);
        assert_eq!(stamp_a.frontier, snap_b.frontier);
        assert_eq!(objects_a, snap_b.rows);
        assert!(!relations_a.is_empty() && !search_a.is_empty());
        // Independent HEAD 3fa42e7, captured before any repair; reuse the
        // existing canonical hashes covering every persisted column, not a
        // second field schema or a four-column projection.
        let physical = L0002ProjectionSnapshot { frontier: frontier_a, relations: relations_a, search: search_a };
        assert_eq!((physical.relations.len(), physical.search.len()), (3, 4));
        assert_eq!(physical.relation_hash().unwrap(), [189, 216, 32, 119, 224, 188, 147, 113, 64, 126, 232, 104, 222, 45, 51, 38, 213, 169, 78, 181, 122, 87, 111, 96, 97, 48, 81, 206, 42, 18, 134, 31]);
        assert_eq!(physical.search_hash().unwrap(), [78, 156, 183, 212, 200, 202, 21, 28, 141, 186, 112, 143, 251, 30, 75, 94, 181, 25, 141, 56, 94, 90, 55, 225, 163, 229, 80, 25, 50, 210, 169, 40]);
        // NoDelta on the real consumer does not move the objects version.
        let epoch_after = stamp_a.objects_epoch;
        let frontier_after = writer_a.sync_frontier().await.unwrap();
        assert_eq!(frontier_after, frontier_a);
        assert_eq!(
            sqlite_a.lock().unwrap().stamp().unwrap().objects_epoch,
            epoch_after
        );
    }

    /// One Wiki projection over the seed atom: the row is shaped exactly
    /// like the synthesis producer's wiki_row and evaluated through the real
    /// deferred-wiki machinery by both implementations.
    fn r185_wiki_row(snapshot: &crate::ProjectionSnapshot) -> ObjectRow {
        use evertrace_domain::canonical::{CanonicalValue, sha256};
        use evertrace_domain::semantic::WikiProjection;
        let atom_id = AtomId::from_str("atom:01890f47-6a4a-7cc1-98b9-01890f476e00").unwrap();
        let atom_row = snapshot
            .rows
            .iter()
            .find(|row| {
                row.object_kind.as_deref() == Some("atom_revision")
                    && row.current_revision_id.as_deref()
                        == Some("01890f47-6a4a-7cc1-98b9-01890f476e02")
            })
            .expect("seed has the current atom row");
        let payload: JournalPayload =
            serde_json::from_str(atom_row.payload_json.as_deref().unwrap()).unwrap();
        let JournalPayload::AtomRecorded(atom) = payload else {
            panic!("atom row must carry an AtomRecorded payload");
        };
        let topic = "writer-lineage";
        let (rendered_blob_ref, _contradictions) = crate::projections::synthesis::wiki_render_identity(
            topic,
            &[&atom],
            &[],
        )
        .unwrap();
        let page_id = evertrace_domain::ids::WikiProjectionId::from_digest(
            sha256(
                "evertrace.wiki_projection.page",
                1,
                &CanonicalValue::String(topic.into()),
            )
            .unwrap(),
        );
        let wiki = WikiProjection {
            page_id,
            topic: topic.into(),
            source_atom_ids: vec![atom_id],
            source_episode_ids: Vec::new(),
            compiler_version: 1,
            source_watermark: snapshot.frontier,
            rendered_blob_ref,
        };
        wiki.validate().unwrap();
        ObjectRow {
            row_id: format!("projection:wiki:{}", wiki.page_id),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Projection),
            object_family: None,
            object_kind: Some("wiki_projection".into()),
            object_id: None,
            current_revision_id: None,
            lifecycle: Some("current".into()),
            epistemic: Some("derived".into()),
            authority: Some("none".into()),
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: None,
            workstream_id: None,
            session_id: None,
            payload_json: Some(serde_json::to_string(&wiki).unwrap()),
            source_event_seq: wiki.source_watermark,
            projection_generation: 1,
        }
    }

    #[tokio::test]
    async fn deferred_wiki_evaluation_matches_frozen_original_expectation() {
        // Projection construction/visit-order equivalence only. Product Wiki
        // admission/review is covered by the existing S26 integration suite.
        let (_temp, _root, writer) = r185_nonempty_seed().await;
        let sqlite = writer.projection_handle();
        let (snapshot, _, _) = ProjectionWorker::new(sqlite.clone())
            .catch_up_validated(None, None)
            .await
            .unwrap();
        let mut rows = snapshot.rows.clone();
        rows.push(r185_wiki_row(&snapshot));
        rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
        let augmented = crate::ProjectionSnapshot {
            frontier: snapshot.frontier,
            rows,
        };
        let expected = super::derive_l0002_projections(&augmented).unwrap();
        assert!(expected.relations.iter().any(|row| {
            row.relation_kind.as_deref() == Some("wiki_to_source_atom")
        }));
        assert!(expected
            .search
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("wiki_projection")));
        // Any visit order derives the identical projection with the wiki row.
        let mut reversed = L0002RowAccumulator::default();
        for row in augmented.rows.iter().rev() {
            reversed.consume_row(row);
        }
        assert_eq!(reversed.finish(augmented.frontier).unwrap(), expected);
        assert_eq!((expected.relations.len(), expected.search.len()), (4, 5));
        assert_eq!(expected.relation_hash().unwrap(), [185, 3, 96, 67, 97, 226, 186, 127, 83, 12, 124, 76, 63, 192, 157, 251, 19, 21, 203, 153, 144, 59, 137, 158, 6, 170, 128, 123, 155, 253, 116, 23]);
        assert_eq!(expected.search_hash().unwrap(), [133, 65, 54, 56, 29, 154, 74, 115, 253, 119, 164, 190, 39, 170, 61, 199, 6, 74, 95, 249, 176, 53, 9, 117, 255, 39, 191, 91, 183, 252, 215, 238]);
        let currentness = expected.search.iter().filter(|row| row.object_kind.as_deref() == Some("atom_revision"))
            .map(|row| row.currentness.clone()).collect::<std::collections::BTreeSet<_>>();
        assert!(currentness.contains(&Some("current".into())) && currentness.contains(&Some("historical".into())));
    }

    #[tokio::test]
    async fn fused_ordinary_commit_fault_leaves_physical_state_unchanged() {
        // The single merged core's commit fault fires before any write on
        // the fused branch exactly like the complete branch.
        let (_temp, _root, mut writer) = r185_nonempty_seed().await;
        let sqlite = writer.projection_handle();
        let worker = ProjectionWorker::new(sqlite.clone());
        let (snapshot, _, _) = worker.catch_up_validated(None, None).await.unwrap();
        let epoch_b0 = sqlite.lock().unwrap().stamp().unwrap().objects_epoch;
        writer
            .commit(
                &r185_migration_command(
                    "01890f47-6a4a-7cc1-98b9-01890f476d40",
                    8,
                    "r185-fault",
                ),
                700,
            )
            .await
            .unwrap();
        let frontier = sqlite.lock().unwrap().stamp().unwrap().frontier;
        let delta = sqlite
            .lock()
            .unwrap()
            .rows_after(snapshot.frontier)
            .unwrap();
        assert!(!delta.is_empty(), "the fault arm needs a nonempty delta");
        assert!(matches!(
            worker
                .catch_up_inner(
                    true,
                    Some((epoch_b0, snapshot.frontier, frontier)),
                    Some(&delta),
                    Some(Box::new(L0002RowAccumulator::default())),
                )
                .await,
            Err(StoreError::Projection)
        ));
        let after = sqlite.lock().unwrap().stamp().unwrap();
        assert_eq!(after.objects_epoch, epoch_b0);
        assert_eq!(after.object_checkpoint, snapshot.frontier);
    }

    #[tokio::test]
    async fn existing_ledger_selects_complete_path_for_unrelated_command() {
        // The ledger is ALREADY persisted (a real ledger row plus the deleted
        // product rows removed, exactly as a purge round leaves them) before
        // the unrelated ordinary command. The ordinary delta carries no
        // reconcile flag, so only the existing-ledger exclusion keeps this off
        // the fused path. The store is reopened after the simulated purge
        // round, like a real restart.
        let run_arm = |via_writer: bool| async move {
            let (_temp, root, writer) = r185_nonempty_seed().await;
            let sqlite = writer.projection_handle();
            r185_insert_existing_ledger(&sqlite).await;
            drop(writer);
            let mut writer = crate::JournalWriter::open(&root).await.unwrap();
            let sqlite = writer.projection_handle();
            // Establish the trusted warm base BEFORE the unrelated append.
            writer.project().await.unwrap();
            let base = sqlite.lock().unwrap().stamp().unwrap();
            let before = writer.fused_delta_selections();
            let command = r185_migration_command(
                "01890f47-6a4a-7cc1-98b9-01890f476d31",
                7,
                "r185-after-ledger",
            );
            writer.commit(&command, 600).await.unwrap();
            if via_writer {
                writer.sync_frontier().await.unwrap();
            } else {
                let worker = ProjectionWorker::new(sqlite.clone());
                let frontier = sqlite.lock().unwrap().stamp().unwrap().frontier;
                let delta = sqlite
                    .lock()
                    .unwrap()
                    .rows_after(base.object_checkpoint)
                    .unwrap();
                assert!(!delta.is_empty(), "the ledger gate must face real work");
                let validated = Some((base.objects_epoch, base.object_checkpoint, frontier));
                let snap_checkpoint = base.object_checkpoint;
                let outcome = worker
                    .catch_up_inner(
                        false,
                        validated,
                        Some(&delta),
                        Some(Box::new(L0002RowAccumulator::default())),
                    )
                    .await
                    .unwrap();
                let crate::projections::CatchUpOutcome::Complete { snapshot, .. } = outcome else {
                    panic!("an existing ledger must select the complete path");
                };
                let search = open_search(&root).await;
                let l0002 = L0002ProjectionWorker::new(sqlite.clone(), search);
                let journal_epoch = sqlite.lock().unwrap().stamp().unwrap().journal_epoch;
                let proof_delta = ProjectionJournalDelta {
                    journal_epoch,
                    checkpoint: snap_checkpoint,
                    rows: delta.clone(),
                };
                let _ = l0002
                    .catch_up_validated_proof(&snapshot, Some(proof_delta))
                    .await
                    .unwrap();
            }
            let selected = writer.fused_delta_selections();
            drop(writer);
            let objects = sqlite.lock().unwrap().object_rows().unwrap();
            let relations = relation_rows(&sqlite);
            (
                selected,
                before,
                objects,
                relations,
            )
        };
        let (selected_writer, before_writer, objects_writer, relations_writer) =
            run_arm(true).await;
        let (selected_direct, before_direct, objects_direct, relations_direct) =
            run_arm(false).await;
        assert_eq!(
            selected_writer, before_writer,
            "an existing ledger must decline the fused path"
        );
        assert_eq!(selected_direct, before_direct);
        assert_eq!(objects_writer, objects_direct);
        assert_eq!(relations_writer, relations_direct);
    }

}
