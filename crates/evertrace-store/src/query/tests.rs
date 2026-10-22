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
            worker
                .catch_up_validated_proof(&ahead, Some(delta.clone()))
                .await,
            Err(StoreError::StoreCorrupt)
        );

        assert_eq!(
            worker
                .catch_up_with_fault(&snapshot, Some(delta.clone()), true, false)
                .await,
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
            worker
                .catch_up_with_fault(&snapshot, Some(delta.clone()), false, true)
                .await,
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
            worker
                .catch_up_validated_proof(&snapshot, Some(delta.clone()))
                .await
                .unwrap()
                .0
                .frontier,
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
            worker
                .catch_up_validated_proof(&snapshot, Some(delta))
                .await,
            Err(StoreError::StoreCorrupt)
        );
        let relations_epoch_after = {
            let mut state = sqlite.lock().unwrap();
            state.stamp().unwrap().relations_epoch
        };
        assert_eq!(relations_epoch_after, relations_epoch);
        assert_eq!(search.version().await.unwrap(), search_version);
        assert_eq!(
            writer.project().await.unwrap().frontier,
            snapshot.frontier + 1
        );

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
            payload_json: Some(dirty.canonical_json().unwrap().into()),
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
        let snapshot = ProjectionWorker::new(sqlite.clone())
            .catch_up()
            .await
            .unwrap();
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
        let snapshot = ProjectionWorker::new(sqlite.clone())
            .catch_up()
            .await
            .unwrap();
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
        let (current, addresses) = crate::search::read_search_rows_with_addresses(&search)
            .await
            .unwrap();
        assert_eq!(
            commit_search_rows(
                &search, &current, &addresses, &search_rows, SearchCommitFault::None
            ).await,
            Err(StoreError::StoreCorrupt)
        );
    }

    // The native search writer must reproduce one complete expected family at
    // every committed version: checkpoint-only moves, an update plus an insert,
    // a further update before the FTS refresh, a removal and a no-op. The
    // expected set is maintained here, independently of the derivation under
    // test, and every step compares all 26 fields plus the returned version.
    #[tokio::test]
    async fn native_address_commit_keeps_complete_expected_search_family_across_versions() {
        fn surface(row_id: &str, text: &str, epoch: u64) -> SearchProjectionRow {
            let span_hash = "a".repeat(64);
            SearchProjectionRow {
                row_id: format!("search:evidence:{row_id}:{span_hash}"),
                row_variant: "evidence_surface".into(),
                candidate_id: Some(format!("{row_id}:1:{span_hash}")),
                source_ref: Some(row_id.into()),
                source_kind: Some("evidence_surface".into()),
                text: text.into(),
                source_role: Some("user".into()),
                content_trust: Some("user_statement".into()),
                capture_completeness: Some("complete".into()),
                instruction_authority: "none".into(),
                object_kind: None,
                currentness: None,
                lifecycle: None,
                epistemic: None,
                authority: None,
                task_id: None,
                repository_id: None,
                worktree_id: None,
                event_time_us: 1,
                recorded_at_us: 2,
                source_sequence: 0,
                time_domain: "event_time".into(),
                retrieval_completeness: "complete".into(),
                suppression_ref_hash: Some("b".repeat(64)),
                source_event_seq: epoch,
                projection_generation: 1,
            }
        }
        fn object(row_id: &str, text: &str, currentness: &str, epoch: u64) -> SearchProjectionRow {
            SearchProjectionRow {
                row_id: format!("search:object:{row_id}"),
                row_variant: "object".into(),
                candidate_id: Some(row_id.into()),
                source_ref: Some(row_id.into()),
                source_kind: Some("object_projection".into()),
                text: text.into(),
                source_role: None,
                content_trust: None,
                capture_completeness: None,
                instruction_authority: "none".into(),
                object_kind: Some("atom_revision".into()),
                currentness: Some(currentness.into()),
                lifecycle: Some("active".into()),
                epistemic: Some("unverified".into()),
                authority: Some("agent_inferred".into()),
                task_id: None,
                repository_id: None,
                worktree_id: None,
                event_time_us: 1,
                recorded_at_us: 0,
                source_sequence: 0,
                time_domain: "event_time".into(),
                retrieval_completeness: "complete".into(),
                suppression_ref_hash: None,
                source_event_seq: epoch,
                projection_generation: 1,
            }
        }
        async fn commit_expected(search: &lancedb::Table, expected: &[SearchProjectionRow]) -> u64 {
            let (current, addresses) = crate::search::read_search_rows_with_addresses(search)
                .await
                .unwrap();
            let before = search.version().await.unwrap();
            let mut wanted = expected.to_vec();
            wanted.sort();
            commit_search_rows(search, &current, &addresses, &wanted, SearchCommitFault::None)
                .await
                .unwrap();
            let version = search.version().await.unwrap();
            if current == wanted {
                assert_eq!(
                    version, before,
                    "an unchanged family is a zero-version no-op"
                );
            } else {
                assert_eq!(
                    version,
                    before + 1,
                    "each real change commits exactly one version"
                );
            }
            assert_eq!(read_search_rows(search).await.unwrap(), wanted);
            version
        }
        fn with_checkpoint(
            rows: &[SearchProjectionRow],
            frontier: u64,
        ) -> Vec<SearchProjectionRow> {
            let mut rows = rows.to_vec();
            rows.push(SearchProjectionRow::checkpoint(frontier));
            rows.sort();
            rows
        }

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let writer = crate::JournalWriter::open(&root).await.unwrap();
        let search = open_search(&root).await;
        // The canonical single FTS profile is the one the real writer already
        // built; this test does not add a second index.
        let indices = search.list_indices().await.unwrap();
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0].columns, ["text"]);

        let first_id = "01890f47-6a4a-7cc1-98b9-01890f476d01";
        let second_id = "01890f47-6a4a-7cc1-98b9-01890f476d02";
        let object_id = "01890f47-6a4a-7cc1-98b9-01890f476d03";
        let removed_id = "01890f47-6a4a-7cc1-98b9-01890f476d04";
        let initial = with_checkpoint(
            &[
                surface(first_id, "alphaword one", 1),
                surface(second_id, "betaword one", 1),
                object(object_id, "gammaword current", "current", 1),
                object(removed_id, "deltaword current", "current", 1),
            ],
            1,
        );
        let mut expected = initial.clone();
        commit_expected(&search, &expected).await;
        // Cover real indexed fragments before changing them, not only the
        // unindexed fallback of an index created on the empty table.
        search
            .optimize(lancedb::table::OptimizeAction::Index(Default::default()))
            .await
            .unwrap();
        let stats = search.index_stats(&indices[0].name).await.unwrap().unwrap();
        assert!(stats.num_indexed_rows > 0);
        assert_eq!(stats.num_unindexed_rows, 0);
        let earliest = search.version().await.unwrap();
        // One old dataset pin, opened at the first committed version.
        let pinned = open_search(&root).await;
        pinned.checkout(earliest).await.unwrap();
        assert_eq!(
            crate::search::read_search_rows_at_current_version(&pinned)
                .await
                .unwrap(),
            expected
        );

        // 1. Checkpoint-only move.
        let mut next = expected
            .iter()
            .filter(|row| row.row_id != crate::SEARCH_CHECKPOINT_ID)
            .cloned()
            .collect::<Vec<_>>();
        next.push(SearchProjectionRow::checkpoint(4));
        next.sort();
        expected = next;
        let checkpoint_version = commit_expected(&search, &expected).await;
        assert_eq!(checkpoint_version, earliest + 1);

        // 2. One old row update plus one new row insert.
        for row in expected.iter_mut() {
            if row.row_id == format!("search:evidence:{first_id}:{}", "a".repeat(64)) {
                row.text = "alphaword two".into();
                row.source_event_seq = 4;
            }
        }
        expected.push(surface(
            "01890f47-6a4a-7cc1-98b9-01890f476d05",
            "epsilonword one",
            4,
        ));
        expected.sort();
        let after_update = commit_expected(&search, &expected).await;
        // A companion read at this version, kept to prove it later refuses.
        let stale = crate::search::read_search_rows_with_addresses(&search)
            .await
            .unwrap()
            .1;

        // 3. A further update before the FTS data refresh.
        for row in expected.iter_mut() {
            if row.row_id == format!("search:object:{object_id}") {
                row.currentness = Some("historical".into());
                row.text = "gammaword historical".into();
                row.source_event_seq = 5;
            }
        }
        commit_expected(&search, &expected).await;

        // 4. Remove one old row.
        expected.retain(|row| row.row_id != format!("search:object:{removed_id}"));
        let after_removal = commit_expected(&search, &expected).await;
        assert_eq!(after_removal, after_update + 2);

        // 5. A whole no-op family must not advance the search version.
        let noop = expected.clone();
        commit_expected(&search, &noop).await;
        assert_eq!(noop, expected, "the no-op family is the expected family");
        let mut final_version = search.version().await.unwrap();
        assert_eq!(final_version, after_removal);

        // FTS reflects current text through the production indexed+flat query path.
        let inserted_id = format!(
            "search:evidence:01890f47-6a4a-7cc1-98b9-01890f476d05:{}",
            "a".repeat(64)
        );
        let hits = crate::search::query_rows_for_test(&search, "alphaword", 64)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "alphaword two");
        assert_eq!(
            crate::search::query_rows_for_test(&search, "epsilonword", 64)
                .await
                .unwrap()
                .iter()
                .map(|row| row.row_id.as_str())
                .collect::<Vec<_>>(),
            vec![inserted_id.as_str()],
            "the inserted row is found before the FTS data refresh"
        );
        assert!(
            crate::search::query_rows_for_test(&search, "deltaword", 64)
                .await
                .unwrap()
                .is_empty(),
            "a removed row is not returned"
        );
        assert!(
            crate::search::query_rows_for_test(&search, "gammaword", 64)
                .await
                .unwrap()
                .iter()
                .any(|row| row.currentness.as_deref() == Some("historical")
                    && row.text == "gammaword historical"),
            "an updated row is returned with its new fields"
        );
        assert_eq!(
            crate::search::query_rows_for_test(&search, "betaword", 64)
                .await
                .unwrap()
                .len(),
            1
        );

        // An address companion from the older version must refuse before any
        // visible change: stale addresses are never rebound to a new version.
        let mut stale_expected = expected.clone();
        stale_expected[0].text.push_str(" stale");
        assert_eq!(
            commit_search_rows(
                &search,
                &read_search_rows(&search).await.unwrap(),
                &stale,
                &stale_expected,
                SearchCommitFault::None
            )
            .await,
            Err(StoreError::StoreCorrupt)
        );
        assert_eq!(search.version().await.unwrap(), after_removal);
        assert_eq!(
            read_search_rows(&search).await.unwrap(),
            expected,
            "a rejected stale companion changes no row"
        );

        // Same numeric version on another handle cannot authorize these
        // addresses. Bind the immutable dataset and its actual table owner.
        let (base, addresses) = crate::search::read_search_rows_with_addresses(&search)
            .await
            .unwrap();
        let independent = open_search(&root).await;
        assert_eq!(independent.version().await.unwrap(), addresses.version());
        let mut next = expected.clone();
        next.iter_mut().find(|row| row.row_variant == "object").unwrap().text =
            "gammaword recovered".into();
        assert_eq!(
            commit_search_rows(&independent, &base, &addresses, &next, SearchCommitFault::None).await,
            Err(StoreError::StoreCorrupt)
        );

        // Files staged before a failed commit do not publish partial rows or
        // checkpoint. A lost ACK after commit is recovered from actual rows.
        assert_eq!(
            commit_search_rows(&search, &base, &addresses, &next, SearchCommitFault::AfterStaging).await,
            Err(StoreError::Projection)
        );
        assert_eq!(search.version().await.unwrap(), final_version);
        assert_eq!(read_search_rows(&search).await.unwrap(), expected);
        assert_eq!(
            commit_search_rows(&search, &base, &addresses, &next, SearchCommitFault::AfterCommit).await,
            Err(StoreError::Projection)
        );
        expected = next;
        final_version += 1;
        assert_eq!(search.version().await.unwrap(), final_version);
        assert_eq!(read_search_rows(&search).await.unwrap(), expected);
        assert_eq!(commit_expected(&search, &expected).await, final_version);
        drop(independent);

        // The old pin still returns exactly its original content.
        assert_eq!(
            crate::search::read_search_rows_at_current_version(&pinned)
                .await
                .unwrap(),
            initial
        );

        // Reopen the current table on a fresh connection and compare against the
        // independent expected set.
        drop(pinned);
        drop(search);
        drop(writer);
        let reopened_search = open_search(&root).await;
        assert_eq!(
            read_search_rows(&reopened_search).await.unwrap(),
            expected,
            "reopen must show exactly the expected family"
        );
        assert_eq!(
            crate::search::read_search_rows_with_addresses(&reopened_search)
                .await
                .unwrap()
                .0,
            expected
        );
        assert_eq!(
            reopened_search.version().await.unwrap(),
            final_version,
            "reopen must not repair or grow the committed search version"
        );
    }
}
