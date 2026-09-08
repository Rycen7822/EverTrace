use evertrace_protocol::envelope::McpResultEnvelope;

pub(crate) fn bound_result(
    envelope: &mut McpResultEnvelope,
    action: evertrace_protocol::mcp::McpAction,
    target_bytes: usize,
) {
    let hard_bytes = if action == evertrace_protocol::mcp::McpAction::Get {
        9_600
    } else {
        4_800
    };
    while envelope_bytes(envelope) > target_bytes {
        if !trim_one_item(envelope) {
            break;
        }
        envelope.truncated = true;
    }
    if envelope.next_refs.len() > 8 {
        let omitted = envelope.next_refs.len() - 8;
        envelope.next_refs.truncate(8);
        envelope
            .warnings
            .push(format!("next_refs_omitted:{omitted}"));
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes {
        let omitted = envelope.warnings.len();
        envelope.warnings.clear();
        envelope
            .warnings
            .push(format!("warnings_aggregated:{omitted}"));
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes {
        let mut omitted = 0;
        while envelope_bytes(envelope) > hard_bytes && envelope.next_refs.len() > 1 {
            let longest = envelope
                .next_refs
                .iter()
                .enumerate()
                .max_by_key(|(_, value)| value.len())
                .map(|(index, _)| index)
                .unwrap_or(0);
            envelope.next_refs.remove(longest);
            omitted += 1;
        }
        envelope
            .warnings
            .push(format!("next_refs_aggregated:{omitted}"));
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes && envelope.audit_ref.take().is_some() {
        envelope.warnings.push("audit_ref_omitted".into());
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes {
        envelope.warnings = vec!["output_hard_truncated".into()];
        envelope.next_refs.clear();
        envelope.audit_ref = None;
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes {
        envelope.scope = "scope_omitted".into();
        envelope.truncated = true;
    }
}

fn envelope_bytes(envelope: &McpResultEnvelope) -> usize {
    serde_json::to_vec(envelope).map_or(usize::MAX, |value| value.len())
}

fn trim_one_item(envelope: &mut McpResultEnvelope) -> bool {
    for partition in [
        &mut envelope.items.evidence,
        &mut envelope.items.warnings,
        &mut envelope.items.procedures,
        &mut envelope.items.normative_constraints,
    ] {
        if let Some(item) = partition
            .iter_mut()
            .rev()
            .find(|item| item.text.as_ref().is_some_and(|text| !text.is_empty()))
            && let Some(text) = &mut item.text
        {
            let mut keep = text.len() / 2;
            while keep > 0 && !text.is_char_boundary(keep) {
                keep -= 1;
            }
            text.truncate(keep);
            return true;
        }
        if let Some(removed) = partition.pop() {
            if let Some(reference) = removed.object_ref
                && envelope.next_refs.len() < 32
                && !envelope.next_refs.contains(&reference)
            {
                envelope.next_refs.push(reference);
            }
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_protocol::envelope::{McpItem, McpItems, McpStatus};

    #[test]
    fn bounded_result_preserves_closed_safety_markers_and_continuation_refs() {
        let critical_ref = "atom:019c0000-0000-7000-8000-000000000001".to_owned();
        let mut envelope = McpResultEnvelope {
            schema_version: 1,
            request_id: "019c0000-0000-7000-8000-000000000001".parse().unwrap(),
            status: McpStatus::Partial,
            scope: "@active".into(),
            freshness: "stale".into(),
            completeness: "partial".into(),
            items: McpItems {
                evidence: (0..16)
                    .map(|_| McpItem {
                        kind: "evidence".into(),
                        object_ref: Some(critical_ref.clone()),
                        object_revision_ref: None,
                        source_revision_ref: None,
                        scope: None,
                        applicability: None,
                        authority: None,
                        text: Some("untrusted body ".repeat(800)),
                        content_trust: serde_json::from_str("\"untrusted_source_content\"")
                            .unwrap(),
                        capture_completeness: None,
                        instruction_authority: serde_json::from_str("\"none\"").unwrap(),
                    })
                    .collect(),
                ..McpItems::default()
            },
            warnings: vec!["search_projection_stale".into(); 64],
            truncated: false,
            next_refs: vec![critical_ref.clone(); 16],
            audit_ref: None,
        };
        bound_result(
            &mut envelope,
            evertrace_protocol::mcp::McpAction::Search,
            2_400,
        );
        assert!(envelope.truncated);
        assert!(serde_json::to_vec(&envelope).unwrap().len() <= 4_800);
        assert_eq!(envelope.freshness, "stale");
        assert_eq!(envelope.completeness, "partial");
        assert!(!envelope.warnings.is_empty());
        assert!(
            envelope.next_refs.contains(&critical_ref)
                || envelope
                    .items
                    .evidence
                    .iter()
                    .any(|item| item.object_ref.as_ref() == Some(&critical_ref))
        );
    }

    #[test]
    fn bounded_result_caps_giant_normative_and_procedure_partitions_without_evidence() {
        let item = |kind: &str, reference: &str| McpItem {
            kind: kind.into(),
            object_ref: Some(reference.into()),
            object_revision_ref: None,
            source_revision_ref: None,
            scope: Some("repo:019c0000-0000-7000-8000-000000000001".into()),
            applicability: Some("true".into()),
            authority: Some("user_explicit".into()),
            text: Some("bounded body ".repeat(2_000)),
            content_trust: serde_json::from_str("\"user_statement\"").unwrap(),
            capture_completeness: Some("complete".into()),
            instruction_authority: serde_json::from_str("\"none\"").unwrap(),
        };
        let mut envelope = McpResultEnvelope {
            schema_version: 1,
            request_id: "019c0000-0000-7000-8000-000000000001".parse().unwrap(),
            status: McpStatus::Ok,
            scope: "w".repeat(4_096),
            freshness: "current".into(),
            completeness: "complete".into(),
            items: McpItems {
                normative_constraints: vec![item("constraint", "atom:normative")],
                procedures: vec![item("procedure", "procedure:bounded")],
                evidence: Vec::new(),
                warnings: Vec::new(),
            },
            warnings: Vec::new(),
            truncated: false,
            next_refs: vec!["r".repeat(512)],
            audit_ref: None,
        };
        bound_result(
            &mut envelope,
            evertrace_protocol::mcp::McpAction::Search,
            2_400,
        );
        assert!(envelope.truncated);
        assert!(serde_json::to_vec(&envelope).unwrap().len() <= 4_800);
        assert!(
            envelope
                .items
                .normative_constraints
                .iter()
                .any(|value| { value.object_ref.as_deref() == Some("atom:normative") })
                || envelope
                    .next_refs
                    .iter()
                    .any(|value| value == "atom:normative")
        );
        assert!(
            envelope
                .items
                .procedures
                .iter()
                .any(|value| { value.object_ref.as_deref() == Some("procedure:bounded") })
                || envelope
                    .next_refs
                    .iter()
                    .any(|value| value == "procedure:bounded")
        );
    }

    #[test]
    fn bounded_result_trims_large_item_before_preserving_medium_scope() {
        let scope = format!("repo:{}", "s".repeat(300));
        let mut envelope = McpResultEnvelope {
            schema_version: 1,
            request_id: "019c0000-0000-7000-8000-000000000001".parse().unwrap(),
            status: McpStatus::Ok,
            scope: scope.clone(),
            freshness: "current".into(),
            completeness: "complete".into(),
            items: McpItems {
                evidence: vec![McpItem {
                    kind: "evidence".into(),
                    object_ref: Some("atom:bounded".into()),
                    object_revision_ref: Some("revision:bounded".into()),
                    source_revision_ref: None,
                    scope: Some(scope.clone()),
                    applicability: None,
                    authority: None,
                    text: Some("large body ".repeat(4_000)),
                    content_trust: serde_json::from_str("\"agent_claim\"").unwrap(),
                    capture_completeness: Some("complete".into()),
                    instruction_authority: serde_json::from_str("\"none\"").unwrap(),
                }],
                ..McpItems::default()
            },
            warnings: Vec::new(),
            truncated: false,
            next_refs: Vec::new(),
            audit_ref: None,
        };
        bound_result(
            &mut envelope,
            evertrace_protocol::mcp::McpAction::Search,
            2_400,
        );
        assert_eq!(envelope.scope, scope);
        assert!(envelope.truncated);
        assert!(envelope_bytes(&envelope) <= 4_800);
    }

    #[test]
    fn bounded_result_shrinks_long_continuation_refs_before_omitting_large_scope() {
        let scope = format!("repo:{}", "s".repeat(600));
        let mut envelope = McpResultEnvelope {
            schema_version: 1,
            request_id: "019c0000-0000-7000-8000-000000000001".parse().unwrap(),
            status: McpStatus::Partial,
            scope: scope.clone(),
            freshness: "current".into(),
            completeness: "partial".into(),
            items: McpItems::default(),
            warnings: Vec::new(),
            truncated: false,
            next_refs: (0..16)
                .map(|index| format!("{index:02}{}", "r".repeat(510)))
                .collect(),
            audit_ref: Some("audit:bounded".into()),
        };
        bound_result(
            &mut envelope,
            evertrace_protocol::mcp::McpAction::Search,
            2_400,
        );
        assert_eq!(envelope.scope, scope);
        assert!(envelope.truncated);
        assert!(envelope.next_refs.len() < 16);
        assert!(envelope_bytes(&envelope) <= 4_800);
    }
}
