//! Exact revision comparisons through the existing current human read gates.
use super::*;
use evertrace_domain::query::{
    HUMAN_COMPARE_LIMIT, HUMAN_COMPARE_VALUE_BYTES, HumanComparedValue, HumanComparisonStatus,
    HumanFieldChange, HumanFieldChangeKind, HumanRevisionComparison, HumanRevisionKind,
    HumanRevisionRef, RevisionCompareCursor, RevisionCompareQuery,
};
use serde_json::Value;

impl HumanGovernanceService {
    pub async fn compare_revisions(
        &self,
        query: RevisionCompareQuery,
        expected_frontier: u64,
        after: Option<&str>,
        limit: u16,
    ) -> Result<Result<HumanRevisionComparison, u64>, HumanGovernanceError> {
        query
            .validate()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if !(1..=HUMAN_COMPARE_LIMIT).contains(&limit) {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let cursor = after
            .map(|raw| {
                if raw.len() > 8192 {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                let cursor: RevisionCompareCursor =
                    serde_json::from_str(raw).map_err(|_| HumanGovernanceError::InvalidInput)?;
                cursor
                    .validate_for(&query, expected_frontier)
                    .map_err(|_| HumanGovernanceError::InvalidInput)?;
                Ok(cursor)
            })
            .transpose()?;
        // Both exact versions and both gates see one canonical snapshot. This
        // does not claim a finite authorization closure or constant-RSS read.
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier < expected_frontier
            || cursor
                .as_ref()
                .is_some_and(|value| value.frontier != snapshot.frontier)
        {
            return Ok(Err(snapshot.frontier));
        }
        let left = select(&snapshot, &query.left)?;
        let right = select(&snapshot, &query.right)?;
        if let (Some(left), Some(right)) = (left, right)
            && (left.object_kind != right.object_kind
                || left.object_id.is_none()
                || left.object_id != right.object_id)
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let deadline = std::time::Instant::now() + presentation::READ_DEADLINE;
        let (left_state, left_value) = self.comparison_side(&snapshot, left, deadline).await?;
        let (right_state, right_value) = self.comparison_side(&snapshot, right, deadline).await?;
        let object_kind = left.and_then(revision_kind);
        let mut result = HumanRevisionComparison {
            frontier: snapshot.frontier,
            query,
            object_kind,
            status: HumanComparisonStatus::SideUnavailable,
            left_state,
            right_state,
            fields: Vec::new(),
            changed_fields: None,
            next_cursor: None,
        };
        // No names, values, lengths or difference counts derived from a side
        // whose current source/deletion gate did not pass.
        let (Some(left), Some(right)) = (left_value, right_value) else {
            return Ok(Ok(result));
        };
        let mut changes = BTreeMap::new();
        let mut nodes = 8192_usize;
        if !differences(&left, &right, "", 0, deadline, &mut nodes, &mut changes) {
            result.status = HumanComparisonStatus::BudgetExhausted;
            return Ok(Ok(result));
        }
        if cursor
            .as_ref()
            .is_some_and(|value| !changes.contains_key(&value.after_path))
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        result.status = HumanComparisonStatus::Ready;
        result.changed_fields = Some(changes.len() as u64);
        let mut selected = changes
            .into_iter()
            .filter(|(path, _)| {
                cursor
                    .as_ref()
                    .is_none_or(|cursor| path > &cursor.after_path)
            })
            .take(usize::from(limit) + 1)
            .collect::<Vec<_>>();
        if selected.len() > usize::from(limit) {
            result.next_cursor = Some(
                serde_json::to_string(&RevisionCompareCursor {
                    frontier: result.frontier,
                    query: result.query.clone(),
                    after_path: selected[usize::from(limit) - 1].0.clone(),
                })
                .map_err(|_| HumanGovernanceError::Store)?,
            );
        }
        selected.truncate(usize::from(limit));
        for (path, (left, right)) in selected {
            result.fields.push(HumanFieldChange {
                path,
                change: match (left, right) {
                    (None, _) => HumanFieldChangeKind::Added,
                    (_, None) => HumanFieldChangeKind::Removed,
                    _ => HumanFieldChangeKind::Modified,
                },
                left: present_value(left)?,
                right: present_value(right)?,
            });
            if std::time::Instant::now() >= deadline {
                result.status = HumanComparisonStatus::BudgetExhausted;
                result.fields.clear();
                result.changed_fields = None;
                result.next_cursor = None;
                break;
            }
        }
        if !result.validate() {
            return Err(HumanGovernanceError::Store);
        }
        Ok(Ok(result))
    }

    async fn comparison_side(
        &self,
        snapshot: &ProjectionSnapshot,
        row: Option<&ObjectRow>,
        deadline: std::time::Instant,
    ) -> Result<(HumanContentState, Option<Value>), HumanGovernanceError> {
        let Some(row) = row else {
            return Ok((HumanContentState::Missing, None));
        };
        if revision_kind(row).is_none() {
            return Ok((HumanContentState::Unsupported, None));
        }
        if let Err(error) = self.readable_row(snapshot, row, deadline).await {
            return Ok((presentation::access_state(error), None));
        }
        let value = if row.object_kind.as_deref() == Some("revision_proposal_revision") {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanGovernanceError::Store)?,
            )
            .map_err(|_| HumanGovernanceError::Store)?;
            let JournalPayload::RevisionProposalRecorded(value) = payload else {
                return Err(HumanGovernanceError::Store);
            };
            value.validate().map_err(|_| HumanGovernanceError::Store)?;
            if row.object_id.as_deref() != Some(value.proposal_id.to_string().as_str())
                || row.current_revision_id.as_deref()
                    != Some(value.proposal_revision_id.to_string().as_str())
            {
                return Err(HumanGovernanceError::Store);
            }
            serde_json::to_value(value)
        } else {
            let Some((content, _)) = presentation::semantic_value(row)? else {
                return Err(HumanGovernanceError::Store);
            };
            match content {
                HumanSemanticContent::Atom(value) => serde_json::to_value(value),
                HumanSemanticContent::Procedure(value) => serde_json::to_value(value),
                HumanSemanticContent::CoreMembership(value) => serde_json::to_value(value),
                HumanSemanticContent::Digest(value) => serde_json::to_value(value),
            }
        }
        .map_err(|_| HumanGovernanceError::Store)?;
        Ok((HumanContentState::Ready, Some(value)))
    }
}

fn select<'a>(
    snapshot: &'a ProjectionSnapshot,
    reference: &HumanRevisionRef,
) -> Result<Option<&'a ObjectRow>, HumanGovernanceError> {
    let Some(row) = snapshot.row(&reference.stable_key) else {
        return Ok(None);
    };
    if row.row_class != Some(ObjectRowClass::Object)
        || row.current_revision_id.as_deref() != Some(reference.revision_ref.as_str())
    {
        return Err(HumanGovernanceError::InvalidInput);
    }
    Ok(Some(row))
}

fn revision_kind(row: &ObjectRow) -> Option<HumanRevisionKind> {
    Some(match row.object_kind.as_deref()? {
        "atom_revision" => HumanRevisionKind::Atom,
        "procedure_revision" => HumanRevisionKind::Procedure,
        "core_membership" => HumanRevisionKind::CoreMembership,
        "revision_proposal_revision" => HumanRevisionKind::Proposal,
        "semantic_digest" => HumanRevisionKind::Digest,
        _ => return None,
    })
}

fn present_value(value: Option<&Value>) -> Result<HumanComparedValue, HumanGovernanceError> {
    let Some(value) = value else {
        return Ok(HumanComparedValue::Absent);
    };
    let json = serde_json::to_string(value).map_err(|_| HumanGovernanceError::Store)?;
    let bytes = json.len();
    Ok(if bytes > HUMAN_COMPARE_VALUE_BYTES {
        HumanComparedValue::TooLarge {
            original_bytes: bytes as u64,
        }
    } else {
        HumanComparedValue::Ready { json }
    })
}

type ChangedValues<'a> = BTreeMap<String, (Option<&'a Value>, Option<&'a Value>)>;

// Native typed field comparison, not semantic truth or a browser's business
// resolver. Arrays and deep/large maps are whole fields; missing != JSON null.
fn differences<'a>(
    left: &'a Value,
    right: &'a Value,
    path: &str,
    depth: usize,
    deadline: std::time::Instant,
    nodes: &mut usize,
    output: &mut ChangedValues<'a>,
) -> bool {
    if *nodes == 0 || std::time::Instant::now() >= deadline {
        return false;
    }
    *nodes -= 1;
    if left == right {
        return true;
    }
    if let (Value::Object(left_map), Value::Object(right_map)) = (left, right)
        && depth < 8
        && left_map.len() + right_map.len() <= 128
    {
        let keys = left_map
            .keys()
            .chain(right_map.keys())
            .collect::<BTreeSet<_>>();
        for key in keys {
            let next = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
            if next.len() > 1024 || next.chars().any(char::is_control) {
                return false;
            }
            match (left_map.get(key), right_map.get(key)) {
                (Some(left), Some(right)) => {
                    if !differences(left, right, &next, depth + 1, deadline, nodes, output) {
                        return false;
                    }
                }
                values => {
                    output.insert(next, values);
                }
            }
        }
    } else {
        output.insert(path.to_owned(), (Some(left), Some(right)));
    }
    output.len() <= 4096
}
