//! Permission-checked list excerpts of stored values, never generated summaries.
use super::{
    HumanContentState as State, HumanGovernanceService, HumanSummary, export, presentation,
};
use evertrace_domain::{
    query::MemorySummaryOrigin as Origin,
    semantic::{
        AtomProposalPayload as A, CoreMembershipProposalPayload as C, ProposalPayload as P,
        SemanticDigestStatus,
    },
};
use evertrace_store::{JournalPayload, ObjectRow};
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanMemoryPreview {
    pub state: State,
    pub title: Option<String>,
    pub excerpt: Option<String>,
    pub origin: Option<Origin>,
    pub truncated: bool,
}
impl HumanMemoryPreview {
    fn unavailable(state: State) -> Self {
        Self {
            state,
            title: None,
            excerpt: None,
            origin: None,
            truncated: false,
        }
    }
    fn stored(title: &str, excerpt: Option<&str>, origin: Origin) -> Self {
        let (title, title_cut) = prefix(&presentation::display_name(title), 512);
        let title = (!title.is_empty()).then_some(title);
        let (excerpt, excerpt_cut) = excerpt
            .filter(|value| !value.is_empty())
            .map(|value| prefix(value, 1024))
            .map_or((None, false), |(text, cut)| (Some(text), cut));
        if title.is_none() && excerpt.is_none() {
            return Self::unavailable(State::Unsupported);
        }
        Self {
            state: State::Ready,
            title,
            excerpt,
            origin: Some(origin),
            truncated: title_cut || excerpt_cut,
        }
    }
}

impl HumanGovernanceService {
    pub(super) async fn reading_previews(&self, items: &mut [HumanSummary]) {
        for item in items.iter_mut() {
            item.reading_preview = matches!(
                item.object_kind.as_str(),
                "semantic_digest"
                    | "atom_revision"
                    | "procedure_revision"
                    | "core_membership"
                    | "revision_proposal_revision"
                    | "work_episode"
            )
            .then(|| HumanMemoryPreview::unavailable(State::Unavailable));
        }
        if !items.iter().any(|item| item.reading_preview.is_some()) {
            return;
        }
        let deadline = Instant::now() + presentation::READ_DEADLINE;
        // Retain the existing exact-detail access contract rather than creating
        // a second ACL. This request-local snapshot is a known active-read cost
        // debt, not a bounded point-read or final large-corpus qualification.
        let Ok(snapshot) = self.writer.project_objects().await else {
            return;
        };
        let Ok(index) = export::presentation_index(&snapshot, deadline) else {
            return;
        };
        for item in items {
            if item.reading_preview.is_none() {
                continue;
            }
            if Instant::now() > deadline {
                break;
            }
            let Some(revision) = item.revision_ref.as_deref() else {
                continue;
            };
            let Some(row) = index.get(item.stable_key.as_str()).and_then(|rows| {
                rows.iter().copied().find(|row| {
                    row.row_id == item.stable_key
                        && row.current_revision_id.as_deref() == Some(revision)
                        && row.object_kind.as_deref() == Some(item.object_kind.as_str())
                })
            }) else {
                item.reading_preview = Some(HumanMemoryPreview::unavailable(State::Missing));
                continue;
            };
            item.reading_preview = Some(
                match self
                    .readable_indexed_row(&snapshot, row, &index, deadline)
                    .await
                {
                    Ok(()) => stored_preview(row, &index)
                        .unwrap_or_else(|| HumanMemoryPreview::unavailable(State::Unsupported)),
                    Err(export::Failure::Denied) => {
                        HumanMemoryPreview::unavailable(State::AccessDenied)
                    }
                    Err(_) => HumanMemoryPreview::unavailable(State::Unavailable),
                },
            );
        }
    }
}

fn stored_preview(
    row: &ObjectRow,
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
) -> Option<HumanMemoryPreview> {
    let payload: JournalPayload = serde_json::from_str(row.payload_json.as_deref()?).ok()?;
    let preview = match payload {
        JournalPayload::AtomRecorded(value) => HumanMemoryPreview::stored(
            &value.value.subject,
            Some(&value.value.text),
            Origin::StoredValue,
        ),
        JournalPayload::ProcedureRevisionRecorded(value) => HumanMemoryPreview::stored(
            &value.draft.title,
            Some(&value.draft.summary),
            Origin::StoredValue,
        ),
        JournalPayload::CoreMembershipRecorded(value) => {
            // The membership's access closure already contains this exact Atom
            // revision; never substitute its current successor for the rule.
            let revision = value.atom_revision_id.to_string();
            let atom = index.get(revision.as_str())?.iter().find(|row| {
                row.object_kind.as_deref() == Some("atom_revision")
                    && row.current_revision_id.as_deref() == Some(revision.as_str())
            })?;
            let JournalPayload::AtomRecorded(atom) =
                serde_json::from_str(atom.payload_json.as_deref()?).ok()?
            else {
                return None;
            };
            HumanMemoryPreview::stored(
                &atom.value.subject,
                Some(&atom.value.text),
                Origin::StoredValue,
            )
        }
        JournalPayload::SemanticDigestRecorded(value) => {
            let delta = value
                .application
                .progress_delta
                .iter()
                .chain(&value.application.decision_delta)
                .chain(&value.application.failed_routes)
                .chain(&value.application.resolved_items)
                .chain(&value.application.open_loops)
                .chain(&value.application.outcome_delta)
                .next();
            let title = delta.map(|delta| delta.label.as_str()).unwrap_or(
                if value.source_target.is_some() {
                    "来源摘要"
                } else {
                    "工作摘要"
                },
            );
            let origin = match value.status {
                SemanticDigestStatus::DeterministicOnly => Origin::DigestDeterministic,
                SemanticDigestStatus::LlmEnriched => Origin::DigestLlmEnriched,
                SemanticDigestStatus::RejectedInvalid => Origin::DigestRejectedGeneration,
            };
            HumanMemoryPreview::stored(title, delta.map(|delta| delta.value.as_str()), origin)
        }
        JournalPayload::WorkEpisodeRecorded(value) => {
            let excerpt = value
                .open_loops
                .iter()
                .take(4)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n");
            let mut preview = HumanMemoryPreview::stored(
                &value.phase_contract.local_goal,
                Some(&excerpt),
                Origin::StoredValue,
            );
            preview.truncated |= value.open_loops.len() > 4;
            preview
        }
        JournalPayload::RevisionProposalRecorded(value) => match value.payload {
            P::Atom(value) => match value.as_ref() {
                A::Create { draft }
                | A::Replace { draft }
                | A::Merge { draft, .. }
                | A::Reclassify { draft } => HumanMemoryPreview::stored(
                    &draft.value.subject,
                    Some(&draft.value.text),
                    Origin::StoredValue,
                ),
                A::Deprecate { reason } => {
                    HumanMemoryPreview::stored("弃用提案", Some(reason), Origin::StoredValue)
                }
                A::Split { .. } => {
                    HumanMemoryPreview::stored("拆分提案", None, Origin::TypeFallback)
                }
            },
            P::Procedure(value) => HumanMemoryPreview::stored(
                &value.draft().title,
                Some(&value.draft().summary),
                Origin::StoredValue,
            ),
            // A proposal cohort is not permission to read an arbitrary Atom it
            // names. Do not resolve target bodies under only the proposal gate.
            P::CoreMembership(value) => HumanMemoryPreview::stored(
                match value.as_ref() {
                    C::Create { .. } => "规则晋升提案",
                    C::ResolveConflict { .. } => "规则冲突处理提案",
                },
                None,
                Origin::TypeFallback,
            ),
            P::ReservedTarget { summary, .. } => {
                HumanMemoryPreview::stored("规则提案参考", Some(&summary), Origin::StoredValue)
            }
        },
        _ => return None,
    };
    Some(preview)
}

fn prefix(value: &str, limit: usize) -> (String, bool) {
    if value.len() <= limit {
        return (value.to_owned(), false);
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}
