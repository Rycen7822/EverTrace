//! Request-local read admission facts shared by native presentations, never a search cache.

use std::time::Instant;

use evertrace_domain::{
    error::ErrorCode,
    query::{ExactFieldsQuery, ExactReadQuery, MetadataReadOutcome},
};
use evertrace_store::ObjectRow;

use crate::{WriterHandle, repository::RepositoryReadAuthority};

/// Assess only the canonical source and repository closure; observation recording belongs to callers.
pub(crate) async fn check_source_access(
    writer: &WriterHandle,
    authority: &RepositoryReadAuthority<'_>,
    all_rows: &[ObjectRow],
    rows: &[&ObjectRow],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    for chunk in rows.chunks(usize::from(evertrace_domain::query::METADATA_READ_LIMIT)) {
        if Instant::now() >= deadline {
            return Err(ErrorCode::ResourceExhausted);
        }
        if !crate::session_import::source_rows_read_assessment(
            writer,
            authority,
            all_rows,
            chunk,
            None,
            Some(deadline),
        )
        .await
        .map_err(|_| ErrorCode::StoreCorrupt)?
        .0
        .is_empty()
        {
            return Err(ErrorCode::Untrusted);
        }
    }
    let scopes = crate::repository::row_repository_contexts_from_scopes(all_rows.iter(), rows)
        .map_err(|_| ErrorCode::StoreCorrupt)?;
    if !crate::repository::repository_read_assessment(
        writer,
        scopes.values().flatten().copied().collect(),
        authority,
        deadline,
    )
    .await
    .map_err(|_| ErrorCode::StoreCorrupt)?
    .0
    .is_empty()
    {
        return Err(ErrorCode::Untrusted);
    }
    if Instant::now() >= deadline {
        return Err(ErrorCode::ResourceExhausted);
    }
    Ok(())
}

/// Use the existing bounded exact-read dependencies for an offered Atom revision.
/// A bare object scope is not proof that the source of its text remains readable.
pub(crate) async fn atom_source_readable(
    writer: &WriterHandle,
    authority: &RepositoryReadAuthority<'_>,
    revision: &str,
    frontier: u64,
    config_hash: [u8; 32],
    deadline: Instant,
) -> bool {
    let read = async {
        let query = ExactReadQuery::Fields(ExactFieldsQuery {
            revision_ref: revision.to_owned(),
        });
        let (cancelled, _cancel_on_drop) = evertrace_store::StoreReadHandle::cancellation_scope();
        let Ok(MetadataReadOutcome::Page(context)) = writer
            .read_stored_fields_context(Box::new(query), cancelled, deadline, config_hash)
            .await
        else {
            return false;
        };
        if context.state.frontier != frontier
            || context.source_suppressed
            || context.selected.as_ref().is_none_or(|row| {
                row.current_revision_id.as_deref() != Some(revision)
                    || row.object_kind.as_deref() != Some("atom_revision")
            })
        {
            return false;
        }
        let refs = context.rows.iter().collect::<Vec<_>>();
        check_source_access(writer, authority, &context.rows, &refs, deadline)
            .await
            .is_ok()
            && writer
                .read_handle()
                .state()
                .await
                .is_ok_and(|state| state == (frontier, context.state.data_identity))
    };
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), read)
        .await
        .unwrap_or(false)
}
