use super::*;
use evertrace_domain::source::{SourceCatalogCursor, SourceCatalogPage, SourceCatalogQuery};

impl HumanGovernanceService {
    pub async fn source_catalog(
        &self,
        query: SourceCatalogQuery,
        expected_frontier: Option<u64>,
        after: Option<&str>,
        limit: u16,
    ) -> Result<Result<SourceCatalogPage, u64>, HumanGovernanceError> {
        query
            .validate()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let cursor = after
            .map(|raw| {
                if raw.len() > 4096 {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                let cursor: SourceCatalogCursor =
                    serde_json::from_str(raw).map_err(|_| HumanGovernanceError::InvalidInput)?;
                cursor
                    .validate_for(&query)
                    .map_err(|_| HumanGovernanceError::InvalidInput)?;
                if expected_frontier != Some(cursor.frontier) {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                Ok(cursor)
            })
            .transpose()?;
        let page = self
            .writer
            .source_catalog_page(&query, cursor.as_ref(), usize::from(limit))
            .await
            .map_err(|error| {
                if error == crate::WriterActorError::InvalidInput {
                    HumanGovernanceError::InvalidInput
                } else {
                    HumanGovernanceError::Store
                }
            })?;
        if expected_frontier.is_some_and(|value| value != page.frontier) {
            return Ok(Err(page.frontier));
        }
        Ok(Ok(page))
    }
}
