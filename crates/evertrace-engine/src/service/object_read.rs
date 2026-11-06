//! Bounded kernel data reads. No presentation, diagnostics or background work.
use super::EngineService;

impl EngineService {
    pub async fn read_state(
        reader: evertrace_store::StoreReadHandle,
        effective_config_hash: [u8; 32],
    ) -> Result<evertrace_domain::query::ObjectReadState, evertrace_store::StoreError> {
        let (frontier, data_identity) = reader.state().await?;
        Ok(evertrace_domain::query::ObjectReadState {
            frontier,
            data_identity,
            effective_config_hash: evertrace_domain::evidence::hex(&effective_config_hash),
        })
    }
}
