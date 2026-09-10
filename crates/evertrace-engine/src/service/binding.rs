use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use evertrace_capture::{DeviceKey, DeviceKeyStore, mcp_call_auth_tag, verify_mcp_call_auth_tag};
use evertrace_codex::binding::{
    BINDING_PROTOCOL_REVISION, BindingAnchor, CanonicalBindingCall, PublicWorkspace,
    TransportWorkspace, valid_lexical_absolute_path,
};
use evertrace_domain::revision::RevisionId;
use thiserror::Error;

const MCP_CLAIM_TTL: Duration = Duration::from_secs(5);
const MCP_CWD_TTL: Duration = Duration::from_secs(30);
const MCP_BINDING_CAPACITY: usize = 256;

#[derive(Clone, Eq, PartialEq)]
pub struct McpBindingIssue {
    pub session_id: String,
    pub turn_id: String,
    pub tool_use_id: String,
    pub agent_id: Option<String>,
    pub action: String,
    pub workspace: String,
    pub input: String,
    pub refs: Vec<String>,
    pub launcher_protocol_revision: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpBindingGrant {
    pub bound_workspace: String,
    pub expires_at_us: i64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpResolvedScope {
    pub workspace: PublicWorkspace,
    pub anchor: Option<BindingAnchor>,
    pub mechanism: McpScopeMechanism,
    pub(crate) repository_report: Option<Arc<evertrace_codex::probe::HostProbeReport>>,
    pub(crate) inventory_host: Option<Arc<crate::repository::NativeHostContext>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpScopeMechanism {
    ExactClaim,
    ConnectionScoped,
    CwdOnly,
    Explicit,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum McpBindingError {
    #[error("MCP scope is unresolved")]
    ScopeUnresolved,
}

#[derive(Clone)]
pub struct McpBindingAuthority {
    device_key: DeviceKey,
    state: Arc<Mutex<McpBindingState>>,
}

#[derive(Default)]
struct McpBindingState {
    claims: BTreeMap<String, McpClaim>,
    client_cwds: BTreeMap<String, McpPinnedCwd>,
    canary: Option<CanaryBindingObservation>,
}

struct CanaryBindingObservation {
    nonce: String,
    workspace: String,
    deadline: Instant,
    started_at: Instant,
    consumed: Option<CanaryConsumedClaim>,
    conflicted: bool,
}

/// Captured only after the existing exact-call MAC and atomic consume checks.
/// This is one probe's transient mechanism evidence, not a connection/lane lease.
#[derive(Clone)]
pub(crate) struct CanaryConsumedClaim {
    pub token: String,
    pub anchor: BindingAnchor,
    pub issued_at: Instant,
    pub expires_at: Instant,
    pub consumed_at: Instant,
}

struct McpClaim {
    anchor: BindingAnchor,
    workspace: PublicWorkspace,
    canonical_call_auth_tag: [u8; 32],
    expires_at: Instant,
    repository_report: Option<Arc<evertrace_codex::probe::HostProbeReport>>,
}

struct McpPinnedCwd {
    path: String,
    expires_at: Instant,
    inventory_host: Option<Arc<crate::repository::NativeHostContext>>,
    inventory_report: Option<Arc<evertrace_codex::HostProbeReport>>,
    inventory_session: Option<String>,
    inventory_pending: bool,
    inventory_wakeup: bool,
}

impl McpPinnedCwd {
    fn request_inventory_rescan(&mut self) {
        if !self.inventory_pending {
            self.inventory_pending = true;
            self.inventory_wakeup = true;
        }
    }
}

impl McpBindingAuthority {
    pub(crate) fn begin_canary(&self, nonce: &str, workspace: &str, deadline: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state
            .canary
            .as_ref()
            .is_some_and(|value| value.deadline > Instant::now())
        {
            return false;
        }
        state.canary = Some(CanaryBindingObservation {
            nonce: nonce.into(),
            workspace: workspace.into(),
            deadline,
            started_at: Instant::now(),
            consumed: None,
            conflicted: false,
        });
        true
    }

    #[cfg(test)]
    fn canary_session(&self, nonce: &str) -> Option<String> {
        self.canary_claim(nonce)
            .map(|value| value.anchor.session_id)
    }

    pub(crate) fn canary_claim(&self, nonce: &str) -> Option<CanaryConsumedClaim> {
        let state = self.state.lock().ok()?;
        let value = state.canary.as_ref()?;
        (value.nonce == nonce && !value.conflicted && Instant::now() < value.deadline)
            .then(|| value.consumed.clone())
            .flatten()
    }

    pub(crate) fn end_canary(&self, nonce: &str) {
        if let Ok(mut state) = self.state.lock()
            && state
                .canary
                .as_ref()
                .is_some_and(|value| value.nonce == nonce)
        {
            state.canary = None;
        }
    }

    pub fn from_device_key_dir(path: &std::path::Path) -> Result<Self, McpBindingError> {
        DeviceKeyStore::new(path)
            .load()
            .map(Self::new)
            .map_err(|_| McpBindingError::ScopeUnresolved)
    }

    pub fn new(device_key: DeviceKey) -> Self {
        Self {
            device_key,
            state: Arc::new(Mutex::new(McpBindingState::default())),
        }
    }

    pub fn issue(&self, issue: McpBindingIssue) -> Result<McpBindingGrant, McpBindingError> {
        self.issue_with_report(issue, None)
    }

    pub fn issue_with_report(
        &self,
        issue: McpBindingIssue,
        repository_report: Option<Arc<evertrace_codex::probe::HostProbeReport>>,
    ) -> Result<McpBindingGrant, McpBindingError> {
        let anchor = BindingAnchor {
            session_id: issue.session_id,
            turn_id: issue.turn_id,
            tool_use_id: issue.tool_use_id,
            agent_id: issue.agent_id,
        };
        anchor
            .validate()
            .map_err(|_| McpBindingError::ScopeUnresolved)?;
        let original = CanonicalBindingCall {
            action: issue.action,
            workspace: issue.workspace,
            input: issue.input,
            refs: issue.refs,
        };
        let workspace = PublicWorkspace::parse(&original.workspace)
            .map_err(|_| McpBindingError::ScopeUnresolved)?;
        if issue.launcher_protocol_revision != BINDING_PROTOCOL_REVISION {
            return Err(McpBindingError::ScopeUnresolved);
        }
        let canonical_call_auth_tag = mcp_call_auth_tag(
            &original
                .canonical_bytes()
                .map_err(|_| McpBindingError::ScopeUnresolved)?,
            &self.device_key,
        )
        .map_err(|_| McpBindingError::ScopeUnresolved)?;
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| McpBindingError::ScopeUnresolved)?;
        state.clean(now);
        if state.claims.len() >= MCP_BINDING_CAPACITY {
            return Err(McpBindingError::ScopeUnresolved);
        }
        let token = RevisionId::new_v7().to_string();
        state.claims.insert(
            token.clone(),
            McpClaim {
                anchor,
                workspace,
                canonical_call_auth_tag,
                expires_at: now + MCP_CLAIM_TTL,
                repository_report,
            },
        );
        Ok(McpBindingGrant {
            bound_workspace: format!("@bound:v1:{token}"),
            expires_at_us: unix_time_us()
                .saturating_add(i64::try_from(MCP_CLAIM_TTL.as_micros()).unwrap_or(i64::MAX)),
        })
    }

    pub fn pin_client_cwd(
        &self,
        connection_id: &str,
        client_cwd: &str,
    ) -> Result<(), McpBindingError> {
        if !valid_lexical_absolute_path(client_cwd) {
            return Err(McpBindingError::ScopeUnresolved);
        }
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| McpBindingError::ScopeUnresolved)?;
        state.clean(now);
        if let Some(pinned) = state.client_cwds.get_mut(connection_id) {
            if pinned.path != client_cwd {
                return Err(McpBindingError::ScopeUnresolved);
            }
            pinned.expires_at = now + MCP_CWD_TTL;
            return Ok(());
        }
        if state.client_cwds.len() >= MCP_BINDING_CAPACITY {
            return Err(McpBindingError::ScopeUnresolved);
        }
        state.client_cwds.insert(
            connection_id.into(),
            McpPinnedCwd {
                path: client_cwd.into(),
                expires_at: now + MCP_CWD_TTL,
                inventory_host: None,
                inventory_report: None,
                inventory_session: None,
                inventory_pending: false,
                inventory_wakeup: false,
            },
        );
        Ok(())
    }

    /// Only called after the exact claim has been successfully consumed.
    pub(crate) fn observe_inventory_host(
        &self,
        connection_id: &str,
        peer: crate::repository::NativeHostPeer,
        lifetime: std::sync::Weak<()>,
        data_root: &std::path::Path,
    ) -> Option<Arc<crate::repository::NativeHostContext>> {
        let cached = self
            .state
            .lock()
            .ok()?
            .client_cwds
            .get(connection_id)?
            .inventory_host
            .clone();
        let observed = cached
            .as_ref()
            .filter(|value| value.current())
            .cloned()
            .or_else(|| {
                crate::repository::NativeHostContext::observe(peer, lifetime, data_root)
                    .map(Arc::new)
            });
        let mut state = self.state.lock().ok()?;
        let entry = state.client_cwds.get_mut(connection_id)?;
        if cached != observed {
            entry.inventory_pending = observed.is_some();
            entry.inventory_wakeup = observed.is_some();
        }
        entry.inventory_host = observed.clone();
        observed
    }

    pub(crate) fn retain_inventory_report(&self, connection: &str, scope: &McpResolvedScope) {
        if scope.mechanism != McpScopeMechanism::ExactClaim {
            return;
        }
        if let Ok(mut state) = self.state.lock()
            && let Some(entry) = state.client_cwds.get_mut(connection)
        {
            let session = scope
                .anchor
                .as_ref()
                .map(|anchor| anchor.session_id.clone());
            if entry.inventory_session != session
                || entry
                    .inventory_report
                    .as_ref()
                    .and_then(|report| report.inventory_host())
                    != scope
                        .repository_report
                        .as_ref()
                        .and_then(|report| report.inventory_host())
            {
                entry.inventory_pending = true;
                entry.inventory_wakeup = true;
            }
            entry.inventory_session = session;
            entry.inventory_report = scope
                .repository_report
                .as_ref()
                .filter(|report| report.inventory_host().is_some())
                .cloned();
        }
    }

    pub(crate) fn pending_inventory_contexts(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Vec<(
        String,
        Arc<crate::repository::NativeHostContext>,
        Arc<evertrace_codex::HostProbeReport>,
    )> {
        use std::ops::Bound::{Excluded, Unbounded};
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        let bounds = (after.map_or(Unbounded, Excluded), Unbounded);
        state
            .client_cwds
            .range::<str, _>(bounds)
            .filter(|(_, entry)| entry.inventory_pending)
            .filter_map(|(id, entry)| {
                Some((
                    id.clone(),
                    entry.inventory_host.clone()?,
                    entry.inventory_report.clone()?,
                ))
            })
            .take(limit)
            .collect()
    }

    pub(crate) fn inventory_context_admitted(&self, connection: &str) {
        if let Ok(mut state) = self.state.lock()
            && let Some(entry) = state.client_cwds.get_mut(connection)
        {
            entry.inventory_pending = false;
            entry.inventory_wakeup = false;
        }
    }

    /// A read can discover a stale finite inventory without a journal write.
    /// Consume each new request once for the existing scheduler wake channel.
    /// Repeated pages cannot re-probe an unresolved pending context, and a
    /// missing Host/report supplies no independently runnable work.
    pub fn take_inventory_wakeup(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let mut wake = false;
        for entry in state.client_cwds.values_mut() {
            wake |= std::mem::take(&mut entry.inventory_wakeup)
                && entry.inventory_pending
                && entry.inventory_host.is_some()
                && entry.inventory_report.is_some();
        }
        wake
    }

    pub(crate) fn inventory_context_stale(
        &self,
        context: &evertrace_domain::inventory::InventoryContext,
    ) {
        if let Ok(mut state) = self.state.lock() {
            for entry in state.client_cwds.values_mut() {
                if entry.inventory_host.as_ref().is_some_and(|host| {
                    host.cwd.to_str() == Some(context.cwd.as_str())
                        && host.home.to_str() == Some(context.host_home.as_str())
                        && host.config_root.to_str() == Some(context.host_config_root.as_str())
                        && host.profile == context.host_profile
                }) {
                    entry.request_inventory_rescan();
                }
            }
        }
    }

    pub(crate) fn active_inventory_contexts(
        &self,
    ) -> Vec<(
        Arc<crate::repository::NativeHostContext>,
        Arc<evertrace_codex::HostProbeReport>,
    )> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        state
            .client_cwds
            .values()
            .filter_map(|entry| {
                Some((
                    entry.inventory_host.clone()?,
                    entry.inventory_report.clone()?,
                ))
            })
            .collect()
    }

    pub(crate) fn inventory_session_ref(
        &self,
        host: &crate::repository::NativeHostContext,
    ) -> Option<String> {
        let state = self.state.lock().ok()?;
        let mut sessions = state.client_cwds.values().filter_map(|entry| {
            (entry.inventory_host.as_deref() == Some(host))
                .then_some(entry.inventory_session.as_deref())
                .flatten()
        });
        let session = sessions.next()?;
        sessions
            .all(|other| other == session)
            .then(|| format!("session:{session}"))
    }

    pub fn resolve(
        &self,
        call: &CanonicalBindingCall,
    ) -> Result<McpResolvedScope, McpBindingError> {
        let transport = TransportWorkspace::parse(&call.workspace)
            .map_err(|_| McpBindingError::ScopeUnresolved)?;
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| McpBindingError::ScopeUnresolved)?;
        state.clean(now);
        match transport {
            TransportWorkspace::BoundClaim(token) => {
                let claim = state
                    .claims
                    .remove(&token)
                    .ok_or(McpBindingError::ScopeUnresolved)?;
                if claim.expires_at <= now {
                    return Err(McpBindingError::ScopeUnresolved);
                }
                let original = CanonicalBindingCall {
                    action: call.action.clone(),
                    workspace: claim.workspace.canonical(),
                    input: call.input.clone(),
                    refs: call.refs.clone(),
                };
                let canonical = original
                    .canonical_bytes()
                    .map_err(|_| McpBindingError::ScopeUnresolved)?;
                if !verify_mcp_call_auth_tag(
                    &canonical,
                    &self.device_key,
                    &claim.canonical_call_auth_tag,
                )
                .map_err(|_| McpBindingError::ScopeUnresolved)?
                {
                    return Err(McpBindingError::ScopeUnresolved);
                }
                if let Some(observation) = state.canary.as_mut()
                    && now < observation.deadline
                    && original.action == "search"
                    && original.input == observation.nonce
                    && original.workspace == observation.workspace
                    && original.refs.is_empty()
                {
                    let issued_at = claim.expires_at - MCP_CLAIM_TTL;
                    if issued_at < observation.started_at || observation.consumed.is_some() {
                        observation.conflicted = true;
                    } else {
                        observation.consumed = Some(CanaryConsumedClaim {
                            token,
                            anchor: claim.anchor.clone(),
                            issued_at,
                            expires_at: claim.expires_at,
                            consumed_at: now,
                        });
                    }
                }
                Ok(McpResolvedScope {
                    workspace: claim.workspace,
                    anchor: Some(claim.anchor),
                    mechanism: McpScopeMechanism::ExactClaim,
                    repository_report: claim.repository_report,
                    inventory_host: None,
                })
            }
            TransportWorkspace::Public(workspace) => {
                if workspace == PublicWorkspace::Active {
                    Ok(McpResolvedScope {
                        workspace,
                        anchor: None,
                        mechanism: McpScopeMechanism::CwdOnly,
                        repository_report: None,
                        inventory_host: None,
                    })
                } else {
                    Ok(McpResolvedScope {
                        workspace,
                        anchor: None,
                        mechanism: McpScopeMechanism::Explicit,
                        repository_report: None,
                        inventory_host: None,
                    })
                }
            }
        }
    }
}

impl McpBindingState {
    fn clean(&mut self, now: Instant) {
        self.claims.retain(|_, claim| claim.expires_at > now);
        self.client_cwds.retain(|_, cwd| cwd.expires_at > now);
    }
}

fn unix_time_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(workspace: &str, input: &str) -> CanonicalBindingCall {
        CanonicalBindingCall {
            action: "search".into(),
            workspace: workspace.into(),
            input: input.into(),
            refs: vec!["atom:019c0000-0000-7000-8000-000000000001".into()],
        }
    }

    fn issue_for(call: &CanonicalBindingCall) -> McpBindingIssue {
        McpBindingIssue {
            session_id: "session-a".into(),
            turn_id: "turn-a".into(),
            tool_use_id: "tool-a".into(),
            agent_id: None,
            action: call.action.clone(),
            workspace: call.workspace.clone(),
            input: call.input.clone(),
            refs: call.refs.clone(),
            launcher_protocol_revision: BINDING_PROTOCOL_REVISION,
        }
    }

    fn new_device_key() -> DeviceKey {
        let directory =
            std::env::temp_dir().join(format!("evertrace-mcp-key-{}", RevisionId::new_v7()));
        let key = DeviceKeyStore::new(&directory).load_or_create().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        key
    }

    fn new_authority() -> McpBindingAuthority {
        McpBindingAuthority::new(new_device_key())
    }

    #[test]
    fn inventory_read_pending_reuses_wakeup_without_granting_authority() {
        let authority = new_authority();
        authority.pin_client_cwd("reader", "/workspace").unwrap();
        assert!(!authority.take_inventory_wakeup());
        // Only the scheduler notification state is exercised here. No Host
        // observation, report, claim or inventory is fabricated by this test.
        {
            let mut state = authority.state.lock().unwrap();
            let entry = state.client_cwds.get_mut("reader").unwrap();
            entry.request_inventory_rescan();
            assert!(entry.inventory_pending && entry.inventory_wakeup);
            entry.request_inventory_rescan();
            assert!(entry.inventory_wakeup);
        }
        assert!(!authority.take_inventory_wakeup());
        assert!(authority.pending_inventory_contexts(None, 1).is_empty());
        {
            let mut state = authority.state.lock().unwrap();
            let entry = state.client_cwds.get_mut("reader").unwrap();
            entry.request_inventory_rescan();
            assert!(
                !entry.inventory_wakeup,
                "the same pending read is coalesced"
            );
        }
        authority.inventory_context_admitted("reader");
        assert!(!authority.take_inventory_wakeup());
    }

    #[test]
    fn claim_is_exact_single_use_and_leaves_no_connection_authority() {
        let authority = new_authority();
        let original = call("@active", "needle");
        let grant = authority.issue(issue_for(&original)).unwrap();
        let bound = call(&grant.bound_workspace, "needle");
        let exact = authority.resolve(&bound).unwrap();
        assert_eq!(exact.mechanism, McpScopeMechanism::ExactClaim);
        assert!(authority.resolve(&bound).is_err());
        let after = authority.resolve(&call("@active", "again")).unwrap();
        assert_eq!(after.mechanism, McpScopeMechanism::CwdOnly);
        assert!(after.anchor.is_none());
        assert_eq!(
            authority
                .resolve(&call("@active", "again"))
                .unwrap()
                .mechanism,
            McpScopeMechanism::CwdOnly
        );
        let report = Arc::new(
            evertrace_codex::HostProbeReport::evaluate(
                &evertrace_codex::ProbeContext::unobserved_codex(),
                &evertrace_codex::ProbeEvidence::empty(),
            )
            .unwrap(),
        );
        let grant = authority
            .issue_with_report(issue_for(&original), Some(Arc::clone(&report)))
            .unwrap();
        let other = authority.issue(issue_for(&original)).unwrap();
        assert!(
            authority
                .resolve(&call(&other.bound_workspace, "needle"))
                .unwrap()
                .repository_report
                .is_none()
        );
        let resolved = authority
            .resolve(&call(&grant.bound_workspace, "needle"))
            .unwrap();
        assert!(Arc::ptr_eq(
            resolved.repository_report.as_ref().unwrap(),
            &report
        ));
        assert!(
            authority
                .resolve(&call(&grant.bound_workspace, "needle"))
                .is_err()
        );
        assert!(
            authority
                .resolve(&call("@active", "needle"))
                .unwrap()
                .repository_report
                .is_none()
        );
    }

    #[test]
    fn canary_observes_only_current_nonce_atomic_consume_and_rejects_cross_session() {
        let call = |workspace: &str, input: &str| {
            let mut value = call(workspace, input);
            value.refs.clear();
            value
        };
        let authority = new_authority();
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(authority.begin_canary("nonce-current", "path_hint:/tmp/canary", deadline));
        assert!(!authority.begin_canary("another", "path_hint:/tmp/canary", deadline));
        let old = call("path_hint:/tmp/canary", "nonce-old");
        let grant = authority.issue(issue_for(&old)).unwrap();
        authority
            .resolve(&call(&grant.bound_workspace, "nonce-old"))
            .unwrap();
        assert!(authority.canary_session("nonce-current").is_none());
        let current = call("path_hint:/tmp/canary", "nonce-current");
        let grant = authority.issue(issue_for(&current)).unwrap();
        assert!(authority.canary_session("nonce-current").is_none());
        let resolved = authority
            .resolve(&call(&grant.bound_workspace, "nonce-current"))
            .unwrap();
        let observed = authority.canary_claim("nonce-current").unwrap();
        assert!(observed.issued_at <= observed.consumed_at);
        assert!(observed.consumed_at < observed.expires_at);
        assert!(!observed.token.is_empty());
        assert_eq!(
            authority.canary_session("nonce-current"),
            Some(resolved.anchor.unwrap().session_id)
        );
        assert!(
            authority
                .resolve(&call(&grant.bound_workspace, "nonce-current"))
                .is_err()
        );
        let mut other = issue_for(&current);
        other.session_id = "another-session".into();
        let grant = authority.issue(other).unwrap();
        authority
            .resolve(&call(&grant.bound_workspace, "nonce-current"))
            .unwrap();
        assert!(authority.canary_session("nonce-current").is_none());
        authority.end_canary("nonce-current");
        assert!(authority.begin_canary("expired", "path_hint:/tmp/canary", Instant::now()));
        assert!(authority.canary_session("expired").is_none());
        assert!(authority.begin_canary("next", "path_hint:/tmp/canary", deadline));
        let restarted = McpBindingAuthority::new(authority.device_key.clone());
        assert!(restarted.canary_session("next").is_none());
        authority.end_canary("next");
        let early = call("path_hint:/tmp/canary", "issued-before-probe");
        let grant = authority.issue(issue_for(&early)).unwrap();
        assert!(authority.begin_canary("issued-before-probe", "path_hint:/tmp/canary", deadline,));
        authority
            .resolve(&call(&grant.bound_workspace, "issued-before-probe"))
            .unwrap();
        assert!(authority.canary_claim("issued-before-probe").is_none());
    }

    #[test]
    fn tamper_consumes_claim_and_same_key_restart_drops_state() {
        let key = new_device_key();
        let authority = McpBindingAuthority::new(key.clone());
        let original = call("@active", "needle");
        let grant = authority.issue(issue_for(&original)).unwrap();
        let tampered = call(&grant.bound_workspace, "different");
        assert!(authority.resolve(&tampered).is_err());
        assert!(
            authority
                .resolve(&call(&grant.bound_workspace, "needle"))
                .is_err()
        );

        let other = McpBindingAuthority::new(key);
        let second = authority.issue(issue_for(&original)).unwrap();
        assert!(
            other
                .resolve(&call(&second.bound_workspace, "needle"))
                .is_err()
        );
    }

    #[test]
    fn every_call_field_is_authenticated_and_matching_claim_failures_are_consumed() {
        for mutation in 0..4 {
            let authority = new_authority();
            let original = call("@active", "needle");
            let grant = authority.issue(issue_for(&original)).unwrap();
            let mut tampered = call(&grant.bound_workspace, "needle");
            match mutation {
                0 => tampered.action = "get".into(),
                1 => tampered.input = "changed".into(),
                2 => tampered.refs = vec!["atom:changed".into()],
                3 => tampered.workspace.push('x'),
                _ => unreachable!(),
            }
            assert!(authority.resolve(&tampered).is_err());
            assert!(authority.resolve(&call("@active", "next")).is_ok());
            assert!(authority.resolve(&call("@active", "next")).is_ok());
            if mutation < 3 {
                assert!(authority.state.lock().unwrap().claims.is_empty());
            }
        }
    }

    #[test]
    fn cwd_is_absolute_and_pinned_per_connection() {
        let authority = new_authority();
        assert!(authority.pin_client_cwd("a", "relative").is_err());
        authority.pin_client_cwd("a", "/workspace/one").unwrap();
        authority.pin_client_cwd("a", "/workspace/one").unwrap();
        assert!(authority.pin_client_cwd("a", "/workspace/two").is_err());
        authority.pin_client_cwd("b", "/workspace/two").unwrap();
        assert!(authority.pin_client_cwd("c", "/repo/../other").is_err());
    }

    #[test]
    fn exact_claim_never_leaks_anchor_into_later_public_workspaces() {
        let authority = new_authority();
        let original = call("@active", "needle");
        let grant = authority.issue(issue_for(&original)).unwrap();
        authority
            .resolve(&call(&grant.bound_workspace, "needle"))
            .unwrap();
        let repository = evertrace_domain::ids::RepositoryId::new_v7();
        let explicit = authority
            .resolve(&call(&repository.to_string(), "next"))
            .unwrap();
        assert_eq!(explicit.workspace, PublicWorkspace::Repository(repository));
        assert_eq!(explicit.mechanism, McpScopeMechanism::Explicit);
        assert!(explicit.anchor.is_none());
        let active = authority.resolve(&call("@active", "again")).unwrap();
        assert_eq!(active.workspace, PublicWorkspace::Active);
        assert_eq!(active.mechanism, McpScopeMechanism::CwdOnly);
        assert!(active.anchor.is_none());

        let other = authority
            .resolve(&call(&repository.to_string(), "next"))
            .unwrap();
        assert!(other.anchor.is_none());
        assert_eq!(other.mechanism, McpScopeMechanism::Explicit);
    }

    #[test]
    fn sequential_claims_are_exact_per_session_and_leave_no_residual_anchor() {
        let authority = new_authority();
        for session in ["session-a", "session-b"] {
            let original = call("@active", session);
            let mut issue = issue_for(&original);
            issue.session_id = session.into();
            let grant = authority.issue(issue).unwrap();
            let exact = authority
                .resolve(&call(&grant.bound_workspace, session))
                .unwrap();
            assert_eq!(exact.mechanism, McpScopeMechanism::ExactClaim);
            assert_eq!(exact.anchor.unwrap().session_id, session);
            let after = authority.resolve(&call("@active", "after")).unwrap();
            assert_eq!(after.mechanism, McpScopeMechanism::CwdOnly);
            assert!(after.anchor.is_none());
        }
    }

    #[test]
    fn same_cwd_concurrent_sessions_do_not_cross_scope() {
        let authority = new_authority();
        authority
            .pin_client_cwd("connection-a", "/workspace/shared")
            .unwrap();
        authority
            .pin_client_cwd("connection-b", "/workspace/shared")
            .unwrap();

        let issue = |session: &str| {
            let original = call("@active", session);
            let mut issue = issue_for(&original);
            issue.session_id = session.into();
            (original, issue)
        };
        let (call_a, issue_a) = issue("session-a");
        let (call_b, issue_b) = issue("session-b");
        let grant_a = authority.issue(issue_a).unwrap();
        let grant_b = authority.issue(issue_b).unwrap();

        let left = authority.clone();
        let right = authority.clone();
        let exact_a = std::thread::spawn(move || {
            left.resolve(&call(&grant_a.bound_workspace, &call_a.input))
        });
        let exact_b = std::thread::spawn(move || {
            right.resolve(&call(&grant_b.bound_workspace, &call_b.input))
        });
        assert_eq!(
            exact_a.join().unwrap().unwrap().anchor.unwrap().session_id,
            "session-a"
        );
        assert_eq!(
            exact_b.join().unwrap().unwrap().anchor.unwrap().session_id,
            "session-b"
        );
        let follow_up = authority.resolve(&call("@active", "follow-up")).unwrap();
        assert_eq!(follow_up.mechanism, McpScopeMechanism::CwdOnly);
        assert!(follow_up.anchor.is_none());
    }

    #[test]
    fn expired_and_concurrent_double_consume_fail_closed() {
        let authority = new_authority();
        let original = call("@active", "needle");
        let grant = authority.issue(issue_for(&original)).unwrap();
        {
            let token = grant.bound_workspace.strip_prefix("@bound:v1:").unwrap();
            authority
                .state
                .lock()
                .unwrap()
                .claims
                .get_mut(token)
                .unwrap()
                .expires_at = Instant::now();
        }
        assert!(
            authority
                .resolve(&call(&grant.bound_workspace, "needle"))
                .is_err()
        );

        let grant = authority.issue(issue_for(&original)).unwrap();
        let bound = call(&grant.bound_workspace, "needle");
        let left = authority.clone();
        let right = authority.clone();
        let first = std::thread::spawn(move || left.resolve(&bound));
        let second_call = call(&grant.bound_workspace, "needle");
        let second = std::thread::spawn(move || right.resolve(&second_call));
        assert_eq!(
            [
                first.join().unwrap().is_ok(),
                second.join().unwrap().is_ok()
            ]
            .into_iter()
            .filter(|success| *success)
            .count(),
            1
        );
    }
}
