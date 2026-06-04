use crate::events::EngineEvent;
use crate::services::foreground::PackageProviderSource;
use crate::services::identity::ResolvedIdentity;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityCacheState {
    pub source: Option<PackageProviderSource>,
    pub coherent: bool,
    pub count: usize,
    pub last_cache_error: Option<String>,
}

/// Minimal state tracked by the Engine reducer.
#[derive(Debug, Default)]
pub struct EngineState {
    pub started: bool,
    pub completed_jobs: u64,
    pub last_identity: Option<ResolvedIdentity>,
    pub identity_cache: IdentityCacheState,
    pub last_error: Option<String>,
}

/// Pure Engine reducer.
#[derive(Debug, Default)]
pub struct Reducer;

impl Reducer {
    pub fn apply(event: &EngineEvent, state: &mut EngineState) {
        match event {
            EngineEvent::RuntimeStarted => {
                state.started = true;
                state.last_error = None;
            }
            EngineEvent::RuntimeStopped => {
                state.started = false;
            }
            EngineEvent::ExecCompleted { .. } => {
                state.completed_jobs = state.completed_jobs.saturating_add(1);
            }
            EngineEvent::ForegroundCandidateChanged(_) => {}
            EngineEvent::ForegroundUnknown(_) => {
                state.last_identity = None;
            }
            EngineEvent::IdentityResolved(identity) => {
                state.last_identity = Some(identity.clone());
            }
            EngineEvent::IdentityCacheWarmed {
                source,
                coherent,
                count,
            } => {
                state.identity_cache = IdentityCacheState {
                    source: Some(*source),
                    coherent: *coherent,
                    count: *count,
                    last_cache_error: None,
                };
            }
            EngineEvent::IdentityCacheWarmupFailed { error } => {
                state.identity_cache = IdentityCacheState {
                    source: None,
                    coherent: false,
                    count: 0,
                    last_cache_error: Some(error.clone()),
                };
            }
            EngineEvent::ServiceFailed { error } => {
                state.last_error = Some(error.to_string());
            }
        }
    }
}
