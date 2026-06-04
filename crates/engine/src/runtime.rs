use crate::EngineError;
use crate::config::{EngineConfig, IdentityCacheProviderMode};
use crate::events::EngineEvent;
use crate::exec::ExecRunner;
use crate::services::SystemServices;
use crate::services::foreground::{
    CmdPackageListProvider, PackageProviderSource, PackageUidProvider, UidPackageCache,
};
use crate::services::identity_cache::{IdentityCacheDirtyState, IdentityCacheInvalidator};
use crate::services::watch::EngineWatch;
use crate::state::{EngineState, Reducer};
use std::path::Path;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityCacheWarmupState {
    pub source: Option<PackageProviderSource>,
    pub coherent: bool,
    pub count: usize,
    pub last_cache_error: Option<String>,
}

/// Runtime coordinator over CoreShift Core primitives.
pub struct EngineRuntime {
    config: EngineConfig,
    started: bool,
    identity_cache: UidPackageCache,
    identity_cache_state: IdentityCacheWarmupState,
    identity_cache_invalidator: IdentityCacheInvalidator,
}

impl EngineRuntime {
    pub fn new(config: EngineConfig) -> Self {
        let identity_cache_invalidator =
            IdentityCacheInvalidator::new(config.identity_cache_invalidation.clone());
        Self {
            config,
            started: false,
            identity_cache: UidPackageCache::default(),
            identity_cache_state: IdentityCacheWarmupState::default(),
            identity_cache_invalidator,
        }
    }

    /// Start runtime-owned in-process state.
    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.started {
            return Err(EngineError::AlreadyStarted);
        }
        self.config.validate()?;
        self.refresh_identity_cache();
        self.started = true;
        Ok(())
    }

    pub fn step<S>(
        &mut self,
        watcher: &mut EngineWatch<S>,
        state: &mut EngineState,
        timeout_ms: i32,
    ) -> Result<Vec<EngineEvent>, EngineError>
    where
        S: crate::services::foreground::ForegroundSource,
    {
        if !self.started {
            return Err(EngineError::NotStarted);
        }

        let mut emitted = Vec::new();
        let mut services = self.system_services();
        let mut refresh_requested = false;
        let watch_events = watcher.poll_once(
            timeout_ms,
            &mut self.identity_cache_invalidator,
            &mut services,
            state,
            || {
                refresh_requested = true;
            },
        )?;
        emitted.extend(watch_events);
        if refresh_requested {
            self.refresh_identity_cache();
            self.apply_identity_cache_state(state, &mut emitted);
        }
        Ok(emitted)
    }

    pub fn refresh_identity_cache(&mut self) {
        match self.load_identity_cache() {
            Ok((cache, state)) => {
                let _ = self.identity_cache_invalidator.consume_dirty();
                self.identity_cache = cache;
                self.identity_cache_state = state;
            }
            Err(err) => {
                self.identity_cache = UidPackageCache::default();
                self.identity_cache_state = IdentityCacheWarmupState {
                    source: None,
                    coherent: false,
                    count: 0,
                    last_cache_error: Some(err.to_string()),
                };
            }
        }
    }

    fn apply_identity_cache_state(&self, state: &mut EngineState, emitted: &mut Vec<EngineEvent>) {
        let event = if let Some(source) = self.identity_cache_state.source {
            EngineEvent::IdentityCacheWarmed {
                source,
                coherent: self.identity_cache_state.coherent,
                count: self.identity_cache_state.count,
            }
        } else if let Some(error) = &self.identity_cache_state.last_cache_error {
            EngineEvent::IdentityCacheWarmupFailed {
                error: error.clone(),
            }
        } else {
            return;
        };
        Reducer::apply(&event, state);
        emitted.push(event);
    }

    fn load_identity_cache(
        &self,
    ) -> Result<(UidPackageCache, IdentityCacheWarmupState), EngineError> {
        match self.config.identity_cache.provider_mode {
            IdentityCacheProviderMode::Disabled => Ok((
                UidPackageCache::default(),
                IdentityCacheWarmupState::default(),
            )),
            IdentityCacheProviderMode::CmdPackageList => {
                let cmd = CmdPackageListProvider::new(
                    self.exec_runner(),
                    self.config.identity_cache.cmd_path.clone(),
                    self.config.identity_cache.user_id,
                );
                let snapshot = cmd.load()?;
                let count = snapshot.entries.len();
                let state = IdentityCacheWarmupState {
                    source: Some(snapshot.source),
                    coherent: snapshot.coherent,
                    count,
                    last_cache_error: None,
                };
                let mut cache = UidPackageCache::default();
                cache.update_from_snapshot(snapshot)?;
                Ok((cache, state))
            }
        }
    }

    /// Drop runtime-owned resources.
    pub fn shutdown(&mut self) {
        self.started = false;
    }

    pub fn exec_runner(&self) -> ExecRunner {
        ExecRunner::new(self.config.exec.clone())
    }

    pub fn system_services(&self) -> SystemServices {
        let services = SystemServices::new(self.exec_runner());
        if self.identity_cache_state.source.is_some() {
            services.with_uid_package_cache(self.identity_cache.clone())
        } else {
            services
        }
    }

    pub fn identity_cache(&self) -> &UidPackageCache {
        &self.identity_cache
    }

    pub fn identity_cache_state(&self) -> &IdentityCacheWarmupState {
        &self.identity_cache_state
    }

    pub fn identity_cache_invalidator(&self) -> &IdentityCacheInvalidator {
        &self.identity_cache_invalidator
    }

    pub fn mark_identity_cache_foreground_candidate(&mut self) {
        self.identity_cache_invalidator.mark_foreground_candidate();
    }

    pub fn mark_identity_cache_event(&mut self, path: &Path) {
        self.identity_cache_invalidator.mark_event(path);
    }

    pub fn should_refresh_identity_cache_now(&self) -> bool {
        self.identity_cache_invalidator.should_refresh_now()
    }

    pub fn consume_identity_cache_dirty(&mut self) -> IdentityCacheDirtyState {
        self.identity_cache_invalidator.consume_dirty()
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }
}
