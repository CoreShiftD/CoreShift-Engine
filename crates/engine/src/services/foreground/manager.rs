use crate::EngineError;
use crate::events::EngineEvent;
use crate::services::foreground::source::{
    ForegroundCandidate, ForegroundSource, ForegroundUnknown,
};
use crate::services::identity_cache::IdentityCacheInvalidator;
use coreshift_core::reactor::{Reactor, Token};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const EVENT_RETRY_ATTEMPTS: usize = 3;

pub struct ForegroundManager<S> {
    source: S,
    last_payload: Option<ForegroundCandidate>,
}

pub struct ForegroundPipeline<S> {
    manager: ForegroundManager<S>,
}

struct ForegroundUpdateResult {
    update: Option<ForegroundUpdate>,
    counts_as_change: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForegroundUpdate {
    Active(ForegroundCandidate),
    Unknown(ForegroundUnknown),
}

impl ForegroundUpdate {
    pub fn active(self) -> Option<ForegroundCandidate> {
        match self {
            Self::Active(candidate) => Some(candidate),
            Self::Unknown(_) => None,
        }
    }
}

impl<S: ForegroundSource> ForegroundPipeline<S> {
    pub fn new(manager: ForegroundManager<S>) -> Self {
        Self { manager }
    }

    pub fn poll_changed(
        &mut self,
        invalidator: &mut IdentityCacheInvalidator,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        Self::event_for_candidate(self.manager.poll_update()?, invalidator)
    }

    pub fn handle_fs_event_changed(
        &mut self,
        path: &Path,
        mask: u32,
        invalidator: &mut IdentityCacheInvalidator,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        Self::event_for_candidate(
            self.manager.handle_fs_event_update(path, mask)?,
            invalidator,
        )
    }

    pub fn manager(&self) -> &ForegroundManager<S> {
        &self.manager
    }

    pub fn manager_mut(&mut self) -> &mut ForegroundManager<S> {
        &mut self.manager
    }

    pub fn source_mut(&mut self) -> &mut S {
        self.manager.source_mut()
    }

    pub fn watch_hint_paths(&self) -> &[PathBuf] {
        self.manager.watch_hint_paths()
    }

    pub fn watch_hint_mask(&self, path: &Path) -> u32 {
        self.manager.watch_hint_mask(path)
    }

    pub fn register_priority_fds(
        &self,
        reactor: &mut Reactor,
        registered_paths: &BTreeSet<PathBuf>,
    ) -> Result<Vec<(Token, PathBuf)>, EngineError> {
        self.manager
            .register_priority_fds(reactor, registered_paths)
    }

    pub fn priority_hint_paths(&self) -> Vec<PathBuf> {
        self.manager.priority_hint_paths()
    }

    pub fn priority_hint_keys(&self) -> Vec<(PathBuf, u64)> {
        self.manager.priority_hint_keys()
    }

    pub fn handle_priority_event_changed(
        &mut self,
        path: &Path,
        invalidator: &mut IdentityCacheInvalidator,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        Self::event_for_candidate(
            self.manager.handle_priority_event_update(path)?,
            invalidator,
        )
    }

    pub fn handle_stale_priority_event_changed(
        &mut self,
        path: &Path,
        invalidator: &mut IdentityCacheInvalidator,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        Self::event_for_candidate(
            self.manager.handle_stale_priority_event_update(path)?,
            invalidator,
        )
    }

    pub fn unregister_priority_fd(
        &self,
        reactor: &Reactor,
        path: &Path,
    ) -> Result<bool, EngineError> {
        self.manager.unregister_priority_fd(reactor, path)
    }

    fn event_for_candidate(
        result: ForegroundUpdateResult,
        invalidator: &mut IdentityCacheInvalidator,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let Some(update) = result.update else {
            return Ok(Vec::new());
        };
        if result.counts_as_change {
            invalidator.mark_foreground_candidate();
        }
        Ok(vec![match update {
            ForegroundUpdate::Active(candidate) => {
                EngineEvent::ForegroundCandidateChanged(candidate)
            }
            ForegroundUpdate::Unknown(unknown) => EngineEvent::ForegroundUnknown(unknown),
        }])
    }
}

impl<S: ForegroundSource> ForegroundManager<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            last_payload: None,
        }
    }

    pub fn poll_current(&mut self) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.source.poll_current()
    }

    pub fn poll_changed(&mut self) -> Result<Option<ForegroundUpdate>, EngineError> {
        Ok(self.poll_update()?.update)
    }

    pub fn watch_hint_paths(&self) -> &[PathBuf] {
        self.source.watch_hint_paths()
    }

    pub fn watch_hint_mask(&self, path: &Path) -> u32 {
        self.source.watch_hint_mask(path)
    }

    pub fn register_priority_fds(
        &self,
        reactor: &mut Reactor,
        registered_paths: &BTreeSet<PathBuf>,
    ) -> Result<Vec<(Token, PathBuf)>, EngineError> {
        self.source.register_priority_fds(reactor, registered_paths)
    }

    pub fn priority_hint_paths(&self) -> Vec<PathBuf> {
        self.source.priority_hint_paths()
    }

    pub fn priority_hint_keys(&self) -> Vec<(PathBuf, u64)> {
        self.source.priority_hint_keys()
    }

    pub fn handle_fs_event(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.source.handle_fs_event(path)
    }

    pub fn handle_fs_event_changed(
        &mut self,
        path: &Path,
        mask: u32,
    ) -> Result<Option<ForegroundUpdate>, EngineError> {
        Ok(self.handle_fs_event_update(path, mask)?.update)
    }

    fn poll_update(&mut self) -> Result<ForegroundUpdateResult, EngineError> {
        let candidate = self.source.poll_current()?;
        Ok(self.filter_changed(candidate))
    }

    fn handle_fs_event_update(
        &mut self,
        path: &Path,
        mask: u32,
    ) -> Result<ForegroundUpdateResult, EngineError> {
        for attempt in 0..EVENT_RETRY_ATTEMPTS {
            if let Some(candidate) = self.source.handle_fs_event_with_mask(path, mask)? {
                return Ok(self.filter_changed(Some(candidate)));
            }
            if attempt + 1 < EVENT_RETRY_ATTEMPTS {
                std::thread::yield_now();
            }
        }
        Ok(self.filter_changed(None))
    }

    pub fn handle_priority_event_changed(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundUpdate>, EngineError> {
        Ok(self.handle_priority_event_update(path)?.update)
    }

    pub fn handle_stale_priority_event_changed(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundUpdate>, EngineError> {
        Ok(self.handle_stale_priority_event_update(path)?.update)
    }

    pub fn unregister_priority_fd(
        &self,
        reactor: &Reactor,
        path: &Path,
    ) -> Result<bool, EngineError> {
        self.source.unregister_priority_fd(reactor, path)
    }

    fn handle_priority_event_update(
        &mut self,
        path: &Path,
    ) -> Result<ForegroundUpdateResult, EngineError> {
        let candidate = self.source.handle_priority_event(path)?;
        Ok(self.filter_changed(candidate))
    }

    fn handle_stale_priority_event_update(
        &mut self,
        path: &Path,
    ) -> Result<ForegroundUpdateResult, EngineError> {
        let candidate = self.source.handle_stale_priority_event(path)?;
        Ok(self.filter_changed(candidate))
    }

    pub fn last_payload(&self) -> Option<&ForegroundCandidate> {
        self.last_payload.as_ref()
    }

    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    fn filter_changed(&mut self, candidate: Option<ForegroundCandidate>) -> ForegroundUpdateResult {
        let Some(candidate) = candidate else {
            return ForegroundUpdateResult {
                update: None,
                counts_as_change: false,
            };
        };
        if self.last_payload.as_ref().is_some_and(|last| {
            last.source == candidate.source
                && last.pid == candidate.pid
                && last.uid == candidate.uid
                && last.package == candidate.package
                && last.identity_resolved == candidate.identity_resolved
        }) {
            return ForegroundUpdateResult {
                update: None,
                counts_as_change: false,
            };
        }
        let counts_as_change = self.last_payload.is_some();
        self.last_payload = Some(candidate.clone());
        ForegroundUpdateResult {
            update: Some(ForegroundUpdate::Active(candidate)),
            counts_as_change,
        }
    }
}
