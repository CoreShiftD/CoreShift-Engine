use super::{ForegroundCandidate, ForegroundSource, ForegroundSourceKind};
use crate::EngineError;
use coreshift_core::reactor::{Reactor, Token};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub struct AutoForegroundSource<V1, V2, A> {
    v1: V1,
    v2: V2,
    activity: A,
    watch_hint_paths: Vec<PathBuf>,
    v1_available: bool,
}

impl<V1, V2, A> AutoForegroundSource<V1, V2, A>
where
    V1: ForegroundSource,
    V2: ForegroundSource,
    A: FnMut() -> Result<Option<ForegroundCandidate>, EngineError>,
{
    pub fn new(v1: V1, v2: V2, activity: A) -> Self {
        let v1_available = v1.is_available();
        let mut this = Self {
            v1,
            v2,
            activity,
            watch_hint_paths: Vec::new(),
            v1_available,
        };
        this.refresh_watch_hint_paths();
        this
    }
}

impl<V1, V2, A> ForegroundSource for AutoForegroundSource<V1, V2, A>
where
    V1: ForegroundSource,
    V2: ForegroundSource,
    A: FnMut() -> Result<Option<ForegroundCandidate>, EngineError>,
{
    fn kind(&self) -> ForegroundSourceKind {
        ForegroundSourceKind::Auto
    }

    fn poll_current(&mut self) -> Result<Option<ForegroundCandidate>, EngineError> {
        match self.v1.poll_current() {
            Ok(candidate) => {
                self.set_v1_available(true);
                return Ok(candidate);
            }
            Err(_) => self.set_v1_available(false),
        }
        match self.v2.poll_current() {
            Ok(candidate) => Ok(candidate),
            Err(_) => (self.activity)(),
        }
    }

    fn handle_fs_event(&mut self, path: &Path) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.handle_fs_event_with_mask(path, 0)
    }

    fn handle_fs_event_with_mask(
        &mut self,
        path: &Path,
        mask: u32,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        if self.v1.watch_hint_paths().iter().any(|hint| hint == path) {
            return match self.v1.handle_fs_event_with_mask(path, mask) {
                Ok(candidate) => {
                    self.set_v1_available(true);
                    Ok(candidate)
                }
                Err(_) => self.poll_without_v1(),
            };
        }
        if self
            .v2
            .watch_hint_paths()
            .iter()
            .any(|hint| hint == path || path.parent() == Some(hint.as_path()))
        {
            if let Some(candidate) = self.recover_v1_if_available()? {
                return Ok(candidate);
            }
            return match self.v2.handle_fs_event_with_mask(path, mask) {
                Ok(candidate) => Ok(candidate),
                Err(_) => (self.activity)(),
            };
        }
        self.poll_current()
    }

    fn watch_hint_paths(&self) -> &[PathBuf] {
        &self.watch_hint_paths
    }

    fn is_available(&self) -> bool {
        self.v1_available || self.v2.is_available()
    }

    fn watch_hint_mask(&self, path: &Path) -> u32 {
        if self.v1.watch_hint_paths().iter().any(|hint| hint == path) {
            return self.v1.watch_hint_mask(path);
        }
        self.v2.watch_hint_mask(path)
    }

    fn register_priority_fds(
        &self,
        reactor: &mut Reactor,
        registered_paths: &BTreeSet<PathBuf>,
    ) -> Result<Vec<(Token, PathBuf)>, EngineError> {
        if self.v1_available {
            return Ok(Vec::new());
        }
        self.v2.register_priority_fds(reactor, registered_paths)
    }

    fn priority_hint_paths(&self) -> Vec<PathBuf> {
        if self.v1_available {
            return Vec::new();
        }
        self.v2.priority_hint_paths()
    }

    fn priority_hint_keys(&self) -> Vec<(PathBuf, u64)> {
        if self.v1_available {
            return Vec::new();
        }
        self.v2.priority_hint_keys()
    }

    fn handle_priority_event(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        if let Some(candidate) = self.recover_v1_if_available()? {
            return Ok(candidate);
        }
        match self.v2.handle_priority_event(path) {
            Ok(candidate) => Ok(candidate),
            Err(_) => (self.activity)(),
        }
    }

    fn handle_stale_priority_event(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        if let Some(candidate) = self.recover_v1_if_available()? {
            return Ok(candidate);
        }
        match self.v2.handle_stale_priority_event(path) {
            Ok(candidate) => Ok(candidate),
            Err(_) => (self.activity)(),
        }
    }

    fn unregister_priority_fd(&self, reactor: &Reactor, path: &Path) -> Result<bool, EngineError> {
        self.v2.unregister_priority_fd(reactor, path)
    }
}

impl<V1, V2, A> AutoForegroundSource<V1, V2, A>
where
    V1: ForegroundSource,
    V2: ForegroundSource,
    A: FnMut() -> Result<Option<ForegroundCandidate>, EngineError>,
{
    fn poll_without_v1(&mut self) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.set_v1_available(false);
        match self.v2.poll_current() {
            Ok(candidate) => Ok(candidate),
            Err(_) => (self.activity)(),
        }
    }

    fn recover_v1_if_available(
        &mut self,
    ) -> Result<Option<Option<ForegroundCandidate>>, EngineError> {
        if self.v1_available {
            return Ok(Some(None));
        }
        match self.v1.poll_current() {
            Ok(candidate) => {
                self.set_v1_available(true);
                Ok(Some(candidate))
            }
            Err(_) => Ok(None),
        }
    }

    fn set_v1_available(&mut self, available: bool) {
        if self.v1_available == available {
            return;
        }
        self.v1_available = available;
        self.refresh_watch_hint_paths();
    }

    fn refresh_watch_hint_paths(&mut self) {
        self.watch_hint_paths = self.v1.watch_hint_paths().to_vec();
        if self.v1_available {
            return;
        }
        for path in self.v2.watch_hint_paths() {
            if !self.watch_hint_paths.contains(path) {
                self.watch_hint_paths.push(path.clone());
            }
        }
    }
}
