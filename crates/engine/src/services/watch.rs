use crate::EngineError;
use crate::dispatch::Dispatcher;
use crate::events::EngineEvent;
use crate::services::foreground::{ForegroundPipeline, ForegroundSource};
use crate::services::identity_cache::IdentityCacheInvalidator;
use crate::services::socket::{EngineUnixListener, EngineUnixStream};
use crate::services::{Service, SystemServices};
use crate::state::{EngineState, Reducer};
use coreshift_core::inotify::{PARENT_WATCH_MASK, add_watch, read_events, remove_watch};
use coreshift_core::reactor::{Fd, Reactor, Token};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

const IN_Q_OVERFLOW_MASK: u32 = 0x0000_4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatchTarget {
    Foreground,
    IdentityCacheHint,
}

#[derive(Debug)]
pub struct WatchRegistrationFailure {
    pub path: PathBuf,
    pub error: EngineError,
}

/// Step-based bridge from Core inotify/reactor readiness into Engine events.
pub struct EngineWatch<S> {
    reactor: Reactor,
    inotify_fd: Fd,
    foreground: ForegroundPipeline<S>,
    watches: BTreeMap<i32, (PathBuf, WatchTarget)>,
    foreground_priority_tokens: HashMap<Token, PathBuf>,
    foreground_priority_keys: BTreeMap<PathBuf, u64>,
    socket_tokens: HashSet<Token>,
    foreground_paths: BTreeSet<PathBuf>,
    foreground_priority_paths: BTreeSet<PathBuf>,
    identity_paths: BTreeSet<PathBuf>,
    registration_failures: Vec<WatchRegistrationFailure>,
}

pub struct EngineWatchPoll {
    pub events: Vec<EngineEvent>,
    pub socket_tokens: Vec<Token>,
}

impl<S: ForegroundSource> EngineWatch<S> {
    pub fn new(
        foreground: ForegroundPipeline<S>,
        invalidator: &IdentityCacheInvalidator,
    ) -> Result<Self, EngineError> {
        let mut reactor = Reactor::new()?;
        let inotify_fd = reactor.setup_inotify()?;
        let mut this = Self {
            reactor,
            inotify_fd,
            foreground,
            watches: BTreeMap::new(),
            foreground_priority_tokens: HashMap::new(),
            foreground_priority_keys: BTreeMap::new(),
            socket_tokens: HashSet::new(),
            foreground_paths: BTreeSet::new(),
            foreground_priority_paths: BTreeSet::new(),
            identity_paths: BTreeSet::new(),
            registration_failures: Vec::new(),
        };

        for path in this.foreground.watch_hint_paths().to_vec() {
            this.add_watch_path(path, WatchTarget::Foreground);
        }
        for path in invalidator.watch_hint_paths() {
            this.add_watch_path(path.clone(), WatchTarget::IdentityCacheHint);
        }
        this.sync_foreground_priority_fds()?;

        Ok(this)
    }

    pub fn poll_once<F>(
        &mut self,
        timeout_ms: i32,
        invalidator: &mut IdentityCacheInvalidator,
        services: &mut SystemServices,
        state: &mut EngineState,
        refresh_identity_cache: F,
    ) -> Result<Vec<EngineEvent>, EngineError>
    where
        F: FnMut(),
    {
        Ok(self
            .poll_once_with_socket_events(
                timeout_ms,
                invalidator,
                services,
                state,
                refresh_identity_cache,
            )?
            .events)
    }

    pub fn poll_once_with_socket_events<F>(
        &mut self,
        timeout_ms: i32,
        invalidator: &mut IdentityCacheInvalidator,
        services: &mut SystemServices,
        state: &mut EngineState,
        mut refresh_identity_cache: F,
    ) -> Result<EngineWatchPoll, EngineError>
    where
        F: FnMut(),
    {
        let mut ready = Vec::new();
        let count = self.reactor.wait(&mut ready, 16, timeout_ms)?;
        if count == 0 {
            return Ok(EngineWatchPoll {
                events: Vec::new(),
                socket_tokens: Vec::new(),
            });
        }

        let mut emitted = Vec::new();
        let mut socket_tokens = Vec::new();
        let mut refreshed_identity_cache = false;
        for event in ready {
            if self.socket_tokens.contains(&event.token) {
                socket_tokens.push(event.token);
                continue;
            }
            if let Some(path) = self.foreground_priority_tokens.get(&event.token).cloned() {
                if event.error {
                    let events = self
                        .foreground
                        .handle_stale_priority_event_changed(&path, invalidator)?;
                    self.apply_events(events, services, state, &mut emitted)?;
                    self.sync_foreground_priority_fds()?;
                } else if event.priority {
                    let events = self
                        .foreground
                        .handle_priority_event_changed(&path, invalidator)?;
                    self.apply_events(events, services, state, &mut emitted)?;
                    self.sync_foreground_priority_fds()?;
                }
                continue;
            }

            if Some(event.token) != self.reactor.inotify_token || !event.readable {
                continue;
            }
            for inotify_event in read_events(&self.inotify_fd)? {
                if inotify_event.mask & IN_Q_OVERFLOW_MASK != 0 {
                    let events = self.foreground.handle_fs_event_changed(
                        Path::new(""),
                        inotify_event.mask,
                        invalidator,
                    )?;
                    self.apply_events(events, services, state, &mut emitted)?;
                    self.sync_foreground_watch_paths();
                    self.sync_foreground_priority_fds()?;
                    continue;
                }
                let Some((path, target)) = self.watches.get(&inotify_event.wd).cloned() else {
                    continue;
                };
                let path = named_event_path(path, inotify_event.name.as_deref());
                match target {
                    WatchTarget::Foreground => {
                        let events = self.foreground.handle_fs_event_changed(
                            &path,
                            inotify_event.mask,
                            invalidator,
                        )?;
                        self.apply_events(events, services, state, &mut emitted)?;
                        self.sync_foreground_watch_paths();
                        self.sync_foreground_priority_fds()?;
                    }
                    WatchTarget::IdentityCacheHint => {
                        invalidator.mark_event(&path);
                        if invalidator.should_refresh_now() && !refreshed_identity_cache {
                            refresh_identity_cache();
                            refreshed_identity_cache = true;
                        }
                    }
                }
            }
        }

        Ok(EngineWatchPoll {
            events: emitted,
            socket_tokens,
        })
    }

    pub fn register_socket_listener(
        &mut self,
        listener: &EngineUnixListener,
    ) -> Result<Token, EngineError> {
        let token = listener.register_readable(&mut self.reactor)?;
        self.socket_tokens.insert(token);
        Ok(token)
    }

    pub fn register_socket_stream(
        &mut self,
        stream: &EngineUnixStream,
    ) -> Result<Token, EngineError> {
        let token = stream.register_readable(&mut self.reactor)?;
        self.socket_tokens.insert(token);
        Ok(token)
    }

    pub fn unregister_socket_stream(
        &mut self,
        token: Token,
        stream: &EngineUnixStream,
    ) -> Result<bool, EngineError> {
        let removed = self.socket_tokens.remove(&token);
        if removed {
            stream.unregister_readable(&self.reactor)?;
        }
        Ok(removed)
    }

    pub fn socket_token_count(&self) -> usize {
        self.socket_tokens.len()
    }

    pub fn foreground_priority_token_count(&self) -> usize {
        self.foreground_priority_tokens.len()
    }

    pub fn foreground_priority_registration_keys(&self) -> &BTreeMap<PathBuf, u64> {
        &self.foreground_priority_keys
    }

    pub fn foreground_source_mut(&mut self) -> &mut S {
        self.foreground.source_mut()
    }

    pub fn poll_current_foreground(
        &mut self,
    ) -> Result<Option<crate::services::foreground::ForegroundCandidate>, EngineError> {
        let candidate = self.foreground.manager_mut().poll_current()?;
        self.sync_foreground_watch_paths();
        self.sync_foreground_priority_fds()?;
        Ok(candidate)
    }

    pub fn foreground_watch_paths(&self) -> &BTreeSet<PathBuf> {
        &self.foreground_paths
    }

    pub fn foreground_priority_paths(&self) -> &BTreeSet<PathBuf> {
        &self.foreground_priority_paths
    }

    pub fn identity_watch_paths(&self) -> &BTreeSet<PathBuf> {
        &self.identity_paths
    }

    pub fn registration_failures(&self) -> &[WatchRegistrationFailure] {
        &self.registration_failures
    }

    fn add_watch_path(&mut self, path: PathBuf, target: WatchTarget) {
        match target {
            WatchTarget::Foreground if self.foreground_paths.contains(&path) => return,
            WatchTarget::IdentityCacheHint if self.identity_paths.contains(&path) => return,
            _ => {}
        }

        let Some(path_str) = path.to_str() else {
            self.registration_failures.push(WatchRegistrationFailure {
                path,
                error: EngineError::invalid_config("watch.path", "must be UTF-8"),
            });
            return;
        };
        let mask = match target {
            WatchTarget::Foreground => self.foreground.watch_hint_mask(&path),
            WatchTarget::IdentityCacheHint => PARENT_WATCH_MASK,
        };
        let wd = match add_watch(&self.inotify_fd, path_str, mask) {
            Ok(wd) => wd,
            Err(error) => {
                self.registration_failures.push(WatchRegistrationFailure {
                    path,
                    error: error.into(),
                });
                return;
            }
        };
        match target {
            WatchTarget::Foreground => {
                self.foreground_paths.insert(path.clone());
            }
            WatchTarget::IdentityCacheHint => {
                self.identity_paths.insert(path.clone());
            }
        }
        self.watches.insert(wd, (path, target));
    }

    fn sync_foreground_watch_paths(&mut self) {
        let desired = self
            .foreground
            .watch_hint_paths()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for path in self
            .foreground_paths
            .difference(&desired)
            .cloned()
            .collect::<Vec<_>>()
        {
            self.remove_watch_path(&path, WatchTarget::Foreground);
        }
        for path in desired {
            self.add_watch_path(path, WatchTarget::Foreground);
        }
    }

    fn sync_foreground_priority_fds(&mut self) -> Result<(), EngineError> {
        let current = self
            .foreground
            .priority_hint_keys()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let previous = self.foreground_priority_keys.clone();
        for path in previous
            .keys()
            .filter(|path| !current.contains_key(*path))
            .cloned()
            .collect::<Vec<_>>()
        {
            let _ = self
                .foreground
                .unregister_priority_fd(&self.reactor, &path)?;
            self.drop_priority_path(&path);
        }
        for path in previous
            .iter()
            .filter_map(|(path, key)| (current.get(path) != Some(key)).then_some(path.clone()))
            .collect::<Vec<_>>()
        {
            self.drop_priority_path(&path);
        }

        for (token, path) in self
            .foreground
            .register_priority_fds(&mut self.reactor, &self.foreground_priority_paths)?
        {
            self.foreground_priority_paths.insert(path.clone());
            if let Some(key) = current.get(&path).copied() {
                self.foreground_priority_keys.insert(path.clone(), key);
            }
            self.foreground_priority_tokens.insert(token, path);
        }
        Ok(())
    }

    fn remove_watch_path(&mut self, path: &Path, target: WatchTarget) {
        let removed = self
            .watches
            .iter()
            .filter_map(|(wd, (watch_path, watch_target))| {
                (*watch_target == target && watch_path == path).then_some(*wd)
            })
            .collect::<Vec<_>>();
        for wd in removed {
            if let Err(error) = remove_watch(&self.inotify_fd, wd) {
                if error.raw_os_error() != Some(22) {
                    self.registration_failures.push(WatchRegistrationFailure {
                        path: path.to_path_buf(),
                        error: error.into(),
                    });
                }
            }
            self.watches.remove(&wd);
        }
        match target {
            WatchTarget::Foreground => {
                self.foreground_paths.remove(path);
            }
            WatchTarget::IdentityCacheHint => {
                self.identity_paths.remove(path);
            }
        }
    }

    fn drop_priority_path(&mut self, path: &Path) {
        self.foreground_priority_paths.remove(path);
        self.foreground_priority_keys.remove(path);
        self.foreground_priority_tokens
            .retain(|_, registered_path| registered_path != path);
    }

    fn apply_events(
        &self,
        events: Vec<EngineEvent>,
        services: &mut SystemServices,
        state: &mut EngineState,
        emitted: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        for event in events {
            Reducer::apply(&event, state);
            emitted.push(event);
            let actions = Dispatcher::dispatch(emitted.last().expect("event just pushed"));
            for action in actions {
                for service_event in services.perform(action)? {
                    Reducer::apply(&service_event, state);
                    emitted.push(service_event);
                }
            }
        }
        Ok(())
    }
}

fn named_event_path(path: PathBuf, name: Option<&[u8]>) -> PathBuf {
    let Some(name) = name else {
        return path;
    };
    match std::str::from_utf8(name) {
        Ok("") | Err(_) => path,
        Ok(name) => path.join(Path::new(name)),
    }
}

#[cfg(test)]
mod tests {
    use super::named_event_path;
    use std::path::PathBuf;

    #[test]
    fn non_utf8_inotify_name_returns_parent_path() {
        let parent = PathBuf::from("/tmp/parent");
        let path = named_event_path(parent.clone(), Some(&[0xff, 0xfe]));

        assert_eq!(path, parent);
    }
}
