use crate::EngineError;
use crate::services::foreground::cache::{UidPackageCache, UidPackageState};
pub use coreshift_core::reactor::{Reactor, Token};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForegroundSourceKind {
    CgroupV1,
    CgroupV2,
    ActivityManager,
    Auto,
    Cleared,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForegroundCandidate {
    pub source: ForegroundSourceKind,
    pub pid: Option<i32>,
    pub uid: Option<u32>,
    pub package: Option<String>,
    pub identity_resolved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForegroundUnknown {
    pub source: ForegroundSourceKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UidRemainderFilter {
    pub modulus: u32,
    pub min_remainder: u32,
}

impl UidRemainderFilter {
    pub fn accepts(&self, uid: u32) -> bool {
        self.modulus != 0 && uid % self.modulus >= self.min_remainder
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForegroundCandidateFilter {
    pub blocked_uids: BTreeSet<u32>,
    pub accessibility_uids: BTreeSet<u32>,
    pub blocked_packages: BTreeSet<String>,
    pub allow_system_uids: bool,
    pub uid_remainder_filter: Option<UidRemainderFilter>,
}

impl ForegroundCandidateFilter {
    pub fn is_valid_uid(&self, uid: u32) -> bool {
        if self.blocked_uids.contains(&uid) {
            return false;
        }
        if self.accessibility_uids.contains(&uid) {
            return false;
        }
        if let Some(filter) = self.uid_remainder_filter {
            if !filter.accepts(uid) {
                return false;
            }
        }
        self.allow_system_uids || uid >= 10_000
    }

    pub fn candidate_for_uid(
        &self,
        source: ForegroundSourceKind,
        pid: Option<i32>,
        uid: u32,
        cache: Option<&UidPackageCache>,
    ) -> Option<ForegroundCandidate> {
        if !self.is_valid_uid(uid) {
            return None;
        }

        let mut candidate = ForegroundCandidate {
            source,
            pid,
            uid: Some(uid),
            package: None,
            identity_resolved: false,
        };

        let Some(cache) = cache else {
            return Some(candidate);
        };

        match cache.uid_state(uid) {
            UidPackageState::Exact(package) => {
                if self.blocked_packages.contains(&package) {
                    None
                } else {
                    candidate.package = Some(package);
                    candidate.identity_resolved = true;
                    Some(candidate)
                }
            }
            UidPackageState::Ambiguous(_) => None,
            UidPackageState::Missing => Some(candidate),
        }
    }
}

pub trait ForegroundSource {
    fn kind(&self) -> ForegroundSourceKind;
    fn poll_current(&mut self) -> Result<Option<ForegroundCandidate>, EngineError>;
    fn handle_fs_event(&mut self, path: &Path) -> Result<Option<ForegroundCandidate>, EngineError>;
    fn handle_fs_event_with_mask(
        &mut self,
        path: &Path,
        _mask: u32,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.handle_fs_event(path)
    }
    fn watch_hint_paths(&self) -> &[PathBuf];

    fn is_available(&self) -> bool {
        true
    }

    fn watch_hint_mask(&self, _path: &Path) -> u32 {
        IN_MODIFY_MASK | IN_CREATE_MASK | IN_DELETE_MASK | IN_MOVED_FROM_MASK | IN_MOVED_TO_MASK
    }

    fn register_priority_fds(
        &self,
        _reactor: &mut Reactor,
        _registered_paths: &BTreeSet<PathBuf>,
    ) -> Result<Vec<(Token, PathBuf)>, EngineError> {
        Ok(Vec::new())
    }

    fn priority_hint_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    fn priority_hint_keys(&self) -> Vec<(PathBuf, u64)> {
        self.priority_hint_paths()
            .into_iter()
            .map(|path| (path, 0))
            .collect()
    }

    fn handle_priority_event(
        &mut self,
        _path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        Ok(None)
    }

    fn handle_stale_priority_event(
        &mut self,
        _path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        Ok(None)
    }

    fn unregister_priority_fd(
        &self,
        _reactor: &Reactor,
        _path: &Path,
    ) -> Result<bool, EngineError> {
        Ok(false)
    }
}
const IN_MODIFY_MASK: u32 = 0x0000_0002;
const IN_CREATE_MASK: u32 = 0x0000_0100;
const IN_DELETE_MASK: u32 = 0x0000_0200;
const IN_MOVED_FROM_MASK: u32 = 0x0000_0040;
const IN_MOVED_TO_MASK: u32 = 0x0000_0080;
