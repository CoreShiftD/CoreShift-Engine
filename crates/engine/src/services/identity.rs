use crate::services::foreground::{UidPackageCache, UidPackageState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedIdentityState {
    Exact,
    Missing,
    Ambiguous,
    Unresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedIdentitySource {
    CacheOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedIdentity {
    pub pid: Option<i32>,
    pub uid: Option<u32>,
    pub package: Option<String>,
    pub state: ResolvedIdentityState,
    pub source: ResolvedIdentitySource,
}

#[derive(Clone, Debug, Default)]
pub struct IdentityService {
    package_cache: Option<UidPackageCache>,
}

impl IdentityService {
    pub fn new(package_cache: Option<UidPackageCache>) -> Self {
        Self { package_cache }
    }

    pub fn resolve(&self, pid: Option<i32>, uid: Option<u32>) -> Option<ResolvedIdentity> {
        let Some(uid) = uid else {
            // No pid-to-uid source is wired yet; empty actions have no identity key.
            return pid.map(|pid| ResolvedIdentity {
                pid: Some(pid),
                uid: None,
                package: None,
                state: ResolvedIdentityState::Unresolved,
                source: ResolvedIdentitySource::CacheOnly,
            });
        };

        let (package, state) = match &self.package_cache {
            Some(cache) => match cache.uid_state(uid) {
                UidPackageState::Exact(package) => (Some(package), ResolvedIdentityState::Exact),
                UidPackageState::Missing => (None, ResolvedIdentityState::Missing),
                UidPackageState::Ambiguous(_) => (None, ResolvedIdentityState::Ambiguous),
            },
            None => (None, ResolvedIdentityState::Unresolved),
        };

        Some(ResolvedIdentity {
            pid,
            uid: Some(uid),
            package,
            state,
            source: ResolvedIdentitySource::CacheOnly,
        })
    }
}
