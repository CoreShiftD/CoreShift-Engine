use super::V1PayloadCache;
use super::source::{
    ForegroundCandidate, ForegroundCandidateFilter, ForegroundSource, ForegroundSourceKind,
};
use crate::EngineError;
use crate::services::foreground::cache::{UidPackageCache, UidPackageState};
use coreshift_core::proc::read_proc_cmdline_at;
use coreshift_core::uid::proc_stat_at;
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

pub trait PidUidResolver {
    fn uid_for_pid(&mut self, proc_root: &Path, pid: i32) -> Result<Option<u32>, EngineError>;
}

#[derive(Clone, Debug, Default)]
pub struct ProcfsPidUidResolver;

impl PidUidResolver for ProcfsPidUidResolver {
    fn uid_for_pid(&mut self, proc_root: &Path, pid: i32) -> Result<Option<u32>, EngineError> {
        match proc_stat_at(proc_root, pid) {
            Ok(stat) => Ok(Some(stat.uid)),
            Err(_) => Ok(None),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MapPidUidResolver {
    uids: BTreeMap<i32, u32>,
}

impl MapPidUidResolver {
    pub fn new(uids: BTreeMap<i32, u32>) -> Self {
        Self { uids }
    }
}

impl PidUidResolver for MapPidUidResolver {
    fn uid_for_pid(&mut self, _proc_root: &Path, pid: i32) -> Result<Option<u32>, EngineError> {
        Ok(self.uids.get(&pid).copied())
    }
}

#[derive(Clone, Debug)]
pub struct CgroupV1CpusetSource<R = ProcfsPidUidResolver> {
    cgroup_procs_path: PathBuf,
    proc_root: PathBuf,
    pub filter: ForegroundCandidateFilter,
    watch_hint_paths: Vec<PathBuf>,
    resolver: R,
    package_cache: Option<UidPackageCache>,
    payload_cache: V1PayloadCache,
    last_candidate: Option<ForegroundCandidate>,
}

impl CgroupV1CpusetSource<ProcfsPidUidResolver> {
    pub fn new(
        cgroup_procs_path: PathBuf,
        proc_root: PathBuf,
        filter: ForegroundCandidateFilter,
    ) -> Self {
        Self::with_resolver(cgroup_procs_path, proc_root, filter, ProcfsPidUidResolver)
    }
}

impl<R> CgroupV1CpusetSource<R> {
    pub fn with_resolver(
        cgroup_procs_path: PathBuf,
        proc_root: PathBuf,
        filter: ForegroundCandidateFilter,
        resolver: R,
    ) -> Self {
        let watch_hint_paths = vec![cgroup_procs_path.clone()];
        Self {
            cgroup_procs_path,
            proc_root,
            filter,
            watch_hint_paths,
            resolver,
            package_cache: None,
            payload_cache: V1PayloadCache::default(),
            last_candidate: None,
        }
    }

    pub fn cgroup_procs_path(&self) -> &Path {
        &self.cgroup_procs_path
    }

    pub fn with_package_cache(mut self, package_cache: UidPackageCache) -> Self {
        self.package_cache = Some(package_cache);
        self
    }

    pub fn set_package_cache(&mut self, package_cache: UidPackageCache) {
        self.package_cache = Some(package_cache);
    }

    pub fn set_filter(&mut self, filter: ForegroundCandidateFilter) {
        self.filter = filter;
    }

    pub fn block_uid(&mut self, uid: u32) {
        self.filter.blocked_uids.insert(uid);
    }
}

impl<R: PidUidResolver> ForegroundSource for CgroupV1CpusetSource<R> {
    fn kind(&self) -> ForegroundSourceKind {
        ForegroundSourceKind::CgroupV1
    }

    fn poll_current(&mut self) -> Result<Option<ForegroundCandidate>, EngineError> {
        let payload = self.payload_cache.read_initial(&self.cgroup_procs_path)?;
        self.resolve_payload(&payload)
    }

    fn handle_fs_event(&mut self, path: &Path) -> Result<Option<ForegroundCandidate>, EngineError> {
        if path != self.cgroup_procs_path {
            return Ok(None);
        }
        let payload = match self.payload_cache.read_changed(&self.cgroup_procs_path)? {
            Some(payload) => payload,
            None => self
                .payload_cache
                .last()
                .map(Vec::from)
                .unwrap_or_else(|| Vec::new()),
        };
        self.resolve_payload(&payload)
    }

    fn watch_hint_paths(&self) -> &[PathBuf] {
        &self.watch_hint_paths
    }

    fn is_available(&self) -> bool {
        std::fs::File::open(&self.cgroup_procs_path).is_ok()
    }
}

impl<R: PidUidResolver> CgroupV1CpusetSource<R> {
    fn resolve_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        let content = String::from_utf8_lossy(payload);
        let mut best: Option<(i32, ForegroundCandidate, bool)> = None;

        for line in content.lines().rev() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let pid = line
                .parse::<i32>()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid cgroup.procs pid list"))?;
            
            if pid < 100 {
                continue;
            }

            let Some(uid) = self.resolver.uid_for_pid(&self.proc_root, pid)? else {
                continue;
            };

            let (candidate, is_ui) = if let Some(res) = self.cmdline_info_for_pid(pid, uid) {
                (Some(res.0), res.1)
            } else if self.termux_process_has_non_package_cmdline(pid, uid) {
                continue;
            } else {
                (
                    self.filter
                        .candidate_for_uid(
                            self.kind(),
                            Some(pid),
                            uid,
                            self.package_cache.as_ref(),
                        )
                        .filter(|c| c.identity_resolved),
                    false,
                )
            };

            if let Some(candidate) = candidate {
                let is_better = match &best {
                    None => true,
                    Some((best_pid, _, best_is_ui)) => {
                        if is_ui && !*best_is_ui {
                            true
                        } else if !is_ui && *best_is_ui {
                            false
                        } else {
                            pid > *best_pid
                        }
                    }
                };

                if is_better {
                    best = Some((pid, candidate, is_ui));
                }
            }
        }

        if let Some((_, candidate, _)) = best {
            self.last_candidate = Some(candidate.clone());
            return Ok(Some(candidate));
        }

        self.last_candidate = None;
        Ok(None)
    }

    fn cmdline_info_for_pid(&self, pid: i32, uid: u32) -> Option<(ForegroundCandidate, bool)> {
        if !self.filter.is_valid_uid(uid) {
            return None;
        }
        let cmdline = read_proc_cmdline_at(&self.proc_root, pid).ok()?;
        let is_ui = cmdline.contains(":") && !cmdline.contains("remote") && !cmdline.contains("service");
        let package = package_from_proc_cmdline(&cmdline)?;
        if self.filter.blocked_packages.contains(package) {
            return None;
        }
        if let Some(cache) = self.package_cache.as_ref() {
            if uid >= 10_000 {
                match cache.uid_state(uid) {
                    UidPackageState::Exact(cached) if cached != package => return None,
                    UidPackageState::Ambiguous(packages)
                        if !packages.iter().any(|cached| cached == package) =>
                    {
                        return None;
                    }
                    UidPackageState::Exact(_)
                    | UidPackageState::Ambiguous(_)
                    | UidPackageState::Missing => {}
                }
            }
        }
        Some((
            ForegroundCandidate {
                source: self.kind(),
                pid: Some(pid),
                uid: Some(uid),
                package: Some(package.to_string()),
                identity_resolved: true,
            },
            is_ui,
        ))
    }

    fn termux_process_has_non_package_cmdline(&self, pid: i32, uid: u32) -> bool {
        if !self.cache_uid_has_package(uid, "com.termux") {
            return false;
        }
        let Ok(cmdline) = read_proc_cmdline_at(&self.proc_root, pid) else {
            return false;
        };
        let Some(process) = cmdline.split_whitespace().next() else {
            return false;
        };
        !process.is_empty() && package_from_proc_cmdline(&cmdline).is_none()
    }

    fn cache_uid_has_package(&self, uid: u32, package: &str) -> bool {
        let Some(cache) = self.package_cache.as_ref() else {
            return false;
        };
        match cache.uid_state(uid) {
            UidPackageState::Exact(cached) => cached == package,
            UidPackageState::Ambiguous(packages) => {
                packages.iter().any(|cached| cached == package)
            }
            UidPackageState::Missing => false,
        }
    }
}

fn package_from_proc_cmdline(cmdline: &str) -> Option<&str> {
    let process = cmdline.split_whitespace().next()?.split(":").next()?;
    (!process.is_empty() && process.contains(".") && !process.contains("/")).then_some(process)
}
