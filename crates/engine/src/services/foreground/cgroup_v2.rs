use super::cache::{UidPackageCache, UidPackageState};
use super::source::{
    ForegroundCandidate, ForegroundCandidateFilter, ForegroundSource, ForegroundSourceKind,
};
use crate::EngineError;
use coreshift_core::reactor::{Fd, Reactor, Token};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::fd::IntoRawFd;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupV2Populated {
    Active,
    Inactive,
    Unknown,
}

const IN_CREATE_MASK: u32 = 0x0000_0100;
const IN_DELETE_MASK: u32 = 0x0000_0200;
const IN_MOVED_FROM_MASK: u32 = 0x0000_0040;
const IN_MOVED_TO_MASK: u32 = 0x0000_0080;
const IN_Q_OVERFLOW_MASK: u32 = 0x0000_4000;
const IN_DELETE_SELF_MASK: u32 = 0x0000_0400;
const IN_MOVE_SELF_MASK: u32 = 0x0000_0800;
const IN_IGNORED_MASK: u32 = 0x0000_8000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CgroupV2UidEvent {
    pub uid: u32,
    pub active: bool,
}

struct UidWatch {
    uid: u32,
    events_path: PathBuf,
    events_fd: Fd,
    generation: u64,
    populated: CgroupV2Populated,
}

pub struct CgroupV2EventsSource {
    roots: Vec<PathBuf>,
    pub filter: ForegroundCandidateFilter,
    watch_hint_paths: Vec<PathBuf>,
    watches: BTreeMap<PathBuf, UidWatch>,
    package_cache: Option<UidPackageCache>,
    stale_roots: BTreeSet<PathBuf>,
    next_watch_generation: u64,
}

impl CgroupV2EventsSource {
    pub fn new(roots: Vec<PathBuf>, filter: ForegroundCandidateFilter) -> Self {
        let mut source = Self {
            watch_hint_paths: roots.clone(),
            roots,
            filter,
            watches: BTreeMap::new(),
            package_cache: None,
            stale_roots: BTreeSet::new(),
            next_watch_generation: 1,
        };
        source.scan_roots();
        source
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

    pub fn uid_watch_count(&self) -> usize {
        self.watches.len()
    }

    pub fn has_uid_watch(&self, uid: u32) -> bool {
        self.watches.values().any(|watch| watch.uid == uid)
    }

    pub fn has_uid_watch_path(&self, path: &Path) -> bool {
        self.watches.contains_key(path)
    }

    pub fn is_root_stale(&self, root: &Path) -> bool {
        self.stale_roots.contains(root)
    }

    pub fn is_available(&self) -> bool {
        !self.watches.is_empty()
            || self
                .roots
                .iter()
                .any(|root| self.root_has_usable_layout(root))
    }

    fn scan_roots(&mut self) {
        for root in self.roots.clone() {
            let Ok(entries) = std::fs::read_dir(&root) else {
                continue;
            };
            for entry in entries.flatten() {
                let uid_dir = entry.path();
                if !uid_dir.is_dir() {
                    continue;
                }
                let Some(uid) = parse_uid_dir_name(&uid_dir) else {
                    continue;
                };
                self.add_uid_watch(uid_dir, uid);
            }
        }
    }

    fn root_has_usable_layout(&self, root: &Path) -> bool {
        if self.stale_roots.contains(root) || !root.is_dir() {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let uid_dir = entry.path();
            if !uid_dir.is_dir() {
                return false;
            }
            let Some(uid) = parse_uid_dir_name(&uid_dir) else {
                return false;
            };
            self.filter.is_valid_uid(uid) && uid_dir.join("cgroup.events").is_file()
        })
    }

    fn rescan_roots(&mut self) {
        let existing = self
            .watches
            .iter()
            .filter_map(|(path, watch)| {
                if path.exists() {
                    None
                } else {
                    Some((path.clone(), watch.uid))
                }
            })
            .collect::<Vec<_>>();
        for (path, uid) in existing {
            self.remove_uid_watch_path(&path, uid);
        }
        self.scan_roots();
    }

    fn add_uid_watch(&mut self, uid_dir: PathBuf, uid: u32) -> bool {
        if !self.filter.is_valid_uid(uid) {
            return false;
        }
        let events_path = uid_dir.join("cgroup.events");
        if self.watches.contains_key(&events_path) {
            return false;
        }
        let Ok(events_fd) = open_cgroup_events_fd(&events_path) else {
            return false;
        };
        let generation = self.next_watch_generation;
        self.next_watch_generation = self.next_watch_generation.saturating_add(1);
        let watch = UidWatch {
            uid,
            events_path: events_path.clone(),
            events_fd,
            generation,
            populated: CgroupV2Populated::Unknown,
        };
        self.watches.insert(events_path.clone(), watch);
        true
    }

    fn remove_uid_watch_path(&mut self, events_path: &Path, uid: u32) -> bool {
        if self
            .watches
            .get(events_path)
            .is_none_or(|watch| watch.uid != uid)
        {
            return false;
        }
        self.watches.remove(events_path).is_some()
    }

    fn remove_watch_path(&mut self, events_path: &Path) -> bool {
        self.watches.remove(events_path).is_some()
    }

    fn candidate_for_uid(&self, uid: u32) -> Option<ForegroundCandidate> {
        let cache = self.package_cache.as_ref()?;
        match cache.uid_state(uid) {
            UidPackageState::Exact(package) => {
                if self.filter.blocked_packages.contains(&package) {
                    None
                } else {
                    Some(ForegroundCandidate {
                        source: ForegroundSourceKind::CgroupV2,
                        pid: None,
                        uid: Some(uid),
                        package: Some(package),
                        identity_resolved: true,
                    })
                }
            }
            UidPackageState::Missing | UidPackageState::Ambiguous(_) => None,
        }
    }

    fn handle_events_path(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        let Some(watch) = self.watches.get(path) else {
            self.rescan_roots();
            return Ok(None);
        };
        if !watch.events_path.exists() {
            return self.handle_stale_events_path(path);
        }
        let uid = watch.uid;
        self.drain_events_fd(path)?;
        let populated = self.read_events_fd_populated(path)?;
        self.handle_uid_populated_at(path, uid, populated)
    }

    fn handle_stale_events_path(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.remove_watch_path(path);
        self.rescan_roots();
        Ok(None)
    }

    fn handle_uid_populated_at(
        &mut self,
        path: &Path,
        uid: u32,
        populated: CgroupV2Populated,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        if !self.watches.contains_key(path) {
            return Ok(None);
        }
        let last = self
            .watches
            .get(path)
            .map(|watch| watch.populated)
            .unwrap_or(CgroupV2Populated::Unknown);
        if let Some(watch) = self.watches.get_mut(path) {
            watch.populated = populated;
        }

        match populated {
            CgroupV2Populated::Active => Ok(self.candidate_for_uid(uid)),
            CgroupV2Populated::Inactive
                if last != CgroupV2Populated::Inactive && last != CgroupV2Populated::Unknown =>
            {
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn handle_root_path(
        &mut self,
        path: &Path,
        mask: u32,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        if mask & IN_Q_OVERFLOW_MASK != 0 {
            self.rescan_roots();
            return Ok(None);
        }
        if mask & (IN_DELETE_SELF_MASK | IN_MOVE_SELF_MASK | IN_IGNORED_MASK) != 0 {
            if self.roots.iter().any(|root| root == path) {
                self.stale_roots.insert(path.to_path_buf());
            }
            self.rescan_roots();
            return Ok(None);
        }
        let Some(uid) = parse_uid_dir_name(path) else {
            return Ok(None);
        };
        if mask & (IN_DELETE_MASK | IN_MOVED_FROM_MASK) != 0 || !path.exists() {
            self.remove_uid_watch_path(&path.join("cgroup.events"), uid);
            return Ok(None);
        }
        if mask & (IN_CREATE_MASK | IN_MOVED_TO_MASK) == 0 && mask != 0 {
            return Ok(None);
        }
        if !self
            .roots
            .iter()
            .any(|root| path.parent() == Some(root.as_path()))
        {
            return Ok(None);
        }
        if !self.add_uid_watch(path.to_path_buf(), uid) {
            return Ok(None);
        }
        self.handle_uid_populated_at(
            &path.join("cgroup.events"),
            uid,
            read_cgroup_events_populated(&path.join("cgroup.events"))?,
        )
    }
}

impl ForegroundSource for CgroupV2EventsSource {
    fn kind(&self) -> ForegroundSourceKind {
        ForegroundSourceKind::CgroupV2
    }

    fn poll_current(&mut self) -> Result<Option<ForegroundCandidate>, EngineError> {
        for path in self.watches.keys().cloned().collect::<Vec<_>>() {
            let Some(watch) = self.watches.get(&path) else {
                continue;
            };
            let uid = watch.uid;
            let populated = match read_cgroup_events_populated(&watch.events_path) {
                Ok(populated) => populated,
                Err(err) if is_not_found(&err) => {
                    self.remove_watch_path(&path);
                    self.rescan_roots();
                    continue;
                }
                Err(err) => return Err(err),
            };
            if let Some(watch) = self.watches.get_mut(&path) {
                watch.populated = populated;
            }
            if populated == CgroupV2Populated::Active {
                if let Some(candidate) = self.candidate_for_uid(uid) {
                    return Ok(Some(candidate));
                }
            }
        }
        Ok(None)
    }

    fn handle_fs_event(&mut self, path: &Path) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.handle_fs_event_with_mask(path, 0)
    }

    fn handle_fs_event_with_mask(
        &mut self,
        path: &Path,
        mask: u32,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        if mask & IN_Q_OVERFLOW_MASK != 0 {
            return self.handle_root_path(path, mask);
        }
        if self.roots.iter().any(|root| root == path) {
            return self.handle_root_path(path, mask);
        }
        if self
            .roots
            .iter()
            .any(|root| path.parent() == Some(root.as_path()))
        {
            return self.handle_root_path(path, mask);
        }
        Ok(None)
    }

    fn watch_hint_paths(&self) -> &[PathBuf] {
        &self.watch_hint_paths
    }

    fn is_available(&self) -> bool {
        CgroupV2EventsSource::is_available(self)
    }

    fn watch_hint_mask(&self, _path: &Path) -> u32 {
        IN_CREATE_MASK
            | IN_DELETE_MASK
            | IN_MOVED_FROM_MASK
            | IN_MOVED_TO_MASK
            | IN_DELETE_SELF_MASK
            | IN_MOVE_SELF_MASK
            | IN_IGNORED_MASK
    }

    fn register_priority_fds(
        &self,
        reactor: &mut Reactor,
        registered_paths: &BTreeSet<PathBuf>,
    ) -> Result<Vec<(Token, PathBuf)>, EngineError> {
        let mut registrations = Vec::new();
        for (path, watch) in &self.watches {
            if registered_paths.contains(path) {
                continue;
            }
            registrations.push((reactor.add_priority(&watch.events_fd)?, path.clone()));
        }
        Ok(registrations)
    }

    fn priority_hint_paths(&self) -> Vec<PathBuf> {
        self.watches.keys().cloned().collect()
    }

    fn priority_hint_keys(&self) -> Vec<(PathBuf, u64)> {
        self.watches
            .iter()
            .map(|(path, watch)| (path.clone(), watch.generation))
            .collect()
    }

    fn handle_priority_event(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.handle_events_path(path)
    }

    fn handle_stale_priority_event(
        &mut self,
        path: &Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.handle_stale_events_path(path)
    }

    fn unregister_priority_fd(&self, reactor: &Reactor, path: &Path) -> Result<bool, EngineError> {
        let Some(watch) = self.watches.get(path) else {
            return Ok(false);
        };
        reactor.del(&watch.events_fd)?;
        Ok(true)
    }
}

impl CgroupV2EventsSource {
    fn drain_events_fd(&self, path: &Path) -> Result<(), EngineError> {
        let Some(watch) = self.watches.get(path) else {
            return Ok(());
        };
        watch.events_fd.seek_set(0)?;
        let mut buf = [0u8; 256];
        let mut len = 0usize;
        loop {
            match watch.events_fd.read_slice(&mut buf[len..])? {
                Some(0) | None => return Ok(()),
                Some(n) => {
                    len = len.saturating_add(n);
                    if len == buf.len() {
                        return Ok(());
                    }
                }
            }
        }
    }

    fn read_events_fd_populated(&self, path: &Path) -> Result<CgroupV2Populated, EngineError> {
        let Some(watch) = self.watches.get(path) else {
            return Ok(CgroupV2Populated::Unknown);
        };
        watch.events_fd.seek_set(0)?;
        let mut buf = [0u8; 256];
        let mut len = 0usize;
        loop {
            match watch.events_fd.read_slice(&mut buf[len..])? {
                Some(0) | None => return Ok(parse_cgroup_events_populated(&buf[..len])),
                Some(n) => {
                    len = len.saturating_add(n);
                    if len == buf.len() {
                        return Ok(parse_cgroup_events_populated(&buf));
                    }
                }
            }
        }
    }
}

fn is_not_found(err: &EngineError) -> bool {
    matches!(err, EngineError::Io(io) if io.kind() == ErrorKind::NotFound)
}

fn open_cgroup_events_fd(path: &Path) -> Result<Fd, EngineError> {
    let file = OpenOptions::new().read(true).open(path)?;
    let raw_fd = file.into_raw_fd();
    // SAFETY: into_raw_fd transfers ownership to Fd, which closes it on drop.
    Ok(unsafe { Fd::from_owned_raw_fd(raw_fd, "open cgroup.events")? })
}

pub fn read_cgroup_events_populated(path: &Path) -> Result<CgroupV2Populated, EngineError> {
    Ok(parse_cgroup_events_populated(&std::fs::read(path)?))
}

pub fn candidate_uid_roots_from_proc_mounts_path(path: &Path) -> Result<Vec<PathBuf>, EngineError> {
    let content = std::fs::read_to_string(path)?;
    Ok(candidate_uid_roots_from_proc_mounts(&content))
}

pub fn candidate_uid_roots_from_proc_mounts(content: &str) -> Vec<PathBuf> {
    find_cgroup2_mount(content)
        .map(|mount| vec![mount.clone(), mount.join("apps")])
        .unwrap_or_default()
}

pub fn find_cgroup2_mount(content: &str) -> Option<PathBuf> {
    parse_proc_mounts(content)
        .into_iter()
        .find_map(|entry| (entry.fs_type == "cgroup2").then_some(entry.mount_point))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcMountEntry {
    pub source: String,
    pub mount_point: PathBuf,
    pub fs_type: String,
}

pub fn parse_proc_mounts(content: &str) -> Vec<ProcMountEntry> {
    content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let source = unescape_proc_mount_field(fields.next()?);
            let mount_point = PathBuf::from(unescape_proc_mount_field(fields.next()?));
            let fs_type = unescape_proc_mount_field(fields.next()?);
            Some(ProcMountEntry {
                source,
                mount_point,
                fs_type,
            })
        })
        .collect()
}

fn unescape_proc_mount_field(field: &str) -> String {
    let mut out = String::new();
    let bytes = field.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &field[i + 1..i + 4];
            if let Ok(value) = u8::from_str_radix(octal, 8) {
                out.push(value as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

pub fn parse_cgroup_events_populated(content: &[u8]) -> CgroupV2Populated {
    let Ok(text) = std::str::from_utf8(content) else {
        return CgroupV2Populated::Unknown;
    };
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("populated") {
            continue;
        }
        return match parts.next() {
            Some("1") => CgroupV2Populated::Active,
            Some("0") => CgroupV2Populated::Inactive,
            _ => CgroupV2Populated::Unknown,
        };
    }
    CgroupV2Populated::Unknown
}

pub fn parse_uid_dir_name(path: &Path) -> Option<u32> {
    let name = path.file_name().and_then(|name| name.to_str())?;
    if let Some(uid) = name.strip_prefix("uid_") {
        return uid.parse::<u32>().ok();
    }

    let (user, app) = name.strip_prefix('u')?.split_once("_a")?;
    let user = user.parse::<u32>().ok()?;
    let app = app.parse::<u32>().ok()?;
    user.checked_mul(100_000)?
        .checked_add(10_000)?
        .checked_add(app)
}

pub fn resolve_v2_uid_with_cache(
    uid: u32,
    cache: &UidPackageCache,
    blocked_packages: &BTreeSet<String>,
) -> Option<String> {
    match cache.uid_state(uid) {
        UidPackageState::Exact(package) if !blocked_packages.contains(&package) => Some(package),
        _ => None,
    }
}
