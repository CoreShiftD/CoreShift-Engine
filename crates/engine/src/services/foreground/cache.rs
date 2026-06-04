use crate::EngineError;
use crate::exec::ExecRunner;
use coreshift_core::spawn::ExitStatus;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const DEFAULT_MIN_ENTRIES: usize = 5;
const NON_APP_UIDS: [u32; 5] = [0, 1000, 1023, 2000, 9997];

pub trait PackageUidProvider {
    fn load(&self) -> Result<PackageUidSnapshot, EngineError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageUidSnapshot {
    pub entries: Vec<PackageUidEntry>,
    pub source: PackageProviderSource,
    pub coherent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageUidEntry {
    pub package: String,
    pub uid: u32,
    pub base_apk_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageProviderSource {
    CmdPackageList,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageUidCoherence {
    pub min_entries: usize,
}

impl Default for PackageUidCoherence {
    fn default() -> Self {
        Self {
            min_entries: DEFAULT_MIN_ENTRIES,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UidPackageCache {
    uid_to_packages: BTreeMap<u32, Vec<String>>,
    package_to_uid: BTreeMap<String, u32>,
    package_to_base_apk_path: BTreeMap<String, PathBuf>,
    source: Option<PackageProviderSource>,
    coherent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UidPackageState {
    Exact(String),
    Missing,
    Ambiguous(Vec<String>),
}

impl UidPackageCache {
    pub fn warm_from<P: PackageUidProvider>(provider: &P) -> Result<Self, EngineError> {
        let mut cache = Self::default();
        cache.update_from(provider)?;
        Ok(cache)
    }

    pub fn update_from<P: PackageUidProvider>(&mut self, provider: &P) -> Result<(), EngineError> {
        self.update_from_snapshot(provider.load()?)
    }

    pub fn update_from_snapshot(
        &mut self,
        snapshot: PackageUidSnapshot,
    ) -> Result<(), EngineError> {
        self.uid_to_packages.clear();
        self.package_to_uid.clear();
        self.package_to_base_apk_path.clear();
        self.source = Some(snapshot.source);
        self.coherent = snapshot.coherent;

        let mut uid_packages: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
        for entry in snapshot.entries {
            self.package_to_uid.insert(entry.package.clone(), entry.uid);
            if let Some(base_apk_path) = entry.base_apk_path {
                self.package_to_base_apk_path
                    .insert(entry.package.clone(), base_apk_path);
            }
            uid_packages
                .entry(entry.uid)
                .or_default()
                .insert(entry.package);
        }
        for (uid, packages) in uid_packages {
            self.uid_to_packages
                .insert(uid, packages.into_iter().collect());
        }
        Ok(())
    }

    pub fn packages_for_uid(&self, uid: u32) -> Option<&[String]> {
        self.uid_to_packages.get(&uid).map(Vec::as_slice)
    }

    pub fn exact_package_for_uid(&self, uid: u32) -> Option<&str> {
        match self.packages_for_uid(uid) {
            Some([package]) => Some(package.as_str()),
            _ => None,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.package_to_uid.len()
    }

    pub fn uid_for_package(&self, package: &str) -> Option<u32> {
        self.package_to_uid.get(package).copied()
    }

    pub fn base_apk_path_for_package(&self, package: &str) -> Option<&std::path::Path> {
        self.package_to_base_apk_path
            .get(package)
            .map(PathBuf::as_path)
    }

    pub fn source(&self) -> Option<PackageProviderSource> {
        self.source
    }

    pub fn coherent(&self) -> bool {
        self.coherent
    }

    pub fn uid_state(&self, uid: u32) -> UidPackageState {
        match self.packages_for_uid(uid) {
            Some([package]) => UidPackageState::Exact(package.clone()),
            Some(packages) if packages.len() > 1 => UidPackageState::Ambiguous(packages.to_vec()),
            _ => UidPackageState::Missing,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CmdPackageListProvider {
    exec: ExecRunner,
    cmd_path: PathBuf,
    user: u32,
    coherence: PackageUidCoherence,
}

impl CmdPackageListProvider {
    pub fn new(exec: ExecRunner, cmd_path: PathBuf, user: u32) -> Self {
        Self {
            exec,
            cmd_path,
            user,
            coherence: PackageUidCoherence::default(),
        }
    }

    pub fn with_min_entries(mut self, min_entries: usize) -> Self {
        self.coherence.min_entries = min_entries;
        self
    }
}

impl PackageUidProvider for CmdPackageListProvider {
    fn load(&self) -> Result<PackageUidSnapshot, EngineError> {
        let output = self.exec.run_capture_stdout(vec![
            self.cmd_path.to_string_lossy().into_owned(),
            "package".to_string(),
            "list".to_string(),
            "packages".to_string(),
            "-U".to_string(),
            "--user".to_string(),
            self.user.to_string(),
        ])?;
        let entries = if output.status == Some(ExitStatus::Exited(0)) {
            parse_cmd_package_list_stdout(&output.stdout)
        } else {
            Vec::new()
        };
        let coherent = is_coherent(&entries, &self.coherence);
        Ok(PackageUidSnapshot {
            entries,
            source: PackageProviderSource::CmdPackageList,
            coherent,
        })
    }
}

pub fn parse_cmd_package_list_stdout(stdout: &[u8]) -> Vec<PackageUidEntry> {
    let Ok(text) = std::str::from_utf8(stdout) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    for line in text.lines() {
        let mut package = None;
        let mut uid = None;

        for token in line.split_whitespace() {
            if let Some(value) = token.strip_prefix("package:") {
                if is_valid_package_name(value) {
                    package = Some(value.to_string());
                }
            } else if let Some(value) = token.strip_prefix("uid:") {
                uid = value.parse::<u32>().ok();
            }
        }

        if let (Some(package), Some(uid)) = (package, uid) {
            entries.push(PackageUidEntry {
                package,
                uid,
                base_apk_path: None,
            });
        }
    }
    entries.sort_by(|a, b| a.package.cmp(&b.package).then(a.uid.cmp(&b.uid)));
    entries
}

fn is_valid_package_name(package: &str) -> bool {
    let mut segments = package.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if !is_valid_package_segment(first) {
        return false;
    }

    let mut segment_count = 1;
    for segment in segments {
        segment_count += 1;
        if !is_valid_package_segment(segment) {
            return false;
        }
    }
    segment_count >= 2
}

fn is_valid_package_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_coherent(entries: &[PackageUidEntry], coherence: &PackageUidCoherence) -> bool {
    if entries.len() < coherence.min_entries {
        return false;
    }
    if !entries.iter().any(|entry| entry.uid >= 10_000) {
        return false;
    }

    let non_app_count = entries
        .iter()
        .filter(|entry| NON_APP_UIDS.contains(&entry.uid))
        .count();
    non_app_count * 2 <= entries.len()
}
