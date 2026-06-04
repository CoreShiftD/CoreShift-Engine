use super::cache::{PackageUidProvider, UidPackageCache, UidPackageState};
use crate::EngineError;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForegroundResolveReport {
    pub package: Option<String>,
    pub lines: Vec<String>,
}

impl ForegroundResolveReport {
    pub fn unknown(source: &str) -> Self {
        Self {
            package: None,
            lines: vec![format!("source={} reason=unknown", source)],
        }
    }

    pub fn unavailable(source: &str) -> Self {
        Self {
            package: None,
            lines: vec![format!("source={} reason=unavailable", source)],
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V1PayloadCache {
    last: Option<Vec<u8>>,
}

impl V1PayloadCache {
    pub fn read_initial(&mut self, path: &Path) -> Result<Vec<u8>, EngineError> {
        let payload = std::fs::read(path)?;
        self.last = Some(payload.clone());
        Ok(payload)
    }

    pub fn read_changed(&mut self, path: &Path) -> Result<Option<Vec<u8>>, EngineError> {
        let payload = std::fs::read(path)?;
        Ok(self.observe(payload))
    }

    pub fn observe(&mut self, payload: Vec<u8>) -> Option<Vec<u8>> {
        if self.last.as_deref() == Some(payload.as_slice()) {
            None
        } else {
            self.last = Some(payload.clone());
            Some(payload)
        }
    }

    pub fn last(&self) -> Option<&[u8]> {
        self.last.as_deref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppUidFilter {
    pub modulus: u32,
    pub min_app_id: u32,
}

impl AppUidFilter {
    pub fn accepts(&self, uid: u32) -> bool {
        self.modulus != 0 && uid % self.modulus >= self.min_app_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForegroundResolverState {
    pub cache: UidPackageCache,
    pub blocked_packages: BTreeSet<String>,
    pub accessibility_uids: BTreeSet<u32>,
    pub app_uid_filter: AppUidFilter,
    pub cache_rebuilds: u64,
    pub foreground_changes: u64,
    marker_fingerprint: Option<PackageFileStat>,
}

impl ForegroundResolverState {
    pub fn new(
        cache: UidPackageCache,
        blocked_packages: BTreeSet<String>,
        accessibility_uids: BTreeSet<u32>,
        app_uid_filter: AppUidFilter,
        marker_fingerprint: Option<PackageFileStat>,
    ) -> Self {
        Self {
            cache,
            blocked_packages,
            accessibility_uids,
            app_uid_filter,
            cache_rebuilds: 1,
            foreground_changes: 0,
            marker_fingerprint,
        }
    }

    pub fn marker_fingerprint(&self) -> Option<&PackageFileStat> {
        self.marker_fingerprint.as_ref()
    }

    pub fn foreground_changed<P, S>(
        &mut self,
        provider: &P,
        statter: &mut S,
        marker_path: &Path,
        interval: u64,
    ) -> Result<Option<String>, EngineError>
    where
        P: PackageUidProvider,
        S: PackageFileStatProvider,
    {
        self.foreground_changes += 1;
        if interval == 0 || self.foreground_changes % interval != 0 {
            return Ok(None);
        }

        match statter.stat_package_marker(marker_path) {
            Ok(current) => {
                let changed = self
                    .marker_fingerprint
                    .as_ref()
                    .is_some_and(|previous| previous != &current);
                if changed {
                    self.cache.update_from(provider)?;
                    self.cache_rebuilds += 1;
                    self.marker_fingerprint = Some(current);
                    Ok(Some(format!(
                        "cache stat_check change_count={} changed=true action=rebuild entries={}",
                        self.foreground_changes,
                        self.cache.entry_count()
                    )))
                } else {
                    self.marker_fingerprint = Some(current);
                    Ok(Some(format!(
                        "cache stat_check change_count={} changed=false action=keep",
                        self.foreground_changes
                    )))
                }
            }
            Err(err) => Ok(Some(format!(
                "cache stat_check error={} action=keep",
                format_io_error_reason(&err)
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageFileStat {
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub size: u64,
}

pub trait PackageFileStatProvider {
    fn stat_package_marker(&mut self, path: &Path) -> Result<PackageFileStat, EngineError>;
}

#[derive(Clone, Debug, Default)]
pub struct FsPackageFileStatProvider;

impl PackageFileStatProvider for FsPackageFileStatProvider {
    fn stat_package_marker(&mut self, path: &Path) -> Result<PackageFileStat, EngineError> {
        fs_package_file_stat(path)
    }
}

pub fn fs_package_file_stat(path: &Path) -> Result<PackageFileStat, EngineError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path)?;
    Ok(PackageFileStat {
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        size: metadata.size(),
    })
}

pub fn resolve_v1_payload_with_uid_resolver<F>(
    payload: &[u8],
    state: &ForegroundResolverState,
    mut uid_for_pid: F,
) -> ForegroundResolveReport
where
    F: FnMut(i32) -> Result<Option<u32>, EngineError>,
{
    let content = String::from_utf8_lossy(payload);
    let mut lines = Vec::new();

    for line in content.lines() {
        let Ok(pid) = line.trim().parse::<i32>() else {
            continue;
        };
        let Ok(Some(uid)) = uid_for_pid(pid) else {
            lines.push(format!("source=v1 pid={} reason=pid_uid_failed", pid));
            continue;
        };
        if !state.app_uid_filter.accepts(uid) {
            lines.push(format!("source=v1 uid={} reason=skipped_non_app", uid));
            continue;
        }
        if state.accessibility_uids.contains(&uid) {
            lines.push(format!("source=v1 uid={} reason=skipped_accessibility", uid));
            continue;
        }
        match state.cache.uid_state(uid) {
            UidPackageState::Exact(package) => {
                if state.blocked_packages.contains(&package) {
                    lines.push(format!("source=v1 package={} reason=blocked", package));
                    continue;
                }
                lines.push(format!(
                    "source=v1 pid={} uid={} package={} reason=resolved",
                    pid, uid, package
                ));
                return ForegroundResolveReport {
                    package: Some(package),
                    lines,
                };
            }
            UidPackageState::Ambiguous(packages) => {
                lines.push(format!(
                    "source=v1 uid={} package_count={} reason=ambiguous",
                    uid,
                    packages.len()
                ));
            }
            UidPackageState::Missing => {
                lines.push(format!("source=v1 pid={} uid={} reason=unmapped", pid, uid));
            }
        }
    }

    if lines.is_empty() {
        ForegroundResolveReport::unknown("v1")
    } else {
        lines.push("source=v1 reason=unknown".to_string());
        ForegroundResolveReport {
            package: None,
            lines,
        }
    }
}

pub fn resolve_after_v1_unavailable_lazy(
    v1_report: ForegroundResolveReport,
    activity: impl FnOnce() -> ForegroundResolveReport,
) -> ForegroundResolveReport {
    if v1_report.package.is_some() {
        return v1_report;
    }
    let mut report = v1_report;
    report
        .lines
        .push("source=v1 reason=unavailable fallback=activity".to_string());
    let activity_report = activity();
    report.package = activity_report.package;
    report.lines.extend(activity_report.lines);
    report
}

pub fn resolve_v2_uid_with_state(
    uid: u32,
    state: &ForegroundResolverState,
) -> ForegroundResolveReport {
    if !state.app_uid_filter.accepts(uid) {
        return ForegroundResolveReport {
            package: None,
            lines: vec![format!("source=v2 uid={} reason=skipped_non_app", uid)],
        };
    }
    if state.accessibility_uids.contains(&uid) {
        return ForegroundResolveReport {
            package: None,
            lines: vec![format!("source=v2 uid={} reason=skipped_accessibility", uid)],
        };
    }
    match state.cache.uid_state(uid) {
        UidPackageState::Exact(package) => {
            if state.blocked_packages.contains(&package) {
                ForegroundResolveReport {
                    package: None,
                    lines: vec![format!("source=v2 package={} reason=blocked", package)],
                }
            } else {
                ForegroundResolveReport {
                    package: Some(package.clone()),
                    lines: vec![format!(
                        "source=v2 uid={} package={} reason=resolved",
                        uid, package
                    )],
                }
            }
        }
        UidPackageState::Ambiguous(packages) => ForegroundResolveReport {
            package: None,
            lines: vec![format!(
                "source=v2 uid={} package_count={} reason=ambiguous",
                uid,
                packages.len()
            )],
        },
        UidPackageState::Missing => ForegroundResolveReport {
            package: None,
            lines: vec![format!("source=v2 uid={} reason=unmapped", uid)],
        },
    }
}

pub fn resolve_after_v1_v2_unavailable_lazy(
    v1_report: ForegroundResolveReport,
    v2: impl FnOnce() -> ForegroundResolveReport,
    activity: impl FnOnce() -> ForegroundResolveReport,
) -> ForegroundResolveReport {
    if v1_report.package.is_some() {
        return v1_report;
    }
    let mut report = v1_report;
    report
        .lines
        .push("source=v1 reason=unavailable fallback=v2".to_string());
    let v2_report = v2();
    if v2_report.package.is_some() {
        let ForegroundResolveReport { package, lines } = v2_report;
        report.package = package;
        report.lines.extend(lines);
        return report;
    }
    report.lines.extend(v2_report.lines);
    report
        .lines
        .push("source=v2 reason=unavailable fallback=activity".to_string());
    let activity_report = activity();
    report.package = activity_report.package;
    report.lines.extend(activity_report.lines);
    report
}

fn format_io_error_reason(err: &EngineError) -> String {
    match err {
        EngineError::Io(err) => match err.kind() {
            std::io::ErrorKind::PermissionDenied => "permission_denied".to_string(),
            std::io::ErrorKind::NotFound => "not_found".to_string(),
            _ => err.to_string().replace(' ', "_"),
        },
        _ => err.to_string().replace(' ', "_"),
    }
}
