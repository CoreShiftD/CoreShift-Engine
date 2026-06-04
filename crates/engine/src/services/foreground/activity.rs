use super::resolver::ForegroundResolveReport;
use super::source::ForegroundCandidateFilter;
use std::collections::BTreeSet;

pub fn parse_top_activity_package(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let (_, after) = text.split_once("topActivity=ComponentInfo{")?;
    let (component, _) = after.split_once('}')?;
    let (package, activity) = component.split_once('/')?;
    if package.is_empty() || activity.is_empty() {
        return None;
    }
    Some(package.to_string())
}

pub fn resolve_activity_stdout(
    stdout: &[u8],
    filter: &ForegroundCandidateFilter,
) -> ForegroundResolveReport {
    let Some(package) = parse_top_activity_package(stdout) else {
        return ForegroundResolveReport::unknown("activity");
    };
    if filter.blocked_packages.contains(&package) {
        return ForegroundResolveReport {
            package: None,
            lines: vec![format!("source=activity package={package} reason=blocked")],
        };
    }
    ForegroundResolveReport {
        package: Some(package.clone()),
        lines: vec![format!("source=activity package={package} reason=resolved")],
    }
}
