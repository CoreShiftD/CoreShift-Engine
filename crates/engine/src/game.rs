use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GameList {
    packages: BTreeSet<String>,
}

impl GameList {
    pub fn from_packages(packages: BTreeSet<String>) -> Self {
        Self { packages }
    }

    pub fn contains(&self, package: &str) -> bool {
        self.packages.contains(package)
    }

    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    pub fn packages(&self) -> impl Iterator<Item = &str> {
        self.packages.iter().map(String::as_str)
    }

    pub fn package_set(&self) -> &BTreeSet<String> {
        &self.packages
    }
}

pub fn load_game_list(path: &Path) -> io::Result<GameList> {
    fs::read_to_string(path).map(|text| parse_game_list(&text))
}

pub fn parse_game_list(text: &str) -> GameList {
    let packages = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| valid_package_name(line))
        .map(str::to_string)
        .collect();
    GameList { packages }
}

pub fn game_targets_from_installed(
    game_list: &GameList,
    installed_packages: &BTreeSet<String>,
) -> GameList {
    GameList::from_packages(
        game_list
            .packages()
            .filter(|package| installed_packages.contains(*package))
            .map(str::to_string)
            .collect(),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedGameDownscale {
    pub package: String,
    pub overlay_hash: String,
    pub applied_ms: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagedGameDownscales {
    entries: BTreeMap<String, ManagedGameDownscale>,
}

impl ManagedGameDownscales {
    pub fn contains(&self, package: &str) -> bool {
        self.entries.contains_key(package)
    }

    pub fn insert(&mut self, entry: ManagedGameDownscale) {
        self.entries.insert(entry.package.clone(), entry);
    }

    pub fn remove(&mut self, package: &str) -> Option<ManagedGameDownscale> {
        self.entries.remove(package)
    }

    pub fn packages(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, package: &str) -> Option<&ManagedGameDownscale> {
        self.entries.get(package)
    }
}

pub fn load_managed_game_downscales(path: &Path) -> io::Result<ManagedGameDownscales> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(parse_managed_game_downscales(&text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(ManagedGameDownscales::default()),
        Err(err) => Err(err),
    }
}

pub fn parse_managed_game_downscales(text: &str) -> ManagedGameDownscales {
    let mut state = ManagedGameDownscales::default();
    for line in text.lines() {
        let columns = line.split('\t').collect::<Vec<_>>();
        let (package, overlay_hash, applied_ms) = match columns.as_slice() {
            [package, overlay_hash, applied_ms] => (*package, *overlay_hash, *applied_ms),
            [package, mode, overlay_hash, applied_ms]
                if matches!(*mode, "standard" | "performance" | "battery") =>
            {
                (*package, *overlay_hash, *applied_ms)
            }
            _ => continue,
        };
        if !valid_package_name(package) {
            continue;
        }
        if overlay_hash.is_empty() || !overlay_hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(applied_ms) = applied_ms.parse::<u64>() else {
            continue;
        };
        state.insert(ManagedGameDownscale {
            package: package.to_string(),
            overlay_hash: overlay_hash.to_string(),
            applied_ms,
        });
    }
    state
}

pub fn write_managed_game_downscales(path: &Path, state: &ManagedGameDownscales) -> io::Result<()> {
    let mut text = String::new();
    for entry in state.entries.values() {
        text.push_str(&format!(
            "{}\t{}\t{}\n",
            entry.package, entry.overlay_hash, entry.applied_ms
        ));
    }
    atomic_write_string(path, &text)
}

fn atomic_write_string(path: &Path, content: &str) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("game_state.tsv"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let write_result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

fn valid_package_name(value: &str) -> bool {
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if !valid_package_segment(first) {
        return false;
    }
    let mut segment_count = 1;
    for segment in segments {
        segment_count += 1;
        if !valid_package_segment(segment) {
            return false;
        }
    }
    segment_count >= 2
}

fn valid_package_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "coreshift-engine-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn gamelist_parser_handles_comments_blank_duplicates_and_invalid_lines() {
        let list = parse_game_list(
            "\n# comment\n com.example.game \ncom.example.game\nbad package\ncom.other.Game_2\n*.wildcard\n",
        );

        assert_eq!(list.len(), 2);
        assert!(list.contains("com.example.game"));
        assert!(list.contains("com.other.Game_2"));
        assert!(!list.contains("bad package"));
        assert!(!list.contains("*.wildcard"));
    }

    #[test]
    fn game_targets_use_installed_cache_intersection() {
        let list = parse_game_list("com.installed.game\ncom.missing.game\ncom.other.app\n");
        let installed =
            BTreeSet::from(["com.installed.game".to_string(), "com.not.game".to_string()]);

        let targets = game_targets_from_installed(&list, &installed);

        assert_eq!(targets.len(), 1);
        assert!(targets.contains("com.installed.game"));
        assert!(!targets.contains("com.missing.game"));
        assert!(!targets.contains("com.not.game"));
    }

    #[test]
    fn managed_downscale_state_loads_writes_and_accepts_legacy_rows() {
        let path = temp_file("game-state");
        let text = "\
com.good.game\tperformance\t0123456789abcdef\t42\n\
com.good.other\t0123456789abcdea\t43\n\
bad line\n\
com.bad\tweird\t0123\t1\n\
com.other.game\tstandard\tabcdef\tbad\n";
        std::fs::write(&path, text).unwrap();

        let state = load_managed_game_downscales(&path).unwrap();

        assert_eq!(state.len(), 2);
        assert!(state.contains("com.good.game"));
        assert!(state.contains("com.good.other"));

        write_managed_game_downscales(&path, &state).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            written,
            "\
com.good.game\t0123456789abcdef\t42\n\
com.good.other\t0123456789abcdea\t43\n"
        );
        let _ = std::fs::remove_file(path);
    }
}
