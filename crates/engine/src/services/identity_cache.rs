use crate::EngineError;
use crate::config::IdentityCacheInvalidationConfig;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCacheFingerprint {
    pub dev: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
}

impl IdentityCacheFingerprint {
    pub fn from_path(path: &Path) -> Result<Self, EngineError> {
        let metadata = std::fs::metadata(path)?;
        Ok(Self {
            dev: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityCacheDirtyState {
    pub packages_xml_changed: bool,
}

#[derive(Clone, Debug)]
pub struct IdentityCacheInvalidator {
    config: IdentityCacheInvalidationConfig,
    foreground_count: u64,
    packages_xml_fingerprint: Option<IdentityCacheFingerprint>,
    dirty: IdentityCacheDirtyState,
}

impl IdentityCacheInvalidator {
    pub fn new(config: IdentityCacheInvalidationConfig) -> Self {
        let packages_xml_fingerprint = if config.packages_xml_path.as_os_str().is_empty() {
            None
        } else {
            IdentityCacheFingerprint::from_path(&config.packages_xml_path).ok()
        };
        Self {
            config,
            foreground_count: 0,
            packages_xml_fingerprint,
            dirty: IdentityCacheDirtyState::default(),
        }
    }

    pub fn config(&self) -> &IdentityCacheInvalidationConfig {
        &self.config
    }

    pub fn watch_hint_paths(&self) -> &[PathBuf] {
        &[]
    }

    pub fn foreground_count(&self) -> u64 {
        self.foreground_count
    }

    pub fn mark_foreground_candidate(&mut self) {
        if !self.config.enabled() {
            return;
        }
        self.foreground_count = self.foreground_count.saturating_add(1);
        let interval = self.config.foreground_check_interval;
        if interval != 0 && self.foreground_count % interval == 0 {
            let _ = self.check_packages_xml();
        }
    }

    pub fn mark_event(&mut self, _path: &Path) {
        // No identity-cache filesystem hint watches are active in the current design.
    }

    pub fn should_refresh_now(&self) -> bool {
        self.dirty.packages_xml_changed
    }

    pub fn consume_dirty(&mut self) -> IdentityCacheDirtyState {
        std::mem::take(&mut self.dirty)
    }

    pub fn check_packages_xml(&mut self) -> Result<bool, EngineError> {
        let next = IdentityCacheFingerprint::from_path(&self.config.packages_xml_path)?;
        let changed = self
            .packages_xml_fingerprint
            .as_ref()
            .is_none_or(|current| current != &next);
        self.packages_xml_fingerprint = Some(next);
        if changed {
            self.dirty.packages_xml_changed = true;
        }
        Ok(changed)
    }
}
