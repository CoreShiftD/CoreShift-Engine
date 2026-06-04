use crate::EngineError;
use coreshift_core::spawn::{SpawnBackend, SpawnFdPolicy};
use std::path::PathBuf;

/// Engine execution settings mapped directly to Core spawn primitives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecConfig {
    /// Required Core spawn backend.
    pub backend: SpawnBackend,
    /// Explicit child file descriptor policy.
    pub fd_policy: SpawnFdPolicy,
    /// Optional process timeout in milliseconds.
    pub timeout_ms: Option<u32>,
    /// Combined stdout/stderr output limit passed to Core.
    pub max_output: usize,
    /// Explicitly allow a zero-byte output capture limit.
    pub allow_zero_max_output: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityCacheProviderMode {
    Disabled,
    CmdPackageList,
}

/// Cache warmup settings for package UID identity lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCacheConfig {
    pub provider_mode: IdentityCacheProviderMode,
    pub cmd_path: PathBuf,
    pub user_id: u32,
}

/// Identity cache invalidation probe settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCacheInvalidationConfig {
    pub packages_xml_path: PathBuf,
    pub foreground_check_interval: u64,
    /// Reserved for the future runtime event loop/timer; no time debounce is applied yet.
    pub debounce_ms: u64,
}

/// Top-level Engine configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineConfig {
    pub exec: ExecConfig,
    pub identity_cache: IdentityCacheConfig,
    pub identity_cache_invalidation: IdentityCacheInvalidationConfig,
}

impl EngineConfig {
    pub fn new(exec: ExecConfig) -> Self {
        Self {
            exec,
            identity_cache: IdentityCacheConfig::default(),
            identity_cache_invalidation: IdentityCacheInvalidationConfig::default(),
        }
    }

    pub fn validate(&self) -> Result<(), EngineError> {
        if self.exec.max_output == 0 && !self.exec.allow_zero_max_output {
            return Err(EngineError::invalid_config(
                "exec.max_output",
                "must be > 0 unless allow_zero_max_output is true",
            ));
        }
        if matches!(
            self.identity_cache.provider_mode,
            IdentityCacheProviderMode::CmdPackageList
        ) && self.identity_cache.cmd_path.as_os_str().is_empty()
        {
            return Err(EngineError::invalid_config(
                "identity_cache.cmd_path",
                "must not be empty",
            ));
        }
        if self.identity_cache_invalidation.enabled()
            && self.identity_cache_invalidation.foreground_check_interval == 0
        {
            return Err(EngineError::invalid_config(
                "identity_cache_invalidation.foreground_check_interval",
                "must be > 0",
            ));
        }
        Ok(())
    }
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            backend: SpawnBackend::PosixSpawn,
            fd_policy: SpawnFdPolicy::CloexecOnly,
            timeout_ms: None,
            max_output: 1024 * 1024,
            allow_zero_max_output: false,
        }
    }
}

impl Default for IdentityCacheConfig {
    fn default() -> Self {
        Self {
            provider_mode: IdentityCacheProviderMode::Disabled,
            cmd_path: PathBuf::new(),
            user_id: 0,
        }
    }
}

impl Default for IdentityCacheInvalidationConfig {
    fn default() -> Self {
        Self {
            packages_xml_path: PathBuf::new(),
            foreground_check_interval: 1,
            debounce_ms: 0,
        }
    }
}

impl IdentityCacheInvalidationConfig {
    pub fn enabled(&self) -> bool {
        !self.packages_xml_path.as_os_str().is_empty()
    }
}
