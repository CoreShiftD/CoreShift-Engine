use coreshift_core::reactor::{Fd, Reactor, Token};
use coreshift_core::spawn::{ExitStatus, SpawnBackend, SpawnFdPolicy};
use coreshift_engine::config::{
    ExecConfig, IdentityCacheConfig, IdentityCacheInvalidationConfig, IdentityCacheProviderMode,
};
use coreshift_engine::dispatch::{Dispatcher, EngineAction};
use coreshift_engine::events::EngineEvent;
use coreshift_engine::exec::ExecRunner;
use coreshift_engine::services::foreground::cache::{
    PackageProviderSource, PackageUidEntry, PackageUidProvider, PackageUidSnapshot,
    UidPackageState, parse_cmd_package_list_stdout,
};
use coreshift_engine::services::foreground::cgroup_v1::MapPidUidResolver;
use coreshift_engine::services::foreground::{
    AppUidFilter, AutoForegroundSource, CgroupV1CpusetSource, CgroupV2EventsSource,
    CgroupV2Populated, ForegroundCandidate, ForegroundCandidateFilter, ForegroundManager,
    ForegroundPipeline, ForegroundResolveReport, ForegroundResolverState, ForegroundSource,
    ForegroundSourceKind, ForegroundUpdate, PackageFileStat, PackageFileStatProvider,
    UidPackageCache, V1PayloadCache, candidate_uid_roots_from_proc_mounts,
    candidate_uid_roots_from_proc_mounts_path, find_cgroup2_mount, parse_cgroup_events_populated,
    parse_top_activity_package, parse_uid_dir_name, resolve_activity_stdout,
    resolve_after_v1_unavailable_lazy, resolve_after_v1_v2_unavailable_lazy,
    resolve_v1_payload_with_uid_resolver,
};
use coreshift_engine::services::identity::{
    ResolvedIdentity, ResolvedIdentitySource, ResolvedIdentityState,
};
use coreshift_engine::services::identity_cache::{
    IdentityCacheFingerprint, IdentityCacheInvalidator,
};
use coreshift_engine::services::socket::{
    bind_abstract_stream_socket, connect_abstract_stream_socket,
};
use coreshift_engine::services::watch::EngineWatch;
use coreshift_engine::services::{Service, SystemServices};
use coreshift_engine::state::{EngineState, Reducer};
use coreshift_engine::{EngineConfig, EngineError, EngineRuntime};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn unique_name(prefix: &str) -> String {
    format!(
        "coreshift_engine_{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn temp_dir(prefix: &str) -> PathBuf {
    let path = std::env::temp_dir().join(unique_name(prefix));
    std::fs::create_dir(&path).unwrap();
    path
}

fn exec_config() -> ExecConfig {
    ExecConfig {
        backend: SpawnBackend::PosixSpawn,
        fd_policy: SpawnFdPolicy::CloexecOnly,
        timeout_ms: Some(2_000),
        max_output: 64 * 1024,
        allow_zero_max_output: false,
    }
}

fn runtime_config(_prefix: &str) -> EngineConfig {
    let mut config = EngineConfig::new(exec_config());
    config.identity_cache = IdentityCacheConfig {
        provider_mode: IdentityCacheProviderMode::CmdPackageList,
        cmd_path: std::env::temp_dir().join(unique_name("missing_cmd_path")),
        user_id: 0,
    };
    config.identity_cache_invalidation =
        invalidation_config(std::env::temp_dir().join(unique_name("packages_xml")));
    config
}

fn fake_cmd_path(prefix: &str, stdout: &str) -> PathBuf {
    let path = std::env::temp_dir().join(unique_name(prefix));
    std::fs::write(&path, format!("#!/bin/sh\nprintf '%s' '{}'\n", stdout)).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).unwrap();
    path
}

fn invalidation_config(packages_xml_path: PathBuf) -> IdentityCacheInvalidationConfig {
    IdentityCacheInvalidationConfig {
        packages_xml_path,
        foreground_check_interval: 2,
        debounce_ms: 1_000,
    }
}

struct FakePackageProvider {
    snapshot: PackageUidSnapshot,
}

impl PackageUidProvider for FakePackageProvider {
    fn load(&self) -> Result<PackageUidSnapshot, EngineError> {
        Ok(self.snapshot.clone())
    }
}

struct FakePackageStat {
    calls: u32,
    stats: Vec<Result<PackageFileStat, EngineError>>,
}

impl PackageFileStatProvider for FakePackageStat {
    fn stat_package_marker(
        &mut self,
        _path: &std::path::Path,
    ) -> Result<PackageFileStat, EngineError> {
        self.calls += 1;
        self.stats.remove(0)
    }
}

fn fake_snapshot(
    source: PackageProviderSource,
    coherent: bool,
    entries: Vec<(&str, u32)>,
) -> PackageUidSnapshot {
    PackageUidSnapshot {
        entries: entries
            .into_iter()
            .map(|(package, uid)| PackageUidEntry {
                package: package.to_string(),
                uid,
                base_apk_path: None,
            })
            .collect(),
        source,
        coherent,
    }
}

struct SequenceForegroundSource {
    kind: ForegroundSourceKind,
    responses: VecDeque<Option<ForegroundCandidate>>,
    watch_hint_paths: Vec<PathBuf>,
}

struct PriorityForegroundSource {
    watch_hint_paths: Vec<PathBuf>,
    priority_path: PathBuf,
    priority_key: u64,
    priority_fd: Option<Fd>,
}

struct UnavailableForegroundSource {
    kind: ForegroundSourceKind,
    watch_hint_paths: Vec<PathBuf>,
}

impl PriorityForegroundSource {
    fn new(watch_hint_path: PathBuf, priority_path: PathBuf) -> Self {
        Self {
            watch_hint_paths: vec![watch_hint_path],
            priority_path,
            priority_key: 1,
            priority_fd: Some(Fd::eventfd(0).unwrap()),
        }
    }

    fn replace_priority_fd(&mut self) {
        self.priority_key = self.priority_key.saturating_add(1);
        self.priority_fd = Some(Fd::eventfd(0).unwrap());
    }

    fn clear_priority_fd(&mut self) {
        self.priority_key = 0;
        self.priority_fd = None;
    }
}

impl ForegroundSource for PriorityForegroundSource {
    fn kind(&self) -> ForegroundSourceKind {
        ForegroundSourceKind::CgroupV2
    }

    fn poll_current(&mut self) -> Result<Option<ForegroundCandidate>, EngineError> {
        Ok(None)
    }

    fn handle_fs_event(
        &mut self,
        _path: &std::path::Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        Ok(None)
    }

    fn watch_hint_paths(&self) -> &[PathBuf] {
        &self.watch_hint_paths
    }

    fn register_priority_fds(
        &self,
        reactor: &mut Reactor,
        registered_paths: &BTreeSet<PathBuf>,
    ) -> Result<Vec<(Token, PathBuf)>, EngineError> {
        let Some(priority_fd) = self.priority_fd.as_ref() else {
            return Ok(Vec::new());
        };
        if registered_paths.contains(&self.priority_path) {
            return Ok(Vec::new());
        }
        Ok(vec![(
            reactor.add_priority(priority_fd)?,
            self.priority_path.clone(),
        )])
    }

    fn priority_hint_paths(&self) -> Vec<PathBuf> {
        if self.priority_key == 0 {
            Vec::new()
        } else {
            vec![self.priority_path.clone()]
        }
    }

    fn priority_hint_keys(&self) -> Vec<(PathBuf, u64)> {
        if self.priority_key == 0 {
            Vec::new()
        } else {
            vec![(self.priority_path.clone(), self.priority_key)]
        }
    }
}

impl SequenceForegroundSource {
    fn new(responses: Vec<Option<ForegroundCandidate>>) -> Self {
        Self {
            kind: ForegroundSourceKind::CgroupV1,
            responses: responses.into(),
            watch_hint_paths: vec![PathBuf::from("/tmp/cgroup.procs")],
        }
    }

    fn with_watch_paths(
        responses: Vec<Option<ForegroundCandidate>>,
        watch_hint_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            kind: ForegroundSourceKind::CgroupV1,
            responses: responses.into(),
            watch_hint_paths,
        }
    }
}

impl ForegroundSource for SequenceForegroundSource {
    fn kind(&self) -> ForegroundSourceKind {
        self.kind
    }

    fn poll_current(&mut self) -> Result<Option<ForegroundCandidate>, EngineError> {
        Ok(self.responses.pop_front().flatten())
    }

    fn handle_fs_event(
        &mut self,
        _path: &std::path::Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        Ok(self.responses.pop_front().flatten())
    }

    fn watch_hint_paths(&self) -> &[PathBuf] {
        &self.watch_hint_paths
    }
}

impl ForegroundSource for UnavailableForegroundSource {
    fn kind(&self) -> ForegroundSourceKind {
        self.kind
    }

    fn poll_current(&mut self) -> Result<Option<ForegroundCandidate>, EngineError> {
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "source unavailable").into())
    }

    fn handle_fs_event(
        &mut self,
        _path: &std::path::Path,
    ) -> Result<Option<ForegroundCandidate>, EngineError> {
        self.poll_current()
    }

    fn watch_hint_paths(&self) -> &[PathBuf] {
        &self.watch_hint_paths
    }

    fn is_available(&self) -> bool {
        false
    }
}

fn foreground_candidate(
    source: ForegroundSourceKind,
    pid: Option<i32>,
    uid: Option<u32>,
) -> ForegroundCandidate {
    ForegroundCandidate {
        source,
        pid,
        uid,
        package: None,
        identity_resolved: false,
    }
}

fn cache_from_entries(entries: Vec<(&str, u32)>) -> UidPackageCache {
    let provider = FakePackageProvider {
        snapshot: fake_snapshot(PackageProviderSource::CmdPackageList, true, entries),
    };
    UidPackageCache::warm_from(&provider).unwrap()
}

fn resolver_state(entries: Vec<(&str, u32)>) -> ForegroundResolverState {
    ForegroundResolverState::new(
        cache_from_entries(entries),
        BTreeSet::new(),
        AppUidFilter {
            modulus: 100_000,
            min_app_id: 10_000,
        },
        None,
    )
}

fn apply_event_path(
    events: Vec<EngineEvent>,
    services: &mut SystemServices,
    state: &mut EngineState,
) {
    for event in events {
        Reducer::apply(&event, state);
        for action in Dispatcher::dispatch(&event) {
            for service_event in services.perform(action).unwrap() {
                Reducer::apply(&service_event, state);
            }
        }
    }
}

fn test_invalidator(prefix: &str) -> (IdentityCacheInvalidator, PathBuf) {
    let root = temp_dir(prefix);
    let packages = root.join("packages.xml");
    std::fs::write(&packages, "packages").unwrap();
    (
        IdentityCacheInvalidator::new(invalidation_config(packages)),
        root,
    )
}

#[test]
fn default_config_builds() {
    let config = EngineConfig::default();
    let mut runtime = EngineRuntime::new(config);
    runtime.start().unwrap();
    runtime.shutdown();
}

#[test]
fn engine_default_identity_config_has_no_android_paths() {
    let config = EngineConfig::default();

    assert_eq!(
        config.identity_cache.provider_mode,
        IdentityCacheProviderMode::Disabled
    );
    assert!(config.identity_cache.cmd_path.as_os_str().is_empty());
    assert!(
        config
            .identity_cache_invalidation
            .packages_xml_path
            .as_os_str()
            .is_empty()
    );
}

#[test]
fn engine_default_identity_runtime_selects_no_hidden_paths() {
    let config = EngineConfig::new(exec_config());
    let mut runtime = EngineRuntime::new(config);

    runtime.start().unwrap();

    assert_eq!(runtime.identity_cache_state().source, None);
    assert_eq!(runtime.identity_cache_state().count, 0);
    assert!(runtime.identity_cache_state().last_cache_error.is_none());
    assert!(
        runtime
            .identity_cache_invalidator()
            .watch_hint_paths()
            .is_empty()
    );
    runtime.shutdown();
}

#[test]
fn engine_config_validate_rejects_invalid_runtime_config() {
    let mut config = runtime_config("invalid_zero_output");
    config.exec.max_output = 0;
    let err = config.validate().unwrap_err();
    assert!(matches!(
        err,
        EngineError::InvalidConfig {
            field: "exec.max_output",
            ..
        }
    ));

    config.exec.allow_zero_max_output = true;
    config.identity_cache_invalidation.foreground_check_interval = 0;
    let err = EngineRuntime::new(config).start().unwrap_err();
    assert!(matches!(
        err,
        EngineError::InvalidConfig {
            field: "identity_cache_invalidation.foreground_check_interval",
            ..
        }
    ));
}

#[test]
fn runtime_startup_warms_cache_from_cmd_fallback_path() {
    let cmd = fake_cmd_path(
        "runtime_cmd_start",
        "package:com.example.app uid:10123\npackage:com.example.two uid:10124\npackage:com.example.three uid:10125\npackage:com.example.four uid:10126\npackage:com.example.five uid:10127\n",
    );
    let mut config = runtime_config("runtime_external_ipc");
    config.identity_cache.cmd_path = cmd.clone();

    let mut runtime = EngineRuntime::new(config);
    runtime.start().unwrap();

    assert_eq!(
        runtime.identity_cache().uid_for_package("com.example.app"),
        Some(10_123)
    );
    assert_eq!(
        runtime.identity_cache_state().source,
        Some(PackageProviderSource::CmdPackageList)
    );
    assert_eq!(runtime.identity_cache_state().count, 5);
    assert!(runtime.identity_cache_state().coherent);
    runtime.shutdown();
    let _ = std::fs::remove_file(cmd);
}

#[test]
fn runtime_cache_warmup_failure_does_not_fail_start() {
    let mut config = runtime_config("runtime_cache_fail");
    config.identity_cache.cmd_path = std::env::temp_dir().join(unique_name("missing_cmd"));

    let mut runtime = EngineRuntime::new(config);
    runtime.start().unwrap();

    assert!(runtime.identity_cache_state().last_cache_error.is_some());
    assert_eq!(runtime.identity_cache_state().count, 0);
    assert_eq!(runtime.identity_cache_state().source, None);
    runtime.shutdown();
}

#[test]
fn resolve_identity_after_start_uses_warmed_cache() {
    let cmd = fake_cmd_path(
        "runtime_cmd_resolve",
        "package:com.example.app uid:10123\npackage:com.example.two uid:10124\npackage:com.example.three uid:10125\npackage:com.example.four uid:10126\npackage:com.example.five uid:10127\n",
    );
    let mut config = runtime_config("runtime_resolve_ipc");
    config.identity_cache.cmd_path = cmd.clone();
    let mut runtime = EngineRuntime::new(config);
    runtime.start().unwrap();
    let mut services = runtime.system_services();

    let events = services
        .perform(EngineAction::ResolveIdentity {
            pid: None,
            uid: Some(10_123),
        })
        .unwrap();

    assert!(matches!(
        events.as_slice(),
        [EngineEvent::IdentityResolved(identity)]
            if identity.package.as_deref() == Some("com.example.app")
                && identity.state == ResolvedIdentityState::Exact
    ));
    runtime.shutdown();
    let _ = std::fs::remove_file(cmd);
}

#[test]
fn refresh_identity_cache_updates_cache() {
    let cmd = fake_cmd_path("runtime_cmd_refresh", "package:com.example.one uid:10123\n");
    let mut config = runtime_config("runtime_refresh_ipc");
    config.identity_cache.cmd_path = cmd.clone();
    let mut runtime = EngineRuntime::new(config);
    runtime.start().unwrap();
    assert_eq!(
        runtime.identity_cache().uid_for_package("com.example.two"),
        None
    );

    std::fs::write(
            &cmd,
            "#!/bin/sh\nprintf '%s' 'package:com.example.one uid:10123\npackage:com.example.two uid:10124\n'\n",
        )
        .unwrap();
    runtime.refresh_identity_cache();

    assert_eq!(
        runtime.identity_cache().uid_for_package("com.example.two"),
        Some(10_124)
    );
    assert_eq!(runtime.identity_cache_state().count, 2);
    runtime.shutdown();
    let _ = std::fs::remove_file(cmd);
}

#[test]
fn failed_refresh_preserves_dirty_state() {
    let root = temp_dir("refresh_dirty_fail");
    let packages = root.join("packages.xml");
    std::fs::write(&packages, "one").unwrap();
    let cmd = fake_cmd_path("refresh_dirty_cmd", "package:com.example.one uid:10123\n");
    let mut config = runtime_config("refresh_dirty_ipc");
    config.identity_cache.cmd_path = cmd.clone();
    config.identity_cache_invalidation = invalidation_config(packages.clone());
    let mut runtime = EngineRuntime::new(config);
    runtime.start().unwrap();

    std::fs::write(&packages, "one-two").unwrap();
    runtime.mark_identity_cache_foreground_candidate();
    runtime.mark_identity_cache_foreground_candidate();
    assert!(runtime.should_refresh_identity_cache_now());
    let _ = std::fs::remove_file(&cmd);

    runtime.refresh_identity_cache();

    assert!(runtime.identity_cache_state().last_cache_error.is_some());
    assert!(runtime.should_refresh_identity_cache_now());
    runtime.shutdown();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn identity_cache_fingerprint_detects_file_change() {
    let root = temp_dir("fingerprint");
    let packages = root.join("packages.xml");
    std::fs::write(&packages, "one").unwrap();
    let first = IdentityCacheFingerprint::from_path(&packages).unwrap();

    std::fs::write(&packages, "one-two").unwrap();
    let second = IdentityCacheFingerprint::from_path(&packages).unwrap();

    assert_ne!(first, second);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn foreground_interval_triggers_packages_xml_stat_check() {
    let root = temp_dir("fg_interval");
    let packages = root.join("packages.xml");
    std::fs::write(&packages, "one").unwrap();
    let mut invalidator = IdentityCacheInvalidator::new(invalidation_config(packages.clone()));

    invalidator.mark_foreground_candidate();
    std::fs::write(&packages, "one-two").unwrap();
    assert!(!invalidator.should_refresh_now());

    invalidator.mark_foreground_candidate();

    assert!(invalidator.should_refresh_now());
    assert!(invalidator.consume_dirty().packages_xml_changed);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn packages_xml_appearing_after_missing_marks_dirty() {
    let root = temp_dir("packages_appears");
    let packages_dir = root.join("system");
    let packages = packages_dir.join("packages.xml");
    let mut invalidator = IdentityCacheInvalidator::new(invalidation_config(packages.clone()));

    std::fs::create_dir_all(packages_dir).unwrap();
    std::fs::write(&packages, "one").unwrap();

    assert!(invalidator.check_packages_xml().unwrap());
    assert!(invalidator.consume_dirty().packages_xml_changed);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn consume_dirty_clears_dirty_state() {
    let root = temp_dir("consume_dirty");
    let packages = root.join("packages.xml");
    std::fs::write(&packages, "one").unwrap();
    let mut invalidator = IdentityCacheInvalidator::new(invalidation_config(packages.clone()));

    std::fs::write(&packages, "one-two").unwrap();
    assert!(invalidator.check_packages_xml().unwrap());
    assert!(invalidator.should_refresh_now());

    let dirty = invalidator.consume_dirty();

    assert!(dirty.packages_xml_changed);
    assert!(!invalidator.should_refresh_now());
    assert_eq!(invalidator.consume_dirty(), Default::default());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_runner_can_run_true_with_explicit_backend() {
    let runner = ExecRunner::new(exec_config());
    let output = runner.run(vec!["/bin/true".to_string()]).unwrap();
    assert_eq!(output.status, Some(ExitStatus::Exited(0)));
}

#[test]
fn exec_runner_can_run_echo_with_explicit_backend() {
    let runner = ExecRunner::new(exec_config());
    let output = runner
        .run_capture_stdout(vec!["/bin/echo".to_string(), "engine".to_string()])
        .unwrap();
    assert_eq!(output.status, Some(ExitStatus::Exited(0)));
    assert_eq!(output.stdout, b"engine\n");
}

#[test]
fn reducer_start_stop_is_deterministic() {
    let mut state = EngineState::default();

    Reducer::apply(&EngineEvent::RuntimeStarted, &mut state);
    assert!(state.started);

    Reducer::apply(&EngineEvent::RuntimeStopped, &mut state);
    assert!(!state.started);
}

#[test]
fn dispatcher_emits_no_policy_actions() {
    assert!(Dispatcher::dispatch(&EngineEvent::RuntimeStarted).is_empty());
    assert!(Dispatcher::dispatch(&EngineEvent::RuntimeStopped).is_empty());
}

#[test]
fn run_exec_action_executes_true() {
    let mut services = SystemServices::new(ExecRunner::new(exec_config()));
    let events = services
        .perform(EngineAction::RunExec {
            argv: vec!["/bin/true".to_string()],
            capture_stdout: false,
        })
        .unwrap();
    assert!(matches!(
        events.as_slice(),
        [EngineEvent::ExecCompleted { output }]
            if output.status == Some(ExitStatus::Exited(0))
    ));
}

#[test]
fn service_failed_records_error() {
    let mut state = EngineState::default();
    Reducer::apply(
        &EngineEvent::ServiceFailed {
            error: EngineError::NotStarted,
        },
        &mut state,
    );
    assert_eq!(state.last_error.as_deref(), Some("runtime not started"));
}

#[test]
fn reducer_records_identity_resolved() {
    let mut state = EngineState::default();
    let identity = ResolvedIdentity {
        pid: Some(7),
        uid: Some(10_123),
        package: Some("example.app".to_string()),
        state: ResolvedIdentityState::Exact,
        source: ResolvedIdentitySource::CacheOnly,
    };

    Reducer::apply(&EngineEvent::IdentityResolved(identity.clone()), &mut state);

    assert_eq!(state.last_identity, Some(identity));
}

#[test]
fn cgroup_v1_first_valid_pid_wins() {
    let root = temp_dir("v1_first_root");
    let proc_root = temp_dir("v1_first_proc");
    std::fs::write(root.join("cgroup.procs"), "10\n").unwrap();

    let filter = ForegroundCandidateFilter::default();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(10, 10_123)]));
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        filter,
        resolver,
    );

    let candidate = source.poll_current().unwrap().unwrap();
    assert_eq!(candidate.source, ForegroundSourceKind::CgroupV1);
    assert_eq!(candidate.pid, Some(10));
    assert_eq!(candidate.uid, Some(10_123));

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v1_blocked_first_pid_skips_to_next() {
    let root = temp_dir("v1_skip_root");
    let proc_root = temp_dir("v1_skip_proc");
    std::fs::write(root.join("cgroup.procs"), "11\n12\n").unwrap();

    let mut filter = ForegroundCandidateFilter::default();
    filter.blocked_uids.insert(10_001);
    let resolver = MapPidUidResolver::new(BTreeMap::from([(11, 10_001), (12, 10_002)]));
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        filter,
        resolver,
    );

    let candidate = source.poll_current().unwrap().unwrap();
    assert_eq!(candidate.pid, Some(12));
    assert_eq!(candidate.uid, Some(10_002));

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v1_cache_hit_uses_warmed_cache_without_provider_fallback() {
    let root = temp_dir("v1_cache_root");
    let proc_root = temp_dir("v1_cache_proc");
    std::fs::write(root.join("cgroup.procs"), "21\n").unwrap();

    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("example.app", 10_123)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    assert_eq!(
        cache.uid_state(10_123),
        UidPackageState::Exact("example.app".to_string())
    );

    let resolver = MapPidUidResolver::new(BTreeMap::from([(21, 10_123)]));
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    )
    .with_package_cache(cache);
    let candidate = source.poll_current().unwrap().unwrap();
    assert_eq!(candidate.uid, Some(10_123));
    assert_eq!(candidate.package.as_deref(), Some("example.app"));
    assert!(candidate.identity_resolved);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v1_cache_miss_resolves_package_from_cmdline() {
    let root = temp_dir("v1_cmdline_miss_root");
    let proc_root = temp_dir("v1_cmdline_miss_proc");
    std::fs::write(root.join("cgroup.procs"), "42\n").unwrap();
    std::fs::create_dir_all(proc_root.join("42")).unwrap();
    std::fs::write(proc_root.join("42/cmdline"), b"missing.app\0:service\0").unwrap();

    let provider = FakePackageProvider {
        snapshot: fake_snapshot(PackageProviderSource::CmdPackageList, true, vec![]),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(42, 10_042)]));
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    )
    .with_package_cache(cache);

    let candidate = source.poll_current().unwrap().unwrap();

    assert_eq!(candidate.pid, Some(42));
    assert_eq!(candidate.uid, Some(10_042));
    assert_eq!(candidate.package.as_deref(), Some("missing.app"));
    assert!(candidate.identity_resolved);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v1_ambiguous_uid_resolves_matching_cmdline_package() {
    let root = temp_dir("v1_cmdline_ambiguous_root");
    let proc_root = temp_dir("v1_cmdline_ambiguous_proc");
    std::fs::write(root.join("cgroup.procs"), "43\n").unwrap();
    std::fs::create_dir_all(proc_root.join("43")).unwrap();
    std::fs::write(proc_root.join("43/cmdline"), b"two.app\0").unwrap();

    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("one.app", 10_043), ("two.app", 10_043)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(43, 10_043)]));
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    )
    .with_package_cache(cache);

    let candidate = source.poll_current().unwrap().unwrap();

    assert_eq!(candidate.package.as_deref(), Some("two.app"));
    assert!(candidate.identity_resolved);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v1_skips_termux_shell_process_before_package_cmdline() {
    let root = temp_dir("v1_cmdline_shell_root");
    let proc_root = temp_dir("v1_cmdline_shell_proc");
    std::fs::write(root.join("cgroup.procs"), "44\n45\n").unwrap();
    std::fs::create_dir_all(proc_root.join("44")).unwrap();
    std::fs::create_dir_all(proc_root.join("45")).unwrap();
    std::fs::write(
        proc_root.join("44/cmdline"),
        b"/data/data/com.termux/files/usr/bin/bash\0",
    )
    .unwrap();
    std::fs::write(proc_root.join("45/cmdline"), b"com.openai.chatgpt\0").unwrap();

    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("com.termux", 10_143), ("com.openai.chatgpt", 10_144)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(44, 10_143), (45, 10_144)]));
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    )
    .with_package_cache(cache);

    let candidate = source.poll_current().unwrap().unwrap();

    assert_eq!(candidate.pid, Some(45));
    assert_eq!(candidate.uid, Some(10_144));
    assert_eq!(candidate.package.as_deref(), Some("com.openai.chatgpt"));
    assert_ne!(
        candidate.package.as_deref(),
        Some("/data/data/com.termux/files/usr/bin/bash")
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v1_non_termux_shell_process_can_resolve_from_uid_cache() {
    let root = temp_dir("v1_cmdline_non_termux_shell_root");
    let proc_root = temp_dir("v1_cmdline_non_termux_shell_proc");
    std::fs::write(root.join("cgroup.procs"), "46\n").unwrap();
    std::fs::create_dir_all(proc_root.join("46")).unwrap();
    std::fs::write(proc_root.join("46/cmdline"), b"/system/bin/sh\0").unwrap();

    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("other.shell.host", 10_146)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(46, 10_146)]));
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    )
    .with_package_cache(cache);

    let candidate = source.poll_current().unwrap().unwrap();

    assert_eq!(candidate.pid, Some(46));
    assert_eq!(candidate.package.as_deref(), Some("other.shell.host"));

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v1_empty_or_invalid_returns_none() {
    let root = temp_dir("v1_empty_root");
    let proc_root = temp_dir("v1_empty_proc");
    std::fs::write(root.join("cgroup.procs"), "\n").unwrap();

    let filter = ForegroundCandidateFilter {
        allow_system_uids: true,
        ..Default::default()
    };
    let resolver = MapPidUidResolver::new(BTreeMap::new());
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        filter,
        resolver,
    );

    assert!(source.poll_current().unwrap().is_none());

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v1_invalid_payload_is_unusable() {
    let root = temp_dir("v1_invalid_root");
    let proc_root = temp_dir("v1_invalid_proc");
    std::fs::write(root.join("cgroup.procs"), "not-a-pid\n999\n").unwrap();

    let resolver = MapPidUidResolver::new(BTreeMap::new());
    let mut source = CgroupV1CpusetSource::with_resolver(
        root.join("cgroup.procs"),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    );

    assert!(matches!(
        source.poll_current().unwrap_err(),
        EngineError::Io(err) if err.kind() == std::io::ErrorKind::InvalidData
    ));

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn cgroup_v2_events_parser_reads_populated_state() {
    assert_eq!(
        parse_cgroup_events_populated(b"populated 1\nfrozen 0\n"),
        CgroupV2Populated::Active
    );
    assert_eq!(
        parse_cgroup_events_populated(b"populated 0\n"),
        CgroupV2Populated::Inactive
    );
    assert_eq!(
        parse_cgroup_events_populated(b"frozen 0\n"),
        CgroupV2Populated::Unknown
    );
    assert_eq!(
        parse_cgroup_events_populated(b"populated x\n"),
        CgroupV2Populated::Unknown
    );
}

#[test]
fn cgroup_v2_uid_dir_parser_accepts_android_forms() {
    assert_eq!(
        parse_uid_dir_name(std::path::Path::new("uid_10123")),
        Some(10_123)
    );
    assert_eq!(
        parse_uid_dir_name(std::path::Path::new("u0_a123")),
        Some(10_123)
    );
    assert_eq!(
        parse_uid_dir_name(std::path::Path::new("u10_a123")),
        Some(1_010_123)
    );
    assert_eq!(parse_uid_dir_name(std::path::Path::new("pid_1")), None);
}

#[test]
fn cgroup2_mount_parser_finds_unified_mount_and_candidate_roots() {
    let mounts = "tmpfs /tmp tmpfs rw 0 0\nnone /sys/fs/cgroup cgroup2 rw,nosuid 0 0\n";

    assert_eq!(
        find_cgroup2_mount(mounts),
        Some(std::path::PathBuf::from("/sys/fs/cgroup"))
    );
    assert_eq!(
        candidate_uid_roots_from_proc_mounts(mounts),
        vec![
            std::path::PathBuf::from("/sys/fs/cgroup"),
            std::path::PathBuf::from("/sys/fs/cgroup/apps")
        ]
    );
}

#[test]
fn cgroup2_mount_parser_reads_parameterized_mounts_path() {
    let root = temp_dir("mounts_path");
    let mounts_path = root.join("mounts");
    std::fs::write(&mounts_path, "none /cg cgroup2 rw 0 0\n").unwrap();

    assert_eq!(
        candidate_uid_roots_from_proc_mounts_path(&mounts_path).unwrap(),
        vec![
            std::path::PathBuf::from("/cg"),
            std::path::PathBuf::from("/cg/apps")
        ]
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_startup_scan_resolves_populated_uid() {
    let root = temp_dir("v2_scan_root");
    let uid_dir = root.join("uid_10123");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(uid_dir.join("cgroup.events"), "populated 1\n").unwrap();

    let filter = ForegroundCandidateFilter {
        uid_remainder_filter: Some(coreshift_engine::services::foreground::UidRemainderFilter {
            modulus: 100_000,
            min_remainder: 10_000,
        }),
        ..Default::default()
    };
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], filter)
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));

    let candidate = source.poll_current().unwrap().unwrap();
    assert_eq!(candidate.source, ForegroundSourceKind::CgroupV2);
    assert_eq!(candidate.uid, Some(10_123));
    assert_eq!(candidate.package.as_deref(), Some("example.app"));
    assert!(candidate.identity_resolved);
    assert_eq!(source.watch_hint_paths(), std::slice::from_ref(&root));
    assert_eq!(
        source.priority_hint_paths(),
        vec![uid_dir.join("cgroup.events")]
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_ignores_non_app_uid() {
    let root = temp_dir("v2_non_app_root");
    let uid_dir = root.join("uid_9999");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(uid_dir.join("cgroup.events"), "populated 1\n").unwrap();

    let filter = ForegroundCandidateFilter {
        uid_remainder_filter: Some(coreshift_engine::services::foreground::UidRemainderFilter {
            modulus: 100_000,
            min_remainder: 10_000,
        }),
        ..Default::default()
    };
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], filter)
        .with_package_cache(cache_from_entries(vec![("system.app", 9_999)]));

    assert!(source.poll_current().unwrap().is_none());
    assert_eq!(source.uid_watch_count(), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_ambiguous_and_blocked_uid_are_skipped() {
    let root = temp_dir("v2_skip_root");
    for uid in [10_123, 10_124] {
        let uid_dir = root.join(format!("uid_{uid}"));
        std::fs::create_dir(&uid_dir).unwrap();
        std::fs::write(uid_dir.join("cgroup.events"), "populated 1\n").unwrap();
    }
    let mut filter = ForegroundCandidateFilter::default();
    filter.blocked_packages.insert("blocked.app".to_string());
    let cache = cache_from_entries(vec![
        ("ambiguous.one", 10_123),
        ("ambiguous.two", 10_123),
        ("blocked.app", 10_124),
    ]);
    let mut source =
        CgroupV2EventsSource::new(vec![root.clone()], filter).with_package_cache(cache);

    assert!(source.poll_current().unwrap().is_none());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_root_create_event_adds_uid_watch() {
    let root = temp_dir("v2_create_root");
    let uid_dir = root.join("uid_10123");
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    assert_eq!(source.uid_watch_count(), 0);

    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(uid_dir.join("cgroup.events"), "populated 1\n").unwrap();
    let candidate = source
        .handle_fs_event_with_mask(&uid_dir, 0x0000_0100)
        .unwrap()
        .unwrap();

    assert!(source.has_uid_watch(10_123));
    assert_eq!(candidate.package.as_deref(), Some("example.app"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_root_delete_event_removes_uid_watch() {
    let root = temp_dir("v2_delete_root");
    let uid_dir = root.join("uid_10123");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(uid_dir.join("cgroup.events"), "populated 1\n").unwrap();
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    assert!(source.has_uid_watch(10_123));

    std::fs::remove_dir_all(&uid_dir).unwrap();
    assert!(
        source
            .handle_fs_event_with_mask(&uid_dir, 0x0000_0200)
            .unwrap()
            .is_none()
    );

    assert!(!source.has_uid_watch(10_123));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_delete_event_removes_only_matching_duplicate_uid_path() {
    let root_one = temp_dir("v2_duplicate_delete_one");
    let root_two = temp_dir("v2_duplicate_delete_two");
    let uid_one = root_one.join("uid_10123");
    let uid_two = root_two.join("uid_10123");
    std::fs::create_dir(&uid_one).unwrap();
    std::fs::create_dir(&uid_two).unwrap();
    std::fs::write(uid_one.join("cgroup.events"), "populated 1\n").unwrap();
    std::fs::write(uid_two.join("cgroup.events"), "populated 1\n").unwrap();
    let mut source =
        CgroupV2EventsSource::new(vec![root_one.clone(), root_two.clone()], Default::default())
            .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));

    assert_eq!(source.uid_watch_count(), 2);
    assert!(source.has_uid_watch_path(&uid_one.join("cgroup.events")));
    assert!(source.has_uid_watch_path(&uid_two.join("cgroup.events")));

    std::fs::remove_dir_all(&uid_two).unwrap();
    assert!(
        source
            .handle_fs_event_with_mask(&uid_two, 0x0000_0200)
            .unwrap()
            .is_none()
    );

    assert_eq!(source.uid_watch_count(), 1);
    assert!(source.has_uid_watch_path(&uid_one.join("cgroup.events")));
    assert!(!source.has_uid_watch_path(&uid_two.join("cgroup.events")));
    assert!(source.has_uid_watch(10_123));

    let _ = std::fs::remove_dir_all(root_one);
    let _ = std::fs::remove_dir_all(root_two);
}

#[test]
fn cgroup_v2_watch_mask_includes_stale_root_masks() {
    let root = temp_dir("v2_watch_mask");
    let source = CgroupV2EventsSource::new(vec![root.clone()], Default::default());
    let mask = source.watch_hint_mask(&root);

    assert_ne!(mask & 0x0000_0400, 0);
    assert_ne!(mask & 0x0000_0800, 0);
    assert_ne!(mask & 0x0000_8000, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_empty_root_is_unavailable() {
    let root = temp_dir("v2_empty_root");
    let source = CgroupV2EventsSource::new(vec![root.clone()], Default::default());

    assert!(!source.is_available());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_uid_layout_without_cgroup_events_is_unavailable() {
    let root = temp_dir("v2_missing_events_root");
    let uid_dir = root.join("uid_10123");
    std::fs::create_dir(&uid_dir).unwrap();
    let source = CgroupV2EventsSource::new(vec![root.clone()], Default::default());

    assert!(!source.is_available());
    assert_eq!(source.uid_watch_count(), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_uid_layout_with_inactive_events_is_available() {
    let root = temp_dir("v2_inactive_available_root");
    let uid_dir = root.join("uid_10123");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(uid_dir.join("cgroup.events"), "populated 0\n").unwrap();
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));

    assert!(source.is_available());
    assert_eq!(source.uid_watch_count(), 1);
    assert!(source.poll_current().unwrap().is_none());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_populated_zero_keeps_last_real_candidate() {
    let root = temp_dir("v2_clear_root");
    let uid_dir = root.join("uid_10123");
    let events_path = uid_dir.join("cgroup.events");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 1\n").unwrap();
    let source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    let mut manager = ForegroundManager::new(source);

    assert!(matches!(
        manager.poll_changed().unwrap(),
        Some(ForegroundUpdate::Active(_))
    ));
    std::fs::write(&events_path, "populated 0\n").unwrap();

    assert!(
        manager
            .handle_priority_event_changed(&events_path)
            .unwrap()
            .is_none()
    );
    assert!(
        matches!(manager.last_payload(), Some(candidate) if candidate.package.as_deref() == Some("example.app"))
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_repeated_priority_active_after_poll_emits_no_duplicate() {
    let root = temp_dir("v2_priority_active_dedupe_root");
    let uid_dir = root.join("uid_10123");
    let events_path = uid_dir.join("cgroup.events");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 1\n").unwrap();
    let source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    let mut manager = ForegroundManager::new(source);

    assert!(matches!(
        manager.poll_changed().unwrap(),
        Some(ForegroundUpdate::Active(_))
    ));
    assert!(
        manager
            .handle_priority_event_changed(&events_path)
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_repeated_priority_inactive_emits_no_duplicate_unknown() {
    let root = temp_dir("v2_priority_inactive_dedupe_root");
    let uid_dir = root.join("uid_10123");
    let events_path = uid_dir.join("cgroup.events");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 0\n").unwrap();
    let source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    let mut manager = ForegroundManager::new(source);

    assert!(manager.poll_changed().unwrap().is_none());
    assert!(
        manager
            .handle_priority_event_changed(&events_path)
            .unwrap()
            .is_none()
    );
    assert!(
        manager
            .handle_priority_event_changed(&events_path)
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_queue_overflow_rescans_roots() {
    let root = temp_dir("v2_overflow_root");
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    assert_eq!(source.uid_watch_count(), 0);

    let uid_dir = root.join("uid_10123");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(uid_dir.join("cgroup.events"), "populated 1\n").unwrap();
    assert!(
        source
            .handle_fs_event_with_mask(std::path::Path::new(""), 0x0000_4000)
            .unwrap()
            .is_none()
    );

    assert!(source.has_uid_watch(10_123));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_stale_root_event_marks_stale_without_panic() {
    let root = temp_dir("v2_stale_root");
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default());

    assert!(
        source
            .handle_fs_event_with_mask(&root, 0x0000_0400)
            .unwrap()
            .is_none()
    );
    assert!(source.is_root_stale(&root));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_recreated_same_path_events_file_gets_new_priority_key() {
    let root = temp_dir("v2_recreate_key_root");
    let uid_dir = root.join("uid_10123");
    let events_path = uid_dir.join("cgroup.events");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 1\n").unwrap();
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    let first_key = source
        .priority_hint_keys()
        .into_iter()
        .find_map(|(path, key)| (path == events_path).then_some(key))
        .unwrap();

    std::fs::remove_dir_all(&uid_dir).unwrap();
    assert!(
        source
            .handle_fs_event_with_mask(&uid_dir, 0x0000_0200)
            .unwrap()
            .is_none()
    );
    assert!(source.priority_hint_keys().is_empty());

    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 1\n").unwrap();
    let candidate = source
        .handle_fs_event_with_mask(&uid_dir, 0x0000_0100)
        .unwrap()
        .unwrap();
    let recreated_key = source
        .priority_hint_keys()
        .into_iter()
        .find_map(|(path, key)| (path == events_path).then_some(key))
        .unwrap();

    assert_eq!(candidate.package.as_deref(), Some("example.app"));
    assert_ne!(first_key, recreated_key);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_deleted_priority_event_does_not_error_and_removes_stale_watch() {
    let root = temp_dir("v2_deleted_priority_root");
    let uid_dir = root.join("uid_10123");
    let events_path = uid_dir.join("cgroup.events");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 1\n").unwrap();
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));

    assert!(source.has_uid_watch_path(&events_path));

    std::fs::remove_dir_all(&uid_dir).unwrap();
    assert!(
        source
            .handle_priority_event(&events_path)
            .unwrap()
            .is_none()
    );

    assert!(!source.has_uid_watch_path(&events_path));
    assert_eq!(source.uid_watch_count(), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_poll_current_removes_deleted_events_path_rescans_and_continues() {
    let root = temp_dir("v2_poll_stale_root");
    let stale_uid_dir = root.join("uid_10123");
    let remaining_uid_dir = root.join("uid_10124");
    let rescanned_uid_dir = root.join("uid_10125");
    let stale_events_path = stale_uid_dir.join("cgroup.events");
    let remaining_events_path = remaining_uid_dir.join("cgroup.events");
    let rescanned_events_path = rescanned_uid_dir.join("cgroup.events");
    std::fs::create_dir(&stale_uid_dir).unwrap();
    std::fs::create_dir(&remaining_uid_dir).unwrap();
    std::fs::write(&stale_events_path, "populated 1\n").unwrap();
    std::fs::write(&remaining_events_path, "populated 1\n").unwrap();
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![
            ("stale.app", 10_123),
            ("remaining.app", 10_124),
            ("rescanned.app", 10_125),
        ]));

    assert!(source.has_uid_watch_path(&stale_events_path));
    assert!(source.has_uid_watch_path(&remaining_events_path));

    std::fs::remove_dir_all(&stale_uid_dir).unwrap();
    std::fs::create_dir(&rescanned_uid_dir).unwrap();
    std::fs::write(&rescanned_events_path, "populated 1\n").unwrap();
    let candidate = source.poll_current().unwrap().unwrap();

    assert_eq!(candidate.package.as_deref(), Some("remaining.app"));
    assert!(!source.has_uid_watch_path(&stale_events_path));
    assert!(source.has_uid_watch_path(&remaining_events_path));
    assert!(source.has_uid_watch_path(&rescanned_events_path));

    std::fs::create_dir(&stale_uid_dir).unwrap();
    std::fs::write(&stale_events_path, "populated 1\n").unwrap();
    let replacement = source
        .handle_fs_event_with_mask(&stale_uid_dir, 0x0000_0100)
        .unwrap()
        .unwrap();
    assert_eq!(replacement.package.as_deref(), Some("stale.app"));
    assert!(source.has_uid_watch_path(&stale_events_path));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_v2_stale_priority_event_rescans_recreated_same_path() {
    let root = temp_dir("v2_stale_priority_recreate_root");
    let uid_dir = root.join("uid_10123");
    let events_path = uid_dir.join("cgroup.events");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 1\n").unwrap();
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    let first_key = source
        .priority_hint_keys()
        .into_iter()
        .find_map(|(path, key)| (path == events_path).then_some(key))
        .unwrap();

    std::fs::remove_dir_all(&uid_dir).unwrap();
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 1\n").unwrap();
    assert!(
        source
            .handle_stale_priority_event(&events_path)
            .unwrap()
            .is_none()
    );
    let recreated_key = source
        .priority_hint_keys()
        .into_iter()
        .find_map(|(path, key)| (path == events_path).then_some(key))
        .unwrap();

    assert!(source.has_uid_watch_path(&events_path));
    assert_ne!(first_key, recreated_key);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn watcher_refreshes_priority_registration_for_same_path_new_key() {
    let root = temp_dir("watch_priority_recreate");
    let trigger = root.join("trigger");
    let priority_path = root.join("uid_10123").join("cgroup.events");
    std::fs::write(&trigger, "initial").unwrap();
    let source = PriorityForegroundSource::new(trigger.clone(), priority_path.clone());
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, invalidator_root) = test_invalidator("watch_priority_recreate_invalid");
    let mut watcher = EngineWatch::new(pipeline, &invalidator).unwrap();
    let mut services = SystemServices::new(ExecRunner::new(exec_config()));
    let mut state = EngineState::default();
    let first_key = *watcher
        .foreground_priority_registration_keys()
        .get(&priority_path)
        .unwrap();

    assert_eq!(watcher.foreground_priority_token_count(), 1);

    watcher.foreground_source_mut().replace_priority_fd();
    std::fs::write(&trigger, "changed").unwrap();
    watcher
        .poll_once(250, &mut invalidator, &mut services, &mut state, || {})
        .unwrap();
    let recreated_key = *watcher
        .foreground_priority_registration_keys()
        .get(&priority_path)
        .unwrap();

    assert_eq!(watcher.foreground_priority_token_count(), 1);
    assert_ne!(first_key, recreated_key);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(invalidator_root);
}

#[test]
fn watcher_removes_stale_priority_registration_when_source_drops_path() {
    let root = temp_dir("watch_priority_drop");
    let trigger = root.join("trigger");
    let priority_path = root.join("uid_10123").join("cgroup.events");
    std::fs::write(&trigger, "initial").unwrap();
    let source = PriorityForegroundSource::new(trigger.clone(), priority_path.clone());
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, invalidator_root) = test_invalidator("watch_priority_drop_invalid");
    let mut watcher = EngineWatch::new(pipeline, &invalidator).unwrap();
    let mut services = SystemServices::new(ExecRunner::new(exec_config()));
    let mut state = EngineState::default();

    assert_eq!(watcher.foreground_priority_token_count(), 1);

    watcher.foreground_source_mut().clear_priority_fd();
    std::fs::write(&trigger, "changed").unwrap();
    watcher
        .poll_once(250, &mut invalidator, &mut services, &mut state, || {})
        .unwrap();

    assert_eq!(watcher.foreground_priority_token_count(), 0);
    assert!(watcher.foreground_priority_registration_keys().is_empty());

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(invalidator_root);
}

#[test]
fn watcher_v2_root_delete_drops_priority_registrations() {
    let root = temp_dir("watch_v2_root_delete");
    let uid_dir = root.join("uid_10123");
    let events_path = uid_dir.join("cgroup.events");
    std::fs::create_dir(&uid_dir).unwrap();
    std::fs::write(&events_path, "populated 1\n").unwrap();
    let mut source = CgroupV2EventsSource::new(vec![root.clone()], Default::default())
        .with_package_cache(cache_from_entries(vec![("example.app", 10_123)]));

    assert_eq!(source.priority_hint_keys().len(), 1);

    std::fs::remove_dir_all(&root).unwrap();
    assert!(
        source
            .handle_fs_event_with_mask(&root, 0x0000_0400)
            .unwrap()
            .is_none()
    );

    assert!(source.priority_hint_keys().is_empty());
    assert!(source.is_root_stale(&root));

    std::fs::create_dir(&root).unwrap();
    assert!(source.priority_hint_keys().is_empty());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn duplicate_in_modify_same_cgroup_procs_emits_once() {
    let root = temp_dir("dedupe_v1_same_root");
    let proc_root = temp_dir("dedupe_v1_same_proc");
    let cgroup_procs = root.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "10\n").unwrap();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(10, 10_123)]));
    let source = CgroupV1CpusetSource::with_resolver(
        cgroup_procs.clone(),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    );
    let mut manager = ForegroundManager::new(source);

    assert!(
        manager
            .handle_fs_event_changed(&cgroup_procs, 0)
            .unwrap()
            .is_some()
    );
    assert!(
        manager
            .handle_fs_event_changed(&cgroup_procs, 0)
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn changed_first_valid_pid_emits_again() {
    let root = temp_dir("dedupe_v1_changed_root");
    let proc_root = temp_dir("dedupe_v1_changed_proc");
    let cgroup_procs = root.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "10\n").unwrap();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(10, 10_123), (11, 10_124)]));
    let source = CgroupV1CpusetSource::with_resolver(
        cgroup_procs.clone(),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    );
    let mut manager = ForegroundManager::new(source);

    assert_eq!(
        manager
            .handle_fs_event_changed(&cgroup_procs, 0)
            .unwrap()
            .unwrap()
            .active()
            .unwrap()
            .pid,
        Some(10)
    );
    std::fs::write(&cgroup_procs, "11\n").unwrap();
    let changed = manager
        .handle_fs_event_changed(&cgroup_procs, 0)
        .unwrap()
        .unwrap()
        .active()
        .unwrap();
    assert_eq!(changed.pid, Some(11));
    assert_eq!(changed.uid, Some(10_124));

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn first_read_none_then_second_read_valid_emits() {
    let candidate = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(10), Some(10_123));
    let source = SequenceForegroundSource::new(vec![None, Some(candidate.clone())]);
    let mut manager = ForegroundManager::new(source);

    let changed = manager
        .handle_fs_event_changed(std::path::Path::new("/tmp/cgroup.procs"), 0)
        .unwrap();

    assert_eq!(changed.and_then(|update| update.active()), Some(candidate));
}

#[test]
fn changed_package_or_identity_resolution_emits_again() {
    let mut first = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(10), Some(10_123));
    first.package = Some("one.app".to_string());
    first.identity_resolved = true;
    let mut second = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(10), Some(10_123));
    second.package = Some("two.app".to_string());
    second.identity_resolved = true;
    let source = SequenceForegroundSource::new(vec![Some(first), Some(second.clone())]);
    let mut manager = ForegroundManager::new(source);

    assert!(manager.poll_changed().unwrap().is_some());
    assert_eq!(
        manager
            .poll_changed()
            .unwrap()
            .and_then(|update| update.active()),
        Some(second)
    );
}

#[test]
fn repeated_same_valid_payload_after_retry_is_ignored() {
    let candidate = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(10), Some(10_123));
    let source =
        SequenceForegroundSource::new(vec![Some(candidate.clone()), None, Some(candidate.clone())]);
    let mut manager = ForegroundManager::new(source);

    assert!(manager.poll_changed().unwrap().is_some());
    assert!(
        manager
            .handle_fs_event_changed(std::path::Path::new("/tmp/cgroup.procs"), 0)
            .unwrap()
            .is_none()
    );
}

#[test]
fn blocked_first_pid_dedupes_based_on_first_valid_unblocked_candidate() {
    let root = temp_dir("dedupe_v1_blocked_root");
    let proc_root = temp_dir("dedupe_v1_blocked_proc");
    let cgroup_procs = root.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "10\n11\n").unwrap();
    let mut filter = ForegroundCandidateFilter::default();
    filter.blocked_uids.insert(10_123);
    let resolver = MapPidUidResolver::new(BTreeMap::from([(10, 10_123), (11, 10_124)]));
    let source = CgroupV1CpusetSource::with_resolver(
        cgroup_procs.clone(),
        proc_root.clone(),
        filter,
        resolver,
    );
    let mut manager = ForegroundManager::new(source);

    let first = manager
        .handle_fs_event_changed(&cgroup_procs, 0)
        .unwrap()
        .unwrap()
        .active()
        .unwrap();
    assert_eq!(first.pid, Some(11));
    assert_eq!(first.uid, Some(10_124));
    assert!(
        manager
            .handle_fs_event_changed(&cgroup_procs, 0)
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn old_foreground_is_retained_when_source_becomes_unknown() {
    let first = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(10), Some(10_123));
    let source = SequenceForegroundSource::new(vec![Some(first.clone()), None, None, None]);
    let mut manager = ForegroundManager::new(source);

    assert!(manager.poll_changed().unwrap().is_some());
    let update = manager
        .handle_fs_event_changed(std::path::Path::new("/tmp/cgroup.procs"), 0)
        .unwrap();
    assert!(update.is_none());
    assert_eq!(manager.last_payload(), Some(&first));
}

#[test]
fn foreground_pipeline_duplicate_same_payload_emits_once() {
    let candidate = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(10), Some(10_123));
    let source = SequenceForegroundSource::new(vec![
        Some(candidate),
        Some(foreground_candidate(
            ForegroundSourceKind::CgroupV1,
            Some(10),
            Some(10_123),
        )),
    ]);
    let mut pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, root) = test_invalidator("pipeline_dup");

    assert_eq!(pipeline.poll_changed(&mut invalidator).unwrap().len(), 1);
    assert!(pipeline.poll_changed(&mut invalidator).unwrap().is_empty());
    assert_eq!(invalidator.foreground_count(), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn foreground_pipeline_changed_payload_emits_twice() {
    let source = SequenceForegroundSource::new(vec![
        Some(foreground_candidate(
            ForegroundSourceKind::CgroupV1,
            Some(10),
            Some(10_123),
        )),
        Some(foreground_candidate(
            ForegroundSourceKind::CgroupV1,
            Some(11),
            Some(10_124),
        )),
    ]);
    let mut pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, root) = test_invalidator("pipeline_changed");

    assert_eq!(pipeline.poll_changed(&mut invalidator).unwrap().len(), 1);
    assert_eq!(pipeline.poll_changed(&mut invalidator).unwrap().len(), 1);
    assert_eq!(invalidator.foreground_count(), 1);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn duplicate_payload_does_not_increment_invalidation_counter() {
    let candidate = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(10), Some(10_123));
    let source = SequenceForegroundSource::new(vec![Some(candidate.clone()), Some(candidate)]);
    let mut pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, root) = test_invalidator("pipeline_counter_dup");

    let _ = pipeline.poll_changed(&mut invalidator).unwrap();
    let _ = pipeline.poll_changed(&mut invalidator).unwrap();

    assert_eq!(invalidator.foreground_count(), 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn changed_payload_increments_invalidation_counter() {
    let source = SequenceForegroundSource::new(vec![
        Some(foreground_candidate(
            ForegroundSourceKind::CgroupV1,
            Some(10),
            Some(10_123),
        )),
        Some(foreground_candidate(
            ForegroundSourceKind::CgroupV1,
            Some(10),
            Some(10_124),
        )),
    ]);
    let mut pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, root) = test_invalidator("pipeline_counter_changed");

    let _ = pipeline.poll_changed(&mut invalidator).unwrap();
    let _ = pipeline.poll_changed(&mut invalidator).unwrap();

    assert_eq!(invalidator.foreground_count(), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn foreground_pipeline_exact_cache_hit_updates_last_identity() {
    let source = SequenceForegroundSource::new(vec![Some(foreground_candidate(
        ForegroundSourceKind::CgroupV1,
        Some(10),
        Some(10_123),
    ))]);
    let mut pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, root) = test_invalidator("pipeline_exact");
    let cache = cache_from_entries(vec![("example.app", 10_123)]);
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);
    let mut state = EngineState::default();

    let events = pipeline.poll_changed(&mut invalidator).unwrap();
    apply_event_path(events, &mut services, &mut state);

    let identity = state.last_identity.unwrap();
    assert_eq!(identity.package.as_deref(), Some("example.app"));
    assert_eq!(identity.state, ResolvedIdentityState::Exact);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn foreground_pipeline_missing_and_ambiguous_cache_states_resolve() {
    let cache = cache_from_entries(vec![
        ("one.app", 10_123),
        ("two.a", 10_124),
        ("two.b", 10_124),
    ]);
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);

    let mut missing_state = EngineState::default();
    apply_event_path(
        vec![EngineEvent::ForegroundCandidateChanged(
            foreground_candidate(ForegroundSourceKind::CgroupV1, None, Some(10_999)),
        )],
        &mut services,
        &mut missing_state,
    );
    assert_eq!(
        missing_state.last_identity.unwrap().state,
        ResolvedIdentityState::Missing
    );

    let mut ambiguous_state = EngineState::default();
    apply_event_path(
        vec![EngineEvent::ForegroundCandidateChanged(
            foreground_candidate(ForegroundSourceKind::CgroupV1, None, Some(10_124)),
        )],
        &mut services,
        &mut ambiguous_state,
    );
    assert_eq!(
        ambiguous_state.last_identity.unwrap().state,
        ResolvedIdentityState::Ambiguous
    );
}

#[test]
fn no_valid_candidate_keeps_last_payload_and_last_identity() {
    let first = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(10), Some(10_123));
    let source = SequenceForegroundSource::new(vec![Some(first.clone()), None, None, None]);
    let mut pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, root) = test_invalidator("pipeline_none");
    let cache = cache_from_entries(vec![("example.app", 10_123)]);
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);
    let mut state = EngineState::default();

    let events = pipeline.poll_changed(&mut invalidator).unwrap();
    apply_event_path(events, &mut services, &mut state);
    let clear_events = pipeline
        .handle_fs_event_changed(
            std::path::Path::new("/tmp/cgroup.procs"),
            0,
            &mut invalidator,
        )
        .unwrap();
    apply_event_path(clear_events, &mut services, &mut state);

    assert_eq!(pipeline.manager().last_payload(), Some(&first));
    assert_eq!(
        state
            .last_identity
            .as_ref()
            .and_then(|id| id.package.as_deref()),
        Some("example.app")
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn blocked_or_ambiguous_candidate_keeps_last_real_package() {
    let first = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(1), Some(10_123));
    let source = SequenceForegroundSource::new(vec![Some(first), None, None, None]);
    let mut pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, root) = test_invalidator("pipeline_blocked_clear");
    let cache = cache_from_entries(vec![("example.app", 10_123)]);
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);
    let mut state = EngineState::default();

    let events = pipeline.poll_changed(&mut invalidator).unwrap();
    apply_event_path(events, &mut services, &mut state);
    assert_eq!(
        state
            .last_identity
            .as_ref()
            .and_then(|id| id.package.as_deref()),
        Some("example.app")
    );

    let events = pipeline
        .handle_fs_event_changed(
            std::path::Path::new("/tmp/cgroup.procs"),
            0,
            &mut invalidator,
        )
        .unwrap();
    assert!(events.is_empty());
    apply_event_path(events, &mut services, &mut state);
    assert_eq!(
        state
            .last_identity
            .as_ref()
            .and_then(|id| id.package.as_deref()),
        Some("example.app")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cmd_package_list_parser_reads_package_uid_lines() {
    let entries = parse_cmd_package_list_stdout(
        b"package:com.example.one uid:10123\n\
              package:bad uid:10124\n\
              package:com.example.two uid:not-a-uid\n\
              package:org.example.two uid:10125 installer=null\n",
    );

    assert_eq!(
        entries,
        vec![
            PackageUidEntry {
                package: "com.example.one".to_string(),
                uid: 10_123,
                base_apk_path: None,
            },
            PackageUidEntry {
                package: "org.example.two".to_string(),
                uid: 10_125,
                base_apk_path: None,
            },
        ]
    );
}

#[test]
fn uid_cache_exact_missing_and_ambiguous() {
    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("one.app", 10_123), ("two.a", 10_124), ("two.b", 10_124)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();

    assert_eq!(cache.uid_for_package("one.app"), Some(10_123));
    assert_eq!(
        cache.uid_state(10_123),
        UidPackageState::Exact("one.app".to_string())
    );
    assert_eq!(cache.uid_state(99_999), UidPackageState::Missing);
    assert_eq!(
        cache.uid_state(10_124),
        UidPackageState::Ambiguous(vec!["two.a".to_string(), "two.b".to_string()])
    );
}

#[test]
fn foreground_filter_uses_cache_for_package_block_and_resolution() {
    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![
                ("blocked.app", 10_123),
                ("clear.app", 10_124),
                ("one.app", 10_125),
                ("two.app", 10_125),
            ],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();

    let mut filter = ForegroundCandidateFilter::default();
    filter.blocked_packages.insert("blocked.app".to_string());
    assert!(
        filter
            .candidate_for_uid(ForegroundSourceKind::CgroupV1, None, 10_123, Some(&cache))
            .is_none()
    );

    let exact = filter
        .candidate_for_uid(ForegroundSourceKind::CgroupV1, None, 10_124, Some(&cache))
        .unwrap();
    assert_eq!(exact.package.as_deref(), Some("clear.app"));
    assert!(exact.identity_resolved);

    let missing = filter
        .candidate_for_uid(ForegroundSourceKind::CgroupV1, None, 10_999, Some(&cache))
        .unwrap();
    assert_eq!(missing.package, None);
    assert!(!missing.identity_resolved);

    assert!(
        filter
            .candidate_for_uid(ForegroundSourceKind::CgroupV1, None, 10_125, Some(&cache),)
            .is_none()
    );
}

#[test]
fn foreground_manager_watch_paths_and_handle_fs_event() {
    let root = temp_dir("manager_root");
    let proc_root = temp_dir("manager_proc");
    let cgroup_procs = root.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "31\n").unwrap();

    let resolver = MapPidUidResolver::new(BTreeMap::from([(31, 10_131)]));
    let source = CgroupV1CpusetSource::with_resolver(
        cgroup_procs.clone(),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    );
    let mut manager = ForegroundManager::new(source);

    assert_eq!(
        manager.watch_hint_paths(),
        std::slice::from_ref(&cgroup_procs)
    );
    let ignored = manager.handle_fs_event(&root.join("other")).unwrap();
    assert!(ignored.is_none());

    let candidate = manager.handle_fs_event(&cgroup_procs).unwrap().unwrap();
    assert_eq!(candidate.pid, Some(31));
    assert_eq!(candidate.uid, Some(10_131));

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn dispatcher_maps_foreground_candidate_to_resolve_identity() {
    let candidate = ForegroundCandidate {
        source: ForegroundSourceKind::CgroupV1,
        pid: Some(123),
        uid: Some(10_123),
        package: Some("example.app".to_string()),
        identity_resolved: true,
    };
    let actions = Dispatcher::dispatch(&EngineEvent::ForegroundCandidateChanged(candidate));
    assert_eq!(
        actions,
        vec![EngineAction::ResolveIdentity {
            pid: Some(123),
            uid: Some(10_123),
        }]
    );

    let empty = ForegroundCandidate {
        source: ForegroundSourceKind::CgroupV1,
        pid: None,
        uid: None,
        package: None,
        identity_resolved: false,
    };
    assert!(Dispatcher::dispatch(&EngineEvent::ForegroundCandidateChanged(empty)).is_empty());
}

#[test]
fn resolve_identity_exact_uid_resolves_package() {
    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("example.app", 10_123)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);

    let events = services
        .perform(EngineAction::ResolveIdentity {
            pid: Some(7),
            uid: Some(10_123),
        })
        .unwrap();

    assert!(matches!(
        events.as_slice(),
        [EngineEvent::IdentityResolved(identity)]
            if identity.pid == Some(7)
                && identity.uid == Some(10_123)
                && identity.package.as_deref() == Some("example.app")
                && identity.state == ResolvedIdentityState::Exact
                && identity.source == ResolvedIdentitySource::CacheOnly
    ));
}

#[test]
fn resolve_identity_missing_uid_returns_missing() {
    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("example.app", 10_123)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);

    let events = services
        .perform(EngineAction::ResolveIdentity {
            pid: None,
            uid: Some(10_999),
        })
        .unwrap();

    assert!(matches!(
        events.as_slice(),
        [EngineEvent::IdentityResolved(identity)]
            if identity.package.is_none()
                && identity.state == ResolvedIdentityState::Missing
                && identity.source == ResolvedIdentitySource::CacheOnly
    ));
}

#[test]
fn resolve_identity_duplicate_uid_returns_ambiguous() {
    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("one.app", 10_123), ("two.app", 10_123)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);

    let events = services
        .perform(EngineAction::ResolveIdentity {
            pid: None,
            uid: Some(10_123),
        })
        .unwrap();

    assert!(matches!(
        events.as_slice(),
        [EngineEvent::IdentityResolved(identity)]
            if identity.package.is_none()
                && identity.state == ResolvedIdentityState::Ambiguous
                && identity.source == ResolvedIdentitySource::CacheOnly
    ));
}

#[test]
fn resolve_identity_pid_only_returns_unresolved_without_cmdline() {
    let mut services = SystemServices::new(ExecRunner::new(exec_config()));

    let events = services
        .perform(EngineAction::ResolveIdentity {
            pid: Some(42),
            uid: None,
        })
        .unwrap();

    assert!(matches!(
        events.as_slice(),
        [EngineEvent::IdentityResolved(identity)]
            if identity.pid == Some(42)
                && identity.uid.is_none()
                && identity.package.is_none()
                && identity.state == ResolvedIdentityState::Unresolved
                && identity.source == ResolvedIdentitySource::CacheOnly
    ));
}

#[test]
fn resolve_identity_empty_action_is_noop() {
    let mut services = SystemServices::new(ExecRunner::new(exec_config()));

    let events = services
        .perform(EngineAction::ResolveIdentity {
            pid: None,
            uid: None,
        })
        .unwrap();

    assert!(events.is_empty());
}

#[test]
fn dispatcher_action_path_emits_identity_resolved() {
    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("example.app", 10_123)],
        ),
    };
    let cache = UidPackageCache::warm_from(&provider).unwrap();
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);
    let candidate = ForegroundCandidate {
        source: ForegroundSourceKind::CgroupV1,
        pid: None,
        uid: Some(10_123),
        package: None,
        identity_resolved: false,
    };
    let actions = Dispatcher::dispatch(&EngineEvent::ForegroundCandidateChanged(candidate));
    let events = services
        .perform(actions.into_iter().next().unwrap())
        .unwrap();

    assert!(matches!(
        events.as_slice(),
        [EngineEvent::IdentityResolved(identity)]
            if identity.package.as_deref() == Some("example.app")
                && identity.state == ResolvedIdentityState::Exact
    ));
}

#[test]
fn watched_foreground_path_triggers_changed_event() {
    let root = temp_dir("watch_fg_root");
    let proc_root = temp_dir("watch_fg_proc");
    let cgroup_procs = root.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "10\n").unwrap();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(10, 10_123), (11, 10_124)]));
    let source = CgroupV1CpusetSource::with_resolver(
        cgroup_procs.clone(),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    );
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, invalidator_root) = test_invalidator("watch_fg_invalid");
    let mut watcher = EngineWatch::new(pipeline, &invalidator).unwrap();
    let cache = cache_from_entries(vec![("example.app", 10_124)]);
    let mut services =
        SystemServices::new(ExecRunner::new(exec_config())).with_uid_package_cache(cache);
    let mut state = EngineState::default();

    std::fs::write(&cgroup_procs, "11\n").unwrap();
    let events = watcher
        .poll_once(250, &mut invalidator, &mut services, &mut state, || {})
        .unwrap();

    assert!(matches!(
        events.as_slice(),
        [
            EngineEvent::ForegroundCandidateChanged(candidate),
            EngineEvent::IdentityResolved(identity),
        ] if candidate.uid == Some(10_124)
            && identity.package.as_deref() == Some("example.app")
            && state.last_identity.as_ref() == Some(identity)
    ));
    assert_eq!(invalidator.foreground_count(), 0);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
    let _ = std::fs::remove_dir_all(invalidator_root);
}

#[test]
fn watched_duplicate_foreground_event_emits_once() {
    let root = temp_dir("watch_dup_root");
    let proc_root = temp_dir("watch_dup_proc");
    let cgroup_procs = root.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "10\n").unwrap();
    let resolver = MapPidUidResolver::new(BTreeMap::from([(10, 10_123)]));
    let source = CgroupV1CpusetSource::with_resolver(
        cgroup_procs.clone(),
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        resolver,
    );
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, invalidator_root) = test_invalidator("watch_dup_invalid");
    let mut watcher = EngineWatch::new(pipeline, &invalidator).unwrap();
    let mut services = SystemServices::new(ExecRunner::new(exec_config()))
        .with_uid_package_cache(cache_from_entries(vec![("example.app", 10_123)]));
    let mut state = EngineState::default();

    std::fs::write(&cgroup_procs, "10\n").unwrap();
    assert_eq!(
        watcher
            .poll_once(250, &mut invalidator, &mut services, &mut state, || {})
            .unwrap()
            .len(),
        2
    );
    std::fs::write(&cgroup_procs, "10\n").unwrap();
    assert!(
        watcher
            .poll_once(250, &mut invalidator, &mut services, &mut state, || {})
            .unwrap()
            .is_empty()
    );
    assert_eq!(invalidator.foreground_count(), 0);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
    let _ = std::fs::remove_dir_all(invalidator_root);
}

#[test]
fn watcher_missing_watch_path_does_not_crash() {
    let root = temp_dir("watch_missing");
    let cgroup_procs = root.join("missing").join("cgroup.procs");
    let source = CgroupV1CpusetSource::with_resolver(
        cgroup_procs,
        root.clone(),
        ForegroundCandidateFilter::default(),
        MapPidUidResolver::new(BTreeMap::new()),
    );
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let invalidator = IdentityCacheInvalidator::new(invalidation_config(root.join("packages.xml")));
    let watcher = EngineWatch::new(pipeline, &invalidator).unwrap();

    assert!(watcher.foreground_watch_paths().is_empty());
    assert!(watcher.identity_watch_paths().is_empty());
    assert_eq!(watcher.registration_failures().len(), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn watcher_duplicate_foreground_watch_path_registered_once() {
    let root = temp_dir("watch_duplicate_path");
    let cgroup_procs = root.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "10\n").unwrap();
    let source = SequenceForegroundSource::with_watch_paths(
        Vec::new(),
        vec![cgroup_procs.clone(), cgroup_procs.clone()],
    );
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let invalidator = IdentityCacheInvalidator::new(invalidation_config(root.join("packages.xml")));
    let watcher = EngineWatch::new(pipeline, &invalidator).unwrap();

    assert_eq!(
        watcher.foreground_watch_paths(),
        &BTreeSet::from([cgroup_procs])
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn dropped_socket_stream_unregisters_token() {
    let root = temp_dir("watch_socket_unregister");
    let source = SequenceForegroundSource::with_watch_paths(Vec::new(), Vec::new());
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let invalidator = IdentityCacheInvalidator::new(invalidation_config(root.join("packages.xml")));
    let mut watcher = EngineWatch::new(pipeline, &invalidator).unwrap();
    let name = unique_name("watch_socket_unregister_client");
    let listener = bind_abstract_stream_socket(name.as_bytes()).unwrap();
    let listener_token = watcher.register_socket_listener(&listener).unwrap();
    let _client = connect_abstract_stream_socket(name.as_bytes()).unwrap();
    let stream = listener.accept().unwrap().unwrap();
    let token = watcher.register_socket_stream(&stream).unwrap();

    assert_eq!(watcher.socket_token_count(), 2);
    assert!(watcher.unregister_socket_stream(token, &stream).unwrap());
    assert_eq!(watcher.socket_token_count(), 1);
    assert!(!watcher.unregister_socket_stream(token, &stream).unwrap());
    assert!(watcher.socket_token_count() >= 1);
    assert_ne!(listener_token, token);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn repeated_socket_connect_disconnect_does_not_grow_stale_tokens() {
    let root = temp_dir("watch_socket_repeated");
    let source = SequenceForegroundSource::with_watch_paths(Vec::new(), Vec::new());
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let invalidator = IdentityCacheInvalidator::new(invalidation_config(root.join("packages.xml")));
    let mut watcher = EngineWatch::new(pipeline, &invalidator).unwrap();
    let name = unique_name("watch_socket_repeated");
    let listener = bind_abstract_stream_socket(name.as_bytes()).unwrap();
    watcher.register_socket_listener(&listener).unwrap();

    for _ in 0..16 {
        let _client = connect_abstract_stream_socket(name.as_bytes()).unwrap();
        let stream = listener.accept().unwrap().unwrap();
        let token = watcher.register_socket_stream(&stream).unwrap();
        assert!(watcher.unregister_socket_stream(token, &stream).unwrap());
    }

    assert_eq!(watcher.socket_token_count(), 1);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn watcher_poll_once_no_events_is_empty() {
    let root = temp_dir("watch_empty");
    let proc_root = temp_dir("watch_empty_proc");
    let cgroup_procs = root.join("cgroup.procs");
    std::fs::write(&cgroup_procs, "10\n").unwrap();
    let source = CgroupV1CpusetSource::with_resolver(
        cgroup_procs,
        proc_root.clone(),
        ForegroundCandidateFilter::default(),
        MapPidUidResolver::new(BTreeMap::from([(10, 10_123)])),
    );
    let pipeline = ForegroundPipeline::new(ForegroundManager::new(source));
    let (mut invalidator, invalidator_root) = test_invalidator("watch_empty_invalid");
    let mut watcher = EngineWatch::new(pipeline, &invalidator).unwrap();
    let mut services = SystemServices::new(ExecRunner::new(exec_config()));
    let mut state = EngineState::default();

    let events = watcher
        .poll_once(0, &mut invalidator, &mut services, &mut state, || {})
        .unwrap();

    assert!(events.is_empty());
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(proc_root);
    let _ = std::fs::remove_dir_all(invalidator_root);
}

#[test]
fn activity_parser_reads_top_activity_package() {
    assert_eq!(
        parse_top_activity_package(
            b"prefix topActivity=ComponentInfo{com.openai.chatgpt/.MainActivity} suffix"
        )
        .as_deref(),
        Some("com.openai.chatgpt")
    );
    assert_eq!(parse_top_activity_package(b"no top activity"), None);
    assert_eq!(
        parse_top_activity_package(b"topActivity=ComponentInfo{bad}"),
        None
    );
}

#[test]
fn activity_resolver_applies_blocklist() {
    let blocked = BTreeSet::from(["com.android.documentsui".to_string()]);
    let report = resolve_activity_stdout(
        b"topActivity=ComponentInfo{com.android.documentsui/.FilesActivity}",
        &blocked,
    );

    assert_eq!(report.package, None);
    assert_eq!(
        report.lines,
        vec!["source=activity package=com.android.documentsui reason=blocked".to_string()]
    );
}

#[test]
fn v1_payload_cache_skips_unchanged_payload() {
    let mut cache = V1PayloadCache::default();

    assert!(cache.observe(b"1\n".to_vec()).is_some());
    assert!(cache.observe(b"1\n".to_vec()).is_none());
    assert!(cache.observe(b"2\n".to_vec()).is_some());
}

#[test]
fn resolver_v1_payload_resolves_exact_package_and_skips_ambiguous() {
    let state = resolver_state(vec![
        ("one.app", 10_123),
        ("two.a", 10_124),
        ("two.b", 10_124),
        ("valid.app", 10_125),
    ]);
    let report = resolve_v1_payload_with_uid_resolver(b"1\n2\n", &state, |pid| {
        Ok(Some(match pid {
            1 => 10_124,
            2 => 10_125,
            _ => unreachable!(),
        }))
    });

    assert_eq!(report.package.as_deref(), Some("valid.app"));
    assert!(
        report
            .lines
            .contains(&"source=v1 uid=10124 package_count=2 reason=ambiguous".to_string())
    );
}

#[test]
fn resolver_auto_is_lazy() {
    let calls = std::cell::Cell::new(0);
    let v1 = ForegroundResolveReport {
        package: Some("v1.app".to_string()),
        lines: vec!["source=v1 package=v1.app reason=resolved".to_string()],
    };

    let report = resolve_after_v1_unavailable_lazy(v1.clone(), || {
        calls.set(calls.get() + 1);
        ForegroundResolveReport {
            package: Some("activity.app".to_string()),
            lines: vec!["source=activity package=activity.app reason=resolved".to_string()],
        }
    });

    assert_eq!(report, v1);
    assert_eq!(calls.get(), 0);
}

#[test]
fn resolver_auto_order_is_v1_v2_activity_and_activity_is_lazy() {
    let calls = std::cell::RefCell::new(Vec::new());
    let report = resolve_after_v1_v2_unavailable_lazy(
        ForegroundResolveReport::unavailable("v1"),
        || {
            calls.borrow_mut().push("v2");
            ForegroundResolveReport {
                package: Some("v2.app".to_string()),
                lines: vec!["source=v2 package=v2.app reason=resolved".to_string()],
            }
        },
        || {
            calls.borrow_mut().push("activity");
            ForegroundResolveReport {
                package: Some("activity.app".to_string()),
                lines: vec!["source=activity package=activity.app reason=resolved".to_string()],
            }
        },
    );

    assert_eq!(report.package.as_deref(), Some("v2.app"));
    assert_eq!(calls.borrow().as_slice(), ["v2"]);

    calls.borrow_mut().clear();
    let report = resolve_after_v1_v2_unavailable_lazy(
        ForegroundResolveReport::unavailable("v1"),
        || {
            calls.borrow_mut().push("v2");
            ForegroundResolveReport::unavailable("v2")
        },
        || {
            calls.borrow_mut().push("activity");
            ForegroundResolveReport {
                package: Some("activity.app".to_string()),
                lines: vec!["source=activity package=activity.app reason=resolved".to_string()],
            }
        },
    );

    assert_eq!(report.package.as_deref(), Some("activity.app"));
    assert_eq!(calls.borrow().as_slice(), ["v2", "activity"]);
}

#[test]
fn auto_foreground_source_order_is_v1_v2_activity_lazy() {
    let v1_candidate = foreground_candidate(ForegroundSourceKind::CgroupV1, Some(1), Some(10_123));
    let v2_candidate = foreground_candidate(ForegroundSourceKind::CgroupV2, None, Some(10_124));
    let activity_calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let calls = activity_calls.clone();
    let mut source = AutoForegroundSource::new(
        SequenceForegroundSource::new(vec![Some(v1_candidate.clone())]),
        SequenceForegroundSource {
            kind: ForegroundSourceKind::CgroupV2,
            responses: vec![Some(v2_candidate.clone())].into(),
            watch_hint_paths: vec![PathBuf::from("/tmp/v2")],
        },
        move || {
            calls.set(calls.get() + 1);
            Ok(Some(foreground_candidate(
                ForegroundSourceKind::ActivityManager,
                None,
                Some(10_125),
            )))
        },
    );

    assert_eq!(source.poll_current().unwrap(), Some(v1_candidate));
    assert_eq!(activity_calls.get(), 0);

    let activity_calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let calls = activity_calls.clone();
    let mut source = AutoForegroundSource::new(
        UnavailableForegroundSource {
            kind: ForegroundSourceKind::CgroupV1,
            watch_hint_paths: vec![PathBuf::from("/tmp/cgroup.procs")],
        },
        SequenceForegroundSource {
            kind: ForegroundSourceKind::CgroupV2,
            responses: vec![Some(v2_candidate.clone())].into(),
            watch_hint_paths: vec![PathBuf::from("/tmp/v2")],
        },
        move || {
            calls.set(calls.get() + 1);
            Ok(None)
        },
    );

    assert_eq!(source.poll_current().unwrap(), Some(v2_candidate.clone()));
    assert_eq!(activity_calls.get(), 0);

    let activity_calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let calls = activity_calls.clone();
    let mut source = AutoForegroundSource::new(
        SequenceForegroundSource::new(vec![None]),
        SequenceForegroundSource {
            kind: ForegroundSourceKind::CgroupV2,
            responses: vec![Some(v2_candidate)].into(),
            watch_hint_paths: vec![PathBuf::from("/tmp/v2")],
        },
        move || {
            calls.set(calls.get() + 1);
            Ok(Some(foreground_candidate(
                ForegroundSourceKind::ActivityManager,
                None,
                Some(10_125),
            )))
        },
    );

    assert!(source.poll_current().unwrap().is_none());
    assert_eq!(activity_calls.get(), 0);

    let activity_calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let calls = activity_calls.clone();
    let mut source = AutoForegroundSource::new(
        UnavailableForegroundSource {
            kind: ForegroundSourceKind::CgroupV1,
            watch_hint_paths: vec![PathBuf::from("/tmp/cgroup.procs")],
        },
        UnavailableForegroundSource {
            kind: ForegroundSourceKind::CgroupV2,
            watch_hint_paths: vec![PathBuf::from("/tmp/v2")],
        },
        move || {
            calls.set(calls.get() + 1);
            Ok(Some(foreground_candidate(
                ForegroundSourceKind::ActivityManager,
                None,
                Some(10_125),
            )))
        },
    );

    let candidate = source.poll_current().unwrap().unwrap();
    assert_eq!(candidate.source, ForegroundSourceKind::ActivityManager);
    assert_eq!(activity_calls.get(), 1);
}

#[test]
fn resolver_invalidation_rebuilds_only_on_interval_and_marker_change() {
    let provider = FakePackageProvider {
        snapshot: fake_snapshot(
            PackageProviderSource::CmdPackageList,
            true,
            vec![("new.app", 10_123)],
        ),
    };
    let mut state = ForegroundResolverState::new(
        UidPackageCache::default(),
        BTreeSet::new(),
        AppUidFilter {
            modulus: 100_000,
            min_app_id: 10_000,
        },
        Some(PackageFileStat {
            mtime_sec: 1,
            mtime_nsec: 0,
            size: 10,
        }),
    );
    let mut stat = FakePackageStat {
        calls: 0,
        stats: vec![
            Ok(PackageFileStat {
                mtime_sec: 1,
                mtime_nsec: 0,
                size: 10,
            }),
            Ok(PackageFileStat {
                mtime_sec: 2,
                mtime_nsec: 0,
                size: 11,
            }),
        ],
    };
    let marker = PathBuf::from("marker");

    for _ in 0..9 {
        assert!(
            state
                .foreground_changed(&provider, &mut stat, &marker, 10)
                .unwrap()
                .is_none()
        );
    }
    let keep = state
        .foreground_changed(&provider, &mut stat, &marker, 10)
        .unwrap()
        .unwrap();
    for _ in 0..9 {
        assert!(
            state
                .foreground_changed(&provider, &mut stat, &marker, 10)
                .unwrap()
                .is_none()
        );
    }
    let rebuild = state
        .foreground_changed(&provider, &mut stat, &marker, 10)
        .unwrap()
        .unwrap();

    assert_eq!(stat.calls, 2);
    assert_eq!(state.cache_rebuilds, 2);
    assert!(keep.contains("changed=false action=keep"));
    assert!(rebuild.contains("changed=true action=rebuild entries=1"));
    assert_eq!(state.cache.exact_package_for_uid(10_123), Some("new.app"));
}
