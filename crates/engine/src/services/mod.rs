pub mod foreground;
pub mod identity;
pub mod identity_cache;
pub mod socket;
pub mod watch;

use crate::EngineError;
use crate::dispatch::EngineAction;
use crate::events::EngineEvent;
use crate::exec::ExecRunner;
use crate::services::foreground::UidPackageCache;
use crate::services::identity::IdentityService;

/// Boundary for performing generic Engine actions.
pub trait Service {
    fn perform(&mut self, action: EngineAction) -> Result<Vec<EngineEvent>, EngineError>;
}

/// System service boundary over Core-backed exec primitives.
pub struct SystemServices {
    exec: ExecRunner,
    identity: IdentityService,
}

impl SystemServices {
    pub fn new(exec: ExecRunner) -> Self {
        Self {
            exec,
            identity: IdentityService::default(),
        }
    }

    pub fn with_uid_package_cache(mut self, package_cache: UidPackageCache) -> Self {
        self.identity = IdentityService::new(Some(package_cache));
        self
    }
}

impl Service for SystemServices {
    fn perform(&mut self, action: EngineAction) -> Result<Vec<EngineEvent>, EngineError> {
        match action {
            EngineAction::RunExec {
                argv,
                capture_stdout,
            } => {
                let output = if capture_stdout {
                    self.exec.run_capture_stdout(argv)?
                } else {
                    self.exec.run(argv)?
                };
                Ok(vec![EngineEvent::ExecCompleted { output }])
            }
            EngineAction::ResolveIdentity { pid, uid } => Ok(self
                .identity
                .resolve(pid, uid)
                .map(EngineEvent::IdentityResolved)
                .into_iter()
                .collect()),
            EngineAction::Shutdown => Ok(vec![EngineEvent::RuntimeStopped]),
        }
    }
}
