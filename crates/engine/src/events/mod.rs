use crate::EngineError;
use crate::services::foreground::PackageProviderSource;
use crate::services::foreground::{ForegroundCandidate, ForegroundUnknown};
use crate::services::identity::ResolvedIdentity;
use coreshift_core::spawn::Output;

/// Generic Engine event.
#[derive(Debug)]
pub enum EngineEvent {
    RuntimeStarted,
    RuntimeStopped,
    ExecCompleted {
        output: Output,
    },
    ForegroundCandidateChanged(ForegroundCandidate),
    ForegroundUnknown(ForegroundUnknown),
    IdentityResolved(ResolvedIdentity),
    IdentityCacheWarmed {
        source: PackageProviderSource,
        coherent: bool,
        count: usize,
    },
    IdentityCacheWarmupFailed {
        error: String,
    },
    ServiceFailed {
        error: EngineError,
    },
}
