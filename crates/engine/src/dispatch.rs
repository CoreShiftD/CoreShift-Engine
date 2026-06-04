use crate::events::EngineEvent;

/// Generic Engine action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineAction {
    RunExec {
        argv: Vec<String>,
        capture_stdout: bool,
    },
    ResolveIdentity {
        pid: Option<i32>,
        uid: Option<u32>,
    },
    Shutdown,
}

/// Policy-free dispatcher.
#[derive(Debug, Default)]
pub struct Dispatcher;

impl Dispatcher {
    pub fn dispatch(event: &EngineEvent) -> Vec<EngineAction> {
        match event {
            EngineEvent::ForegroundCandidateChanged(candidate)
                if candidate.pid.is_some() || candidate.uid.is_some() =>
            {
                vec![EngineAction::ResolveIdentity {
                    pid: candidate.pid,
                    uid: candidate.uid,
                }]
            }
            _ => Vec::new(),
        }
    }
}
