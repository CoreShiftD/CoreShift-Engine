use std::fmt;

/// Engine-level error wrapper.
#[derive(Debug)]
pub enum EngineError {
    /// Low-level Core primitive failed.
    Core(coreshift_core::CoreError),
    /// Local filesystem or OS I/O failed outside a Core primitive.
    Io(std::io::Error),
    /// Runtime was started more than once.
    AlreadyStarted,
    /// Runtime has not been started.
    NotStarted,
    /// Engine configuration failed validation before runtime start.
    InvalidConfig {
        field: &'static str,
        reason: &'static str,
    },
}

impl EngineError {
    pub(crate) fn invalid_config(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidConfig { field, reason }
    }
}

impl From<coreshift_core::CoreError> for EngineError {
    fn from(value: coreshift_core::CoreError) -> Self {
        Self::Core(value)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::AlreadyStarted => write!(f, "runtime already started"),
            Self::NotStarted => write!(f, "runtime not started"),
            Self::InvalidConfig { field, reason } => {
                write!(f, "invalid config ({field}: {reason})")
            }
        }
    }
}

impl std::error::Error for EngineError {}
