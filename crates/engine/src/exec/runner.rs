use crate::EngineError;
use crate::config::ExecConfig;
use coreshift_core::spawn::{Output, SpawnOptions};

/// Explicit process execution wrapper over Core spawn.
#[derive(Clone, Debug)]
pub struct ExecRunner {
    config: ExecConfig,
}

impl ExecRunner {
    pub fn new(config: ExecConfig) -> Self {
        Self { config }
    }

    pub fn run(&self, argv: Vec<String>) -> Result<Output, EngineError> {
        let mut builder = SpawnOptions::builder(argv)
            .backend(self.config.backend)
            .fd_policy(self.config.fd_policy.clone())
            .max_output(self.config.max_output);

        if let Some(timeout_ms) = self.config.timeout_ms {
            builder = builder.timeout_ms(timeout_ms);
        }

        Ok(builder.build()?.run()?)
    }

    pub fn run_capture_stdout(&self, argv: Vec<String>) -> Result<Output, EngineError> {
        let mut builder = SpawnOptions::builder(argv)
            .backend(self.config.backend)
            .fd_policy(self.config.fd_policy.clone())
            .capture_stdout()
            .max_output(self.config.max_output);

        if let Some(timeout_ms) = self.config.timeout_ms {
            builder = builder.timeout_ms(timeout_ms);
        }

        Ok(builder.build()?.run()?)
    }
}
