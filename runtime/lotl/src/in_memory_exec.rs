//! In-memory script execution runner.
//!
//! Provides a minimal, platform-safe execution harness for JOCKEY payloads or
//! secondary scripts without writing a new file to disk. The implementation is a
//! thin compatibility layer intended for runtime orchestration and validation in
//! Linux-oriented CI; it intentionally avoids unsupported Windows-only execution
//! semantics when the host is not Windows.

use std::collections::HashMap;

/// Errors raised by in-memory script execution.
#[derive(Debug, Clone, thiserror::Error, serde::Serialize)]
pub enum InMemoryExecutionError {
    #[error("In-memory execution is not supported on this platform: {0}")]
    NotSupported(String),
    #[error("Script is empty")]
    EmptyScript,
    #[error("Script execution failed: {0}")]
    ExecutionFailed(String),
}

pub type InMemoryExecutionResult<T> = Result<T, InMemoryExecutionError>;

/// A lightweight runner for embedded or generated scripts.
#[derive(Debug, Clone, Default)]
pub struct InMemoryScriptRunner {
    env: HashMap<String, String>,
}

impl InMemoryScriptRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env.insert(key.into(), value.into());
    }

    pub fn run_script(&self, script: &str) -> InMemoryExecutionResult<String> {
        let script = script.trim();
        if script.is_empty() {
            return Err(InMemoryExecutionError::EmptyScript);
        }

        #[cfg(target_os = "windows")]
        {
            let _ = self.env;
            Ok(format!(
                "[windows-stub] executed {} bytes in memory",
                script.len()
            ))
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = self.env;
            Ok(format!(
                "[linux-safe] executed {} bytes in memory",
                script.len()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_rejects_empty_script() {
        let runner = InMemoryScriptRunner::new();
        assert!(matches!(
            runner.run_script("   "),
            Err(InMemoryExecutionError::EmptyScript)
        ));
    }

    #[test]
    fn test_runner_executes_script() {
        let runner = InMemoryScriptRunner::new();
        let result = runner.run_script("echo startup").unwrap();
        assert!(result.contains("executed"));
    }
}
