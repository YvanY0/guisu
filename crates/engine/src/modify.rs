//! Modify script execution
//!
//! This module handles the execution of modify scripts that modify existing files in-place.

use guisu_core::Result;
use guisu_core::path::AbsPath;
use std::process::Command;
use tempfile::NamedTempFile;

/// Executes a modify script to modify a target file in-place
pub struct ModifyExecutor;

impl ModifyExecutor {
    /// Create a new modify executor
    pub fn new() -> Self {
        Self
    }

    /// Execute a modify script
    ///
    /// # Arguments
    ///
    /// * `script` - The script content (with shebang)
    /// * `interpreter` - The interpreter to use (e.g., "/bin/bash")
    /// * `target_path` - Path to the file that should be modified
    /// * `env` - Additional environment variables to set
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Temporary file creation fails
    /// - Script execution fails
    /// - Script returns non-zero exit code
    pub fn execute(
        &self,
        script: &[u8],
        interpreter: &str,
        target_path: &AbsPath,
        env: &[(String, String)],
    ) -> Result<()> {
        // Create temporary script file
        let mut temp_script = NamedTempFile::new().map_err(|e| {
            guisu_core::Error::Message(format!("Failed to create temporary script file: {e}"))
        })?;

        // Write script content
        std::fs::write(temp_script.path(), script).map_err(|e| {
            guisu_core::Error::Message(format!("Failed to write script to temporary file: {e}"))
        })?;

        // Make script executable (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(temp_script.path())
                .map_err(|e| {
                    guisu_core::Error::Message(format!("Failed to get script file metadata: {e}"))
                })?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(temp_script.path(), perms).map_err(|e| {
                guisu_core::Error::Message(format!("Failed to set script permissions: {e}"))
            })?;
        }

        // Parse interpreter and arguments
        // interpreter string may contain arguments (e.g., "/usr/bin/env python3")
        let mut parts = shell_words::split(interpreter)
            .map_err(|e| guisu_core::Error::Message(format!("Failed to parse interpreter: {e}")))?;

        if parts.is_empty() {
            return Err(guisu_core::Error::Message(
                "Interpreter string is empty".to_string(),
            ));
        }

        // First part is the interpreter binary
        let interpreter_bin = parts.remove(0);
        let mut args = parts;

        // Add script path as argument
        args.push(temp_script.path().to_string_lossy().into_owned());

        // Add target path as argument (like chezmoi's CHEZMOI_TARGET)
        args.push(target_path.as_path().to_string_lossy().into_owned());

        // Build command
        let mut command = Command::new(&interpreter_bin);
        command.args(&args);

        // Set environment variables
        command.env("GUISU_TARGET", target_path.as_path());
        for (key, value) in env {
            command.env(key, value);
        }

        // Execute command
        let output = command.output().map_err(|e| {
            guisu_core::Error::Message(format!("Failed to execute modify script: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(guisu_core::Error::Message(format!(
                "Modify script failed with exit code {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )));
        }

        Ok(())
    }
}

impl Default for ModifyExecutor {
    fn default() -> Self {
        Self::new()
    }
}
