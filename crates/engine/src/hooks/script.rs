//! Script execution with shebang parsing and interpreter inference
//!
//! Handles running scripts via their shebang interpreter, parsing shebang lines,
//! and inferring interpreters from file extensions when no shebang is present.

use guisu_core::{Error, Result};
use indexmap::IndexMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Execute a script using its shebang interpreter
///
/// Reads the script's shebang line to determine the interpreter,
/// then executes the script with that interpreter.
#[tracing::instrument(skip(env), fields(script_path = %script_path.display(), working_dir = %working_dir.display(), timeout))]
pub(crate) fn execute_script(
    script_path: &Path,
    working_dir: &Path,
    env: &IndexMap<String, String>,
    timeout: u64,
) -> Result<()> {
    use std::time::Duration;

    if !script_path.exists() {
        return Err(Error::HookExecution(format!(
            "Script not found: {}",
            script_path.display()
        )));
    }

    tracing::debug!("Executing script: {}", script_path.display());
    tracing::debug!("Working directory: {}", working_dir.display());
    if timeout > 0 {
        tracing::debug!("Timeout: {} seconds", timeout);
    }

    // Parse shebang to get interpreter
    let (interpreter, args) = parse_shebang(script_path)?;

    // Build command: interpreter + args + script_path
    let mut cmd_args = args;
    cmd_args.push(script_path.to_string_lossy().to_string());

    tracing::debug!("Using interpreter: {} {:?}", interpreter, cmd_args);

    // Build command - inherits parent env by default
    let mut cmd_builder = duct::cmd(&interpreter, &cmd_args)
        .dir(working_dir)
        .stderr_to_stdout();

    // Add custom environment variables (guisu-specific + hook-specific)
    for (key, value) in env {
        cmd_builder = cmd_builder.env(key, value);
    }

    let cmd_builder = cmd_builder;

    // Execute with or without timeout
    if timeout > 0 {
        let handle = cmd_builder.start().map_err(|e| {
            Error::HookExecution(format!(
                "Failed to start script '{}': {}",
                script_path.display(),
                e
            ))
        })?;

        match handle.wait_timeout(Duration::from_secs(timeout)) {
            Ok(Some(_output)) => Ok(()),
            Ok(None) => Err(Error::HookExecution(format!(
                "Script '{}' timed out after {} seconds",
                script_path.display(),
                timeout
            ))),
            Err(e) => Err(Error::HookExecution(format!(
                "Script '{}' failed: {}",
                script_path.display(),
                e
            ))),
        }
    } else {
        cmd_builder.run().map(|_| ()).map_err(|e| {
            Error::HookExecution(format!("Script '{}' failed: {}", script_path.display(), e))
        })
    }
}

/// Execute processed script content via a temporary file
///
/// Creates a temporary file with the given content, sets executable permissions,
/// and executes it using its shebang interpreter.
pub(crate) fn execute_processed_script(
    content: &str,
    working_dir: &Path,
    env: &IndexMap<String, String>,
    timeout: u64,
) -> Result<()> {
    use tempfile::NamedTempFile;

    // Create temporary file
    let mut temp_file = NamedTempFile::new()
        .map_err(|e| Error::HookExecution(format!("Failed to create temp file: {e}")))?;

    // Write content
    temp_file
        .write_all(content.as_bytes())
        .map_err(|e| Error::HookExecution(format!("Failed to write temp file: {e}")))?;

    // Set executable permissions (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        temp_file
            .as_file()
            .set_permissions(perms)
            .map_err(|e| Error::HookExecution(format!("Failed to set permissions: {e}")))?;
    }

    let temp_path = temp_file.path();
    tracing::debug!("Executing processed script: {}", temp_path.display());
    tracing::debug!("Working directory: {}", working_dir.display());

    // Execute script using shebang (same as regular scripts)
    // temp_file is automatically deleted when dropped
    execute_script(temp_path, working_dir, env, timeout)
}

/// Parse shebang line from a script file
///
/// Returns (interpreter, args)
///
/// # Examples
///
/// - `#!/bin/bash` -> ("bash", [])
/// - `#!/usr/bin/env python3` -> ("python3", [])
/// - `#!/bin/bash -e` -> ("bash", [`"-e"`])
pub(crate) fn parse_shebang(script_path: &Path) -> Result<(String, Vec<String>)> {
    use std::io::{BufRead, BufReader};

    let file = fs::File::open(script_path).map_err(|e| {
        Error::HookExecution(format!(
            "Failed to open script {}: {}",
            script_path.display(),
            e
        ))
    })?;

    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    reader.read_line(&mut first_line).map_err(|e| {
        Error::HookExecution(format!(
            "Failed to read script {}: {}",
            script_path.display(),
            e
        ))
    })?;

    // Check for shebang
    if !first_line.starts_with("#!") {
        // No shebang, try to infer from extension or use default
        return infer_interpreter(script_path);
    }

    // Parse shebang line
    let shebang = first_line[2..].trim();

    // Handle "#! /usr/bin/env interpreter"
    if shebang.starts_with("/usr/bin/env") || shebang.starts_with("/bin/env") {
        let parts: Vec<&str> = shebang.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::HookExecution(format!(
                "Invalid env shebang: {first_line}"
            )));
        }

        let interpreter = parts[1].to_string();
        let args = parts[2..].iter().map(|s| (*s).to_string()).collect();
        return Ok((interpreter, args));
    }

    // Handle "#! /bin/bash" or "#! /bin/bash -e"
    let parts: Vec<&str> = shebang.split_whitespace().collect();
    if parts.is_empty() {
        return Err(Error::HookExecution(format!("Empty shebang: {first_line}")));
    }

    // Extract interpreter name from path
    let interpreter_path = PathBuf::from(parts[0]);
    let interpreter = interpreter_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::HookExecution(format!("Invalid interpreter path: {}", parts[0])))?
        .to_string();

    let args = parts[1..].iter().map(|s| (*s).to_string()).collect();

    Ok((interpreter, args))
}

/// Infer interpreter from script extension when no shebang is present
pub(crate) fn infer_interpreter(script_path: &Path) -> Result<(String, Vec<String>)> {
    let extension = script_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let interpreter = match extension {
        "sh" => "sh",
        "bash" => "bash",
        "zsh" => "zsh",
        "py" => "python3",
        "rb" => "ruby",
        "pl" => "perl",
        "js" => "node",
        "" => {
            // No extension, check if executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = fs::metadata(script_path)?;
                if metadata.permissions().mode() & 0o111 != 0 {
                    // Executable, try to execute directly
                    return Ok((script_path.to_string_lossy().to_string(), vec![]));
                }
            }

            // Default to sh
            "sh"
        }
        _ => {
            return Err(Error::HookExecution(format!(
                "Cannot infer interpreter for script: {} (extension: {})",
                script_path.display(),
                extension
            )));
        }
    };

    Ok((interpreter.to_string(), vec![]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ======================================================================
    // Shebang Parsing Tests
    // ======================================================================

    #[test]
    fn test_parse_shebang_bash() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.sh");
        fs::write(&script_path, "#!/bin/bash\necho hello").unwrap();

        let (interpreter, args) = parse_shebang(&script_path).unwrap();
        assert_eq!(interpreter, "bash");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_shebang_bash_with_args() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.sh");
        fs::write(&script_path, "#!/bin/bash -e\necho hello").unwrap();

        let (interpreter, args) = parse_shebang(&script_path).unwrap();
        assert_eq!(interpreter, "bash");
        assert_eq!(args, vec!["-e"]);
    }

    #[test]
    fn test_parse_shebang_env_python() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.py");
        fs::write(&script_path, "#!/usr/bin/env python3\nprint('hello')").unwrap();

        let (interpreter, args) = parse_shebang(&script_path).unwrap();
        assert_eq!(interpreter, "python3");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_shebang_env_with_args() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.sh");
        fs::write(&script_path, "#!/usr/bin/env bash -x\necho hello").unwrap();

        let (interpreter, args) = parse_shebang(&script_path).unwrap();
        assert_eq!(interpreter, "bash");
        assert_eq!(args, vec!["-x"]);
    }

    #[test]
    fn test_parse_shebang_bin_env() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.sh");
        fs::write(&script_path, "#!/bin/env bash\necho hello").unwrap();

        let (interpreter, args) = parse_shebang(&script_path).unwrap();
        assert_eq!(interpreter, "bash");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_shebang_with_spaces() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.sh");
        fs::write(&script_path, "#! /bin/bash\necho hello").unwrap();

        let (interpreter, args) = parse_shebang(&script_path).unwrap();
        assert_eq!(interpreter, "bash");
        assert!(args.is_empty());
    }

    // ======================================================================
    // Interpreter Inference Tests
    // ======================================================================

    #[test]
    fn test_infer_interpreter_sh() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.sh");
        fs::write(&script_path, "echo hello").unwrap();

        let (interpreter, args) = infer_interpreter(&script_path).unwrap();
        assert_eq!(interpreter, "sh");
        assert!(args.is_empty());
    }

    #[test]
    fn test_infer_interpreter_bash() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.bash");
        fs::write(&script_path, "echo hello").unwrap();

        let (interpreter, args) = infer_interpreter(&script_path).unwrap();
        assert_eq!(interpreter, "bash");
        assert!(args.is_empty());
    }

    #[test]
    fn test_infer_interpreter_python() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.py");
        fs::write(&script_path, "print('hello')").unwrap();

        let (interpreter, args) = infer_interpreter(&script_path).unwrap();
        assert_eq!(interpreter, "python3");
        assert!(args.is_empty());
    }

    #[test]
    fn test_infer_interpreter_ruby() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.rb");
        fs::write(&script_path, "puts 'hello'").unwrap();

        let (interpreter, args) = infer_interpreter(&script_path).unwrap();
        assert_eq!(interpreter, "ruby");
        assert!(args.is_empty());
    }

    #[test]
    fn test_infer_interpreter_perl() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.pl");
        fs::write(&script_path, "print 'hello'").unwrap();

        let (interpreter, args) = infer_interpreter(&script_path).unwrap();
        assert_eq!(interpreter, "perl");
        assert!(args.is_empty());
    }

    #[test]
    fn test_infer_interpreter_javascript() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.js");
        fs::write(&script_path, "console.log('hello')").unwrap();

        let (interpreter, args) = infer_interpreter(&script_path).unwrap();
        assert_eq!(interpreter, "node");
        assert!(args.is_empty());
    }

    #[test]
    fn test_infer_interpreter_zsh() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.zsh");
        fs::write(&script_path, "echo hello").unwrap();

        let (interpreter, args) = infer_interpreter(&script_path).unwrap();
        assert_eq!(interpreter, "zsh");
        assert!(args.is_empty());
    }

    #[test]
    fn test_infer_interpreter_unknown_extension() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test.unknown");
        fs::write(&script_path, "content").unwrap();

        let result = infer_interpreter(&script_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot infer"));
    }

    #[test]
    fn test_infer_interpreter_no_extension_defaults_to_sh() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("test");
        fs::write(&script_path, "echo hello").unwrap();

        let (interpreter, args) = infer_interpreter(&script_path).unwrap();
        assert_eq!(interpreter, "sh");
        assert!(args.is_empty());
    }
}
