//! Per-entry drift detection between target state and destination filesystem.
//!
//! Promoted from `cmd::apply::needs_update` so that the `apply`, `verify`,
//! and (future) drift-summary commands share one comparison primitive.

use crate::Result;
use crate::entry::TargetEntry;
use guisu_core::path::AbsPath;
use std::fs;

/// Permission bit mask used when comparing POSIX modes.
///
/// The source file's mode carries the `S_IFREG` file-type bit (it is the raw
/// `PermissionsExt::mode()` from `std::fs::metadata`). The destination's mode
/// is masked to permission bits before comparison, so mask here too —
/// otherwise a regular `0o644` file would falsely compare unequal to its
/// `target_mode` of `0o100644` on every comparison.
pub const PERM_MASK: u32 = 0o777;

/// Outcome of comparing one target entry to its destination path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResult {
    /// Destination matches target.
    Match,
    /// Destination is missing.
    Missing,
    /// Destination exists but content / mode / target differs.
    Modified,
}

/// Compare one `TargetEntry` against the destination path on disk.
///
/// Returns `Match` if the entry would be a no-op for `apply`; any other
/// variant means `apply` would have to write something.
///
/// # Errors
///
/// Returns an error only for unexpected I/O / decrypt failures, not for the
/// "files differ" case (which is reported as `MatchResult::Modified`).
#[allow(clippy::too_many_lines)]
pub fn matches_dest(
    entry: &TargetEntry,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    fail_on_decrypt_error: bool,
) -> Result<MatchResult> {
    match entry {
        TargetEntry::File { content, mode, .. } => {
            if !dest_path.as_path().exists() {
                return Ok(MatchResult::Missing);
            }

            let target_content_decrypted =
                decrypt_inline_age_values(content, identities, fail_on_decrypt_error)?;

            let Ok(existing_content) = fs::read(dest_path.as_path()) else {
                return Ok(MatchResult::Modified);
            };
            if existing_content != target_content_decrypted {
                return Ok(MatchResult::Modified);
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(target_mode) = mode
                    && let Ok(metadata) = fs::metadata(dest_path.as_path())
                {
                    let current_mode = metadata.permissions().mode() & PERM_MASK;
                    let target_mode_masked = *target_mode & PERM_MASK;
                    if current_mode != target_mode_masked {
                        return Ok(MatchResult::Modified);
                    }
                }
            }

            Ok(MatchResult::Match)
        }
        TargetEntry::Directory { mode, .. } => {
            if !dest_path.as_path().exists() {
                return Ok(MatchResult::Missing);
            }
            if !dest_path.as_path().is_dir() {
                return Ok(MatchResult::Modified);
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(target_mode) = mode
                    && let Ok(metadata) = fs::metadata(dest_path.as_path())
                {
                    let current_mode = metadata.permissions().mode() & PERM_MASK;
                    if current_mode != *target_mode {
                        return Ok(MatchResult::Modified);
                    }
                }
            }

            Ok(MatchResult::Match)
        }
        TargetEntry::Symlink { target, .. } => {
            if !dest_path.as_path().exists() {
                return Ok(MatchResult::Missing);
            }
            if !dest_path.as_path().is_symlink() {
                return Ok(MatchResult::Modified);
            }
            if let Ok(existing_target) = fs::read_link(dest_path.as_path()) {
                if existing_target != target.as_path() {
                    return Ok(MatchResult::Modified);
                }
            } else {
                return Ok(MatchResult::Modified);
            }
            Ok(MatchResult::Match)
        }
    }
}

/// Decrypt any `age:base64...` inline values in a UTF-8 text file.
///
/// - If the content is not valid UTF-8, returns it unchanged (binary file).
/// - If no `age:` prefix is present, returns the original content.
/// - If no identities are available, returns the original content.
/// - On decrypt failure, behaviour depends on `fail_on_decrypt_error`.
///
/// # Errors
///
/// Returns an error only when `fail_on_decrypt_error` is `true` and the
/// decryption call itself fails. Non-UTF-8 content, missing `age:` prefix,
/// and empty identity lists are all short-circuited and do **not** produce
/// errors.
pub fn decrypt_inline_age_values(
    content: &[u8],
    identities: &[guisu_crypto::Identity],
    fail_on_decrypt_error: bool,
) -> Result<Vec<u8>> {
    let Ok(content_str) = std::str::from_utf8(content) else {
        return Ok(content.to_vec());
    };

    if !content_str.contains("age:") {
        return Ok(content.to_vec());
    }

    if identities.is_empty() {
        return Ok(content.to_vec());
    }

    match guisu_crypto::decrypt_file_content(content_str, identities) {
        Ok(decrypted) => Ok(decrypted.into_bytes()),
        Err(e) => {
            if fail_on_decrypt_error {
                Err(guisu_core::Error::InlineDecryption {
                    message: format!(
                        "Failed to decrypt inline age values in file. \
                         This usually means the wrong identity was used or the encrypted value is corrupted. \
                         Error: {e}"
                    ),
                })
            } else {
                tracing::warn!(
                    "Failed to decrypt inline age values in file. \
                     Content will be returned with encrypted age: values intact. \
                     Error: {}",
                    e
                );
                Ok(content.to_vec())
            }
        }
    }
}
