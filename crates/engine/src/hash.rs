//! Content hashing using blake3
//!
//! This module provides fast, cryptographically-secure hashing for content comparison.
//! blake3 is 3-10x faster than SHA256 while maintaining cryptographic security.

use std::fs::File;
use std::io::{BufReader, Result as IoResult};
use std::path::Path;

/// Hash content using blake3
///
/// This is the primary function for hashing file content and data for
/// change detection and state tracking.
///
/// # Performance
///
/// blake3 achieves ~3-10 GB/s throughput on modern CPUs through SIMD optimization
/// and parallel processing, making it 3-10x faster than SHA256.
///
/// Returns a fixed-size array allocated on the stack (zero heap allocations),
/// which is more efficient than returning a `Vec<u8>` for comparison operations.
///
/// # Security
///
/// blake3 is cryptographically secure and suitable for:
/// - Content verification
/// - Collision-resistant hashing
/// - Digital signatures
///
/// # Examples
///
/// ```
/// use guisu_engine::hash_content;
///
/// let content = b"Hello, world!";
/// let hash = hash_content(content);
/// assert_eq!(hash.len(), 32); // 256-bit hash
/// ```
#[must_use]
pub fn hash_content(content: &[u8]) -> [u8; 32] {
    *blake3::hash(content).as_bytes()
}

/// Hash a large file with buffered reading
///
/// This function is optimized for large files by using buffered I/O
/// and blake3's streaming hasher, which can process data in parallel.
///
/// # Performance
///
/// For files larger than 1MB, this is more efficient than reading the
/// entire file into memory before hashing.
///
/// Returns a fixed-size array allocated on the stack (zero heap allocations).
///
/// # Examples
///
/// ```no_run
/// use guisu_engine::hash_file;
/// use std::path::Path;
///
/// # fn main() -> std::io::Result<()> {
/// let path = Path::new("/path/to/large/file");
/// let hash = hash_file(path)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
pub fn hash_file(path: &Path) -> IoResult<[u8; 32]> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut reader, &mut hasher)?;
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_content_deterministic() {
        let content = b"Hello, world!";
        let hash1 = hash_content(content);
        let hash2 = hash_content(content);

        assert_eq!(hash1, hash2, "Hashes should be deterministic");
        assert_eq!(hash1.len(), 32, "blake3 produces 256-bit (32-byte) hash");
    }

    #[test]
    fn test_hash_content_different() {
        let content1 = b"Hello, world!";
        let content2 = b"Hello, world?";
        let hash1 = hash_content(content1);
        let hash2 = hash_content(content2);

        assert_ne!(
            hash1, hash2,
            "Different content should produce different hashes"
        );
    }

    #[test]
    fn test_hash_content_empty() {
        let content = b"";
        let hash = hash_content(content);

        assert_eq!(
            hash.len(),
            32,
            "Hash of empty content should still be 32 bytes"
        );
        assert!(
            !hash.iter().all(|&b| b == 0),
            "Hash should not be all zeros"
        );
    }

    #[test]
    fn test_hash_content_large() {
        // Test with 1MB of data
        let content = vec![0xAB; 1024 * 1024];
        let hash1 = hash_content(&content);
        let hash2 = hash_content(&content);

        assert_eq!(
            hash1, hash2,
            "Large content hashing should be deterministic"
        );
    }

    #[test]
    fn test_hash_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"Test file content for hashing";
        temp_file.write_all(content).unwrap();
        temp_file.flush().unwrap();

        let hash_from_file = hash_file(temp_file.path()).unwrap();
        let hash_from_content = hash_content(content);

        assert_eq!(
            hash_from_file, hash_from_content,
            "File hash should match content hash"
        );
    }

    #[test]
    fn test_hash_file_nonexistent() {
        let result = hash_file(Path::new("/nonexistent/file"));
        assert!(result.is_err(), "Should error on nonexistent file");
    }

    #[test]
    fn test_hash_file_large() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write 10MB of data
        let chunk = vec![0x42; 1024 * 1024];
        for _ in 0..10 {
            temp_file.write_all(&chunk).unwrap();
        }
        temp_file.flush().unwrap();

        let hash = hash_file(temp_file.path()).unwrap();
        assert_eq!(hash.len(), 32, "Large file hash should be 32 bytes");
    }

    #[test]
    fn test_same_content_same_hash() {
        // Test the property that same content = same hash
        let content = b"Identical content";
        let hash1 = hash_content(content);
        let hash2 = hash_content(content);
        let hash3 = hash_content(content);

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    #[test]
    fn test_single_bit_difference() {
        // blake3 should produce completely different hashes for single bit differences
        let content1 = b"Test content 0";
        let content2 = b"Test content 1";
        let hash1 = hash_content(content1);
        let hash2 = hash_content(content2);

        assert_ne!(hash1, hash2);

        // Count different bytes (should be significant due to avalanche effect)
        let different_bytes = hash1
            .iter()
            .zip(hash2.iter())
            .filter(|&(a, b)| a != b)
            .count();

        assert!(
            different_bytes > hash1.len() / 4,
            "Single bit change should affect many hash bytes (avalanche effect)"
        );
    }
}
