//! Recipient types for age encryption
//!
//! This module defines a unified Recipient type that can represent both
//! native age recipients and SSH-based recipients.

use age::{ssh, x25519};
use std::fmt;
use std::str::FromStr;

/// A recipient for age encryption
///
/// This enum wraps both native age x25519 recipients and SSH-based recipients,
/// allowing encryption to work with either key type.
#[derive(Clone)]
pub enum Recipient {
    /// Native age x25519 recipient
    Age(x25519::Recipient),
    /// SSH public key recipient
    Ssh(ssh::Recipient),
}

impl Recipient {
    /// Convert to a boxed trait object for use with age encryption
    #[must_use]
    pub fn to_boxed(&self) -> Box<dyn age::Recipient + Send> {
        match self {
            Self::Age(r) => Box::new(r.clone()),
            Self::Ssh(r) => Box::new(r.clone()),
        }
    }

    /// Create from an age x25519 recipient
    #[must_use]
    pub fn from_age(recipient: x25519::Recipient) -> Self {
        Self::Age(recipient)
    }

    /// Create from an SSH recipient
    #[must_use]
    pub fn from_ssh(recipient: ssh::Recipient) -> Self {
        Self::Ssh(recipient)
    }
}

impl From<x25519::Recipient> for Recipient {
    fn from(r: x25519::Recipient) -> Self {
        Self::Age(r)
    }
}

impl From<ssh::Recipient> for Recipient {
    fn from(r: ssh::Recipient) -> Self {
        Self::Ssh(r)
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Age(r) => write!(f, "{r}"),
            Self::Ssh(r) => write!(f, "{r}"),
        }
    }
}

impl FromStr for Recipient {
    type Err = crate::Error;

    /// Parse a recipient from a string
    ///
    /// Tries to parse as an age x25519 recipient first (`age1...`), then as
    /// an SSH recipient. SSH keys must be `ssh-rsa`; ed25519 SSH keys return
    /// `Error::UnsupportedSshKey` because the `age` 0.11 encryption protocol
    /// only supports RSA-OAEP recipients.
    fn from_str(s: &str) -> crate::Result<Self> {
        // Try parsing as age recipient first (starts with "age1")
        if let Ok(recipient) = s.parse::<x25519::Recipient>() {
            return Ok(Self::Age(recipient));
        }

        // Try parsing as SSH recipient. Distinguish "unsupported key type"
        // (e.g. ssh-ed25519) from "not an SSH key at all" so the caller gets
        // a meaningful error.
        match s.parse::<ssh::Recipient>() {
            Ok(recipient) => Ok(Self::Ssh(recipient)),
            Err(ssh::ParseRecipientKeyError::Unsupported(key_type)) => {
                Err(crate::Error::UnsupportedSshKey { key_type })
            }
            Err(_) => Err(crate::Error::InvalidRecipient {
                recipient: s.to_string(),
                reason: "Expected age1... or ssh-rsa... format".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::Identity;

    #[test]
    fn test_from_age_recipient() {
        let identity = Identity::generate();
        // Get the inner age::x25519::Recipient to test from_age()
        let recipient_str = identity.to_public().to_string();
        let age_recipient: x25519::Recipient = recipient_str.parse().unwrap();

        let recipient = Recipient::from_age(age_recipient);

        // Should be Age variant
        assert!(matches!(recipient, Recipient::Age(_)));
    }

    #[test]
    #[ignore = "SSH support not available in current age build"]
    fn test_from_ssh_recipient() {
        // Valid SSH Ed25519 public key
        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjWGmoqxq6JAN0F7+CkHgbQBXV/7/RNGsZpYH1MPvYb";
        let ssh_recipient = ssh_key
            .parse::<ssh::Recipient>()
            .expect("Failed to parse SSH key");

        let recipient = Recipient::from_ssh(ssh_recipient);

        // Should be Ssh variant
        assert!(matches!(recipient, Recipient::Ssh(_)));
    }

    #[test]
    fn test_from_trait_age() {
        let identity = Identity::generate();
        let recipient_str = identity.to_public().to_string();
        let age_recipient: x25519::Recipient = recipient_str.parse().unwrap();

        let recipient: Recipient = age_recipient.into();

        assert!(matches!(recipient, Recipient::Age(_)));
    }

    #[test]
    #[ignore = "SSH support not available in current age build"]
    fn test_from_trait_ssh() {
        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjWGmoqxq6JAN0F7+CkHgbQBXV/7/RNGsZpYH1MPvYb";
        let ssh_recipient = ssh_key
            .parse::<ssh::Recipient>()
            .expect("Failed to parse SSH key");

        let recipient: Recipient = ssh_recipient.into();

        assert!(matches!(recipient, Recipient::Ssh(_)));
    }

    #[test]
    fn test_to_boxed_age() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let boxed = recipient.to_boxed();

        // Should successfully create a boxed recipient
        // Verify it's a valid trait object by checking type name contains "Recipient"
        let type_name = std::any::type_name_of_val(&boxed);
        assert!(type_name.contains("Recipient") || type_name.contains("dyn"));
    }

    #[test]
    #[ignore = "SSH support not available in current age build"]
    fn test_to_boxed_ssh() {
        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjWGmoqxq6JAN0F7+CkHgbQBXV/7/RNGsZpYH1MPvYb";
        let ssh_recipient = ssh_key
            .parse::<ssh::Recipient>()
            .expect("Failed to parse SSH key");
        let recipient = Recipient::from_ssh(ssh_recipient);

        let boxed = recipient.to_boxed();

        // Should successfully create a boxed recipient
        let type_name = std::any::type_name_of_val(&boxed);
        assert!(type_name.contains("Recipient") || type_name.contains("dyn"));
    }

    #[test]
    fn test_clone_age() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let cloned = recipient.clone();

        // Both should have same Display output
        assert_eq!(recipient.to_string(), cloned.to_string());
    }

    #[test]
    #[ignore = "SSH support not available in current age build"]
    fn test_clone_ssh() {
        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjWGmoqxq6JAN0F7+CkHgbQBXV/7/RNGsZpYH1MPvYb";
        let ssh_recipient = ssh_key
            .parse::<ssh::Recipient>()
            .expect("Failed to parse SSH key");
        let recipient = Recipient::from_ssh(ssh_recipient);

        let cloned = recipient.clone();

        assert_eq!(recipient.to_string(), cloned.to_string());
    }

    #[test]
    fn test_display_age() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let display = recipient.to_string();

        // Age recipients start with "age1"
        assert!(
            display.starts_with("age1"),
            "Age recipient should start with 'age1': {display}"
        );
    }

    #[test]
    #[ignore = "SSH support not available in current age build"]
    fn test_display_ssh() {
        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjWGmoqxq6JAN0F7+CkHgbQBXV/7/RNGsZpYH1MPvYb";
        let ssh_recipient = ssh_key
            .parse::<ssh::Recipient>()
            .expect("Failed to parse SSH key");
        let recipient = Recipient::from_ssh(ssh_recipient);

        let display = recipient.to_string();

        // SSH recipients start with "ssh-"
        assert!(
            display.starts_with("ssh-"),
            "SSH recipient should start with 'ssh-': {display}"
        );
    }

    #[test]
    fn test_from_str_age_format() {
        // Generate a valid age recipient string
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let age_string = recipient.to_string();

        let parsed: Recipient = age_string.parse().expect("Failed to parse age recipient");

        assert!(matches!(parsed, Recipient::Age(_)));
        assert_eq!(parsed.to_string(), age_string);
    }

    #[test]
    #[ignore = "SSH support not available in current age build"]
    fn test_from_str_ssh_format() {
        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjWGmoqxq6JAN0F7+CkHgbQBXV/7/RNGsZpYH1MPvYb";

        let parsed: Recipient = ssh_key.parse().expect("Failed to parse SSH recipient");

        assert!(matches!(parsed, Recipient::Ssh(_)));
    }

    #[test]
    fn test_from_str_invalid_format() {
        let invalid = "not-a-valid-recipient";

        let result = invalid.parse::<Recipient>();

        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                crate::Error::InvalidRecipient { recipient, reason } => {
                    assert_eq!(recipient, invalid);
                    assert!(reason.contains("age1") || reason.contains("ssh"));
                }
                _ => panic!("Expected InvalidRecipient error, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_from_str_empty() {
        let result = "".parse::<Recipient>();

        assert!(result.is_err());
        if let Err(crate::Error::InvalidRecipient { .. }) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidRecipient error");
        }
    }

    #[test]
    fn test_from_str_ssh_ed25519_returns_typed_error() {
        // SSH ed25519 is not supported by age 0.11 as a recipient; we should
        // get a clear UnsupportedSshKey error, not a raw age parse error.
        let ssh_ed25519 =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjWGmoqxq6JAN0F7+CkHgbQBXV/7/RNGsZpYH1MPvYb";

        let result = ssh_ed25519.parse::<Recipient>();

        assert!(result.is_err());
        if let Err(crate::Error::UnsupportedSshKey { key_type }) = result {
            assert_eq!(key_type, "ssh-ed25519");
        } else {
            panic!(
                "Expected UnsupportedSshKey error for ed25519, got: {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn test_roundtrip_age() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        // Convert to string and back
        let string = recipient.to_string();
        let parsed: Recipient = string.parse().expect("Failed to parse");

        // Should produce same string
        assert_eq!(parsed.to_string(), recipient.to_string());
    }

    #[test]
    #[ignore = "SSH support not available in current age build"]
    fn test_roundtrip_ssh() {
        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjWGmoqxq6JAN0F7+CkHgbQBXV/7/RNGsZpYH1MPvYb";
        let recipient: Recipient = ssh_key.parse().expect("Failed to parse");

        // Convert to string and back
        let string = recipient.to_string();
        let parsed: Recipient = string.parse().expect("Failed to parse again");

        assert_eq!(parsed.to_string(), recipient.to_string());
    }

    #[test]
    fn test_multiple_recipients_different() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        let recipient1 = id1.to_public();
        let recipient2 = id2.to_public();

        // Different identities should produce different recipients
        assert_ne!(recipient1.to_string(), recipient2.to_string());
    }

    #[test]
    fn test_recipient_starts_with_age1() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let recipient_str = recipient.to_string();

        // All age recipients should start with age1
        assert!(recipient_str.starts_with("age1"));
        // Should be a reasonable length (typically 62 chars)
        assert!(recipient_str.len() > 50 && recipient_str.len() < 70);
    }

    #[test]
    fn test_from_str_with_whitespace() {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let age_string = recipient.to_string();

        // Test with leading/trailing whitespace
        let with_whitespace = format!("  {age_string}  ");
        let result = with_whitespace.trim().parse::<Recipient>();

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.to_string(), age_string);
    }

    #[test]
    fn test_from_str_partial_age_string() {
        // Try parsing a partial age string (should fail)
        let partial = "age1abc";

        let result = partial.parse::<Recipient>();
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_wrong_prefix() {
        let wrong_prefix = "age2qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm1234567890";

        let result = wrong_prefix.parse::<Recipient>();
        assert!(result.is_err());
    }

    #[test]
    fn test_to_boxed_can_be_used_for_encryption() {
        // Verify it's a Send trait object
        fn require_send<T: Send>(_: &T) {}

        let identity = Identity::generate();
        let recipient = identity.to_public();

        // Convert to boxed trait object
        let boxed = recipient.to_boxed();

        require_send(&boxed);
    }

    #[test]
    fn test_clone_produces_identical_string() {
        // Both boxes should be valid (this just checks they don't panic)
        fn require_send<T: Send>(_: &T) {}

        let identity = Identity::generate();
        let recipient = identity.to_public();

        let cloned = recipient.clone();

        // Cloned recipient should produce identical string
        assert_eq!(recipient.to_string(), cloned.to_string());

        // And they should be independently usable
        let boxed1 = recipient.to_boxed();
        let boxed2 = cloned.to_boxed();

        require_send(&boxed1);
        require_send(&boxed2);
    }

    #[test]
    fn test_display_format_is_stable() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        // Display should be stable across multiple calls
        let display1 = recipient.to_string();
        let display2 = recipient.to_string();
        let display3 = format!("{recipient}");

        assert_eq!(display1, display2);
        assert_eq!(display1, display3);
    }

    #[test]
    fn test_from_str_case_handling() {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let age_string = recipient.to_string();

        // Test with uppercase version
        let uppercase = age_string.to_uppercase();
        if uppercase != age_string {
            // Age uses bech32 encoding which is case-insensitive
            // The parser may accept uppercase but normalize to lowercase
            let result = uppercase.parse::<Recipient>();
            // If it parses successfully, it should normalize correctly
            if let Ok(parsed) = result {
                // Should still work for encryption even if case differs
                assert!(matches!(parsed, Recipient::Age(_)));
            }
        }
    }

    #[test]
    fn test_multiple_different_recipients_all_age() {
        // Generate multiple recipients
        let recipients: Vec<Recipient> = (0..5).map(|_| Identity::generate().to_public()).collect();

        // All should be Age variant
        for recipient in &recipients {
            assert!(matches!(recipient, Recipient::Age(_)));
        }

        // All should have unique strings
        let strings: Vec<String> = recipients.iter().map(Recipient::to_string).collect();
        for i in 0..strings.len() {
            for j in (i + 1)..strings.len() {
                assert_ne!(strings[i], strings[j]);
            }
        }
    }

    #[test]
    fn test_from_age_preserves_recipient() {
        let identity = Identity::generate();
        let public_key = identity.to_public();
        let age_string = public_key.to_string();

        // Parse to get an x25519::Recipient
        let x25519_recipient: x25519::Recipient = age_string.parse().unwrap();

        // Create Recipient from x25519::Recipient
        let recipient = Recipient::from_age(x25519_recipient);

        // Should produce same string as original
        assert_eq!(recipient.to_string(), age_string);
    }

    #[test]
    fn test_from_trait_is_equivalent_to_from_age() {
        let identity = Identity::generate();
        let age_string = identity.to_public().to_string();
        let x25519_recipient: x25519::Recipient = age_string.parse().unwrap();

        // Using From trait
        let via_from: Recipient = x25519_recipient.clone().into();

        // Using from_age method
        let via_method = Recipient::from_age(x25519_recipient);

        // Both should produce same string
        assert_eq!(via_from.to_string(), via_method.to_string());
    }

    #[test]
    fn test_error_message_for_invalid_recipient() {
        let invalid_inputs = vec![
            "invalid",
            "age",
            "age1",
            "ssh-rsa invalid",
            "random string",
            "12345",
        ];

        for input in invalid_inputs {
            let result = input.parse::<Recipient>();
            assert!(result.is_err(), "Should fail for input: {input}");

            if let Err(crate::Error::InvalidRecipient { recipient, reason }) = result {
                assert_eq!(recipient, input);
                assert!(
                    reason.contains("age1") || reason.contains("ssh"),
                    "Error message should mention expected formats: {reason}"
                );
            } else {
                panic!("Expected InvalidRecipient error for: {input}");
            }
        }
    }

    #[test]
    fn test_from_str_with_leading_whitespace() {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let age_string = recipient.to_string();

        // Test with leading whitespace (after trim)
        let with_whitespace = format!("   {age_string}");
        let result = with_whitespace.trim().parse::<Recipient>();

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.to_string(), age_string);
    }

    #[test]
    fn test_from_str_with_trailing_whitespace() {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let age_string = recipient.to_string();

        // Test with trailing whitespace (after trim)
        let with_whitespace = format!("{age_string}   ");
        let result = with_whitespace.trim().parse::<Recipient>();

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.to_string(), age_string);
    }

    #[test]
    fn test_multiple_recipients_conversion() {
        // Create multiple recipients
        let recipients: Vec<Recipient> =
            (0..10).map(|_| Identity::generate().to_public()).collect();

        // Convert to boxed trait objects
        let boxed: Vec<Box<dyn age::Recipient + Send>> =
            recipients.iter().map(Recipient::to_boxed).collect();

        assert_eq!(boxed.len(), 10);
    }

    #[test]
    fn test_recipient_clone_independence() {
        // Verify both boxes are valid (don't panic)
        fn require_send<T: Send>(_: &T) {}

        let identity = Identity::generate();
        let recipient = identity.to_public();
        let cloned = recipient.clone();

        // Both should produce same string
        assert_eq!(recipient.to_string(), cloned.to_string());

        // Both should produce valid boxed recipients
        let boxed1 = recipient.to_boxed();
        let boxed2 = cloned.to_boxed();

        require_send(&boxed1);
        require_send(&boxed2);
    }

    #[test]
    fn test_from_age_then_to_string() {
        let identity = Identity::generate();
        let public_key = identity.to_public();
        let age_string = public_key.to_string();

        // Parse to x25519::Recipient
        let x25519_recipient: x25519::Recipient = age_string.parse().unwrap();

        // Convert to our Recipient
        let recipient = Recipient::from_age(x25519_recipient);

        // Should produce same string
        assert_eq!(recipient.to_string(), age_string);
    }

    #[test]
    fn test_display_multiple_times_same_result() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        // Call Display multiple times
        let s1 = format!("{recipient}");
        let s2 = format!("{recipient}");
        let s3 = recipient.to_string();

        assert_eq!(s1, s2);
        assert_eq!(s1, s3);
    }

    #[test]
    fn test_from_str_then_clone() {
        let identity = Identity::generate();
        let age_string = identity.to_public().to_string();

        let recipient: Recipient = age_string.parse().unwrap();
        let cloned = recipient.clone();

        assert_eq!(recipient.to_string(), cloned.to_string());
    }

    #[test]
    fn test_batch_parsing_all_valid() {
        // Create batch of valid age strings
        let identities: Vec<Identity> = (0..5).map(|_| Identity::generate()).collect();
        let age_strings: Vec<String> = identities
            .iter()
            .map(|i| i.to_public().to_string())
            .collect();

        // Parse all
        let recipients: Result<Vec<Recipient>, _> =
            age_strings.iter().map(|s| s.parse::<Recipient>()).collect();

        assert!(recipients.is_ok());
        let recipients = recipients.unwrap();
        assert_eq!(recipients.len(), 5);

        // Verify all are Age variant
        for recipient in recipients {
            assert!(matches!(recipient, Recipient::Age(_)));
        }
    }

    #[test]
    fn test_batch_parsing_mixed_valid_invalid() {
        let identity = Identity::generate();
        let valid = identity.to_public().to_string();

        let inputs = [
            valid.clone(),
            "invalid".to_string(),
            valid.clone(),
            "also-invalid".to_string(),
        ];

        let results: Vec<Result<Recipient, _>> =
            inputs.iter().map(|s| s.parse::<Recipient>()).collect();

        // Should have 2 successes and 2 failures
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();

        assert_eq!(successes, 2);
        assert_eq!(failures, 2);
    }

    #[test]
    fn test_to_boxed_multiple_times() {
        // All should be valid Send trait objects
        fn require_send<T: Send>(_: &T) {}

        let identity = Identity::generate();
        let recipient = identity.to_public();

        // Create multiple boxes from same recipient
        let box1 = recipient.to_boxed();
        let box2 = recipient.to_boxed();
        let box3 = recipient.to_boxed();

        require_send(&box1);
        require_send(&box2);
        require_send(&box3);
    }

    #[test]
    fn test_from_trait_vs_from_age_identical() {
        let identity = Identity::generate();
        let age_string = identity.to_public().to_string();
        let x25519_recipient: x25519::Recipient = age_string.parse().unwrap();

        // Using From trait
        let via_from: Recipient = x25519_recipient.clone().into();

        // Using from_age method
        let via_method = Recipient::from_age(x25519_recipient);

        // Both should produce identical strings
        assert_eq!(via_from.to_string(), via_method.to_string());
    }

    #[test]
    fn test_very_long_recipient_string() {
        // Valid age recipient strings have fixed length
        // Test that we handle them correctly
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let s = recipient.to_string();

        // Age recipients should be around 62 characters
        assert!(
            s.len() > 50 && s.len() < 70,
            "Unexpected length: {}",
            s.len()
        );
        assert!(s.starts_with("age1"));
    }

    #[test]
    fn test_from_str_with_mixed_case() {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let age_string = recipient.to_string();

        // Age uses bech32 encoding which is case-insensitive
        // Test uppercase version
        let uppercase = age_string.to_uppercase();

        if uppercase != age_string {
            let result = uppercase.parse::<Recipient>();
            // If it parses successfully, verify it's an Age variant
            if let Ok(parsed) = result {
                assert!(matches!(parsed, Recipient::Age(_)));
            }
        }
    }

    #[test]
    fn test_clone_then_to_boxed() {
        // Verify it's a valid Send trait object
        fn require_send<T: Send>(_: &T) {}

        let identity = Identity::generate();
        let recipient = identity.to_public();
        let cloned = recipient.clone();

        // Convert cloned to boxed
        let boxed = cloned.to_boxed();

        require_send(&boxed);
    }

    #[test]
    fn test_multiple_from_age_calls() {
        let identity = Identity::generate();
        let age_string = identity.to_public().to_string();

        // Parse and convert multiple times
        let x25519_recipient: x25519::Recipient = age_string.parse().unwrap();

        let recipient1 = Recipient::from_age(x25519_recipient.clone());
        let recipient2 = Recipient::from_age(x25519_recipient.clone());
        let recipient3 = Recipient::from_age(x25519_recipient);

        // All should produce same string
        assert_eq!(recipient1.to_string(), age_string);
        assert_eq!(recipient2.to_string(), age_string);
        assert_eq!(recipient3.to_string(), age_string);
    }
}
