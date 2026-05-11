# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |

## Known Vulnerabilities

### RUSTSEC-2023-0071: RSA Timing Side-Channel (Marvin Attack)

**Severity**: Medium (5.9)

**Affected Component**: `rsa` crate v0.9.10 (transitive dependency through `age`)

**Description**: The RSA implementation used by the `age` encryption library has a potential key recovery vulnerability through timing side-channels.

**Impact on Guisu**: This vulnerability affects the SSH private key encryption feature when using age format with RSA keys. For dotfile management use cases, the practical risk is low since:

1. Attack requires repeated cryptographic operations with the same key
2. Dotfiles typically don't contain high-value cryptographic keys
3. The attack is theoretical and has not been demonstrated in practice

**Status**: No fix available. The `rsa` crate maintainers have not released a patched version. Upstream `age` crate depends on `rsa 0.9.x` and has not yet adopted `rsa 0.10`.

**Workaround**: Use passphrase-protected SSH keys or switch to age encryption with symmetric keys (passphrase-based).

**References**:
- https://rustsec.org/advisories/RUSTSEC-2023-0071
- https://github.com/str4d/rage/issues

---

## Reporting a Vulnerability

For security issues, please email the maintainer directly rather than opening a public issue.
