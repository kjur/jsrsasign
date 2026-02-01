# Security Policy

## Reporting Security Vulnerabilities

The jsrsasign library is a cryptography library used in many production applications. We take security very seriously.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:
1. GitHub's private vulnerability reporting feature
2. Direct email to the maintainer

### What to Include

- Type of vulnerability (e.g., cryptographic weakness, injection, etc.)
- Full paths of source file(s) related to the issue
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact assessment

### Response Process

1. **Acknowledgment**: Within 48 hours
2. **Initial Assessment**: Within 7 days
3. **Fix Development**: Timeline depends on severity
4. **Disclosure**: Coordinated with reporter

## Security Best Practices

When using jsrsasign:

### Key Management
- Never hardcode private keys in source code
- Use secure key storage mechanisms
- Rotate keys periodically

### Algorithm Selection
- Use RSA keys of at least 2048 bits
- Prefer RSASSA-PSS over PKCS#1 v1.5 for new implementations
- Use ECDSA with P-256 or higher curves

### Input Validation
- Always validate certificate chains
- Check certificate validity periods
- Verify signatures before trusting data

### Dependencies
- Keep jsrsasign updated to the latest version
- Monitor security advisories

## Known Security Considerations

- This library is designed for client-side JavaScript; for server-side crypto, consider native solutions
- Random number generation relies on the browser's crypto API
- Performance-sensitive operations should use Web Crypto API when available

## Acknowledgments

We thank all security researchers who responsibly disclose vulnerabilities.
