# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in go-annotate, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: [maintainer-email@example.com]

Include the following information:
- Type of issue (buffer overflow, injection, etc.)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Process

1. **Acknowledgment**: We'll acknowledge receipt within 48 hours
2. **Investigation**: We'll investigate and validate the issue
3. **Resolution**: We'll work on a fix and coordinate disclosure
4. **Publication**: We'll publish a security advisory after the fix is available

### Security Considerations for Users

#### Safe Usage Guidelines

1. **Input Validation**: Only instrument trusted Go source code
2. **Log Destination Security**: 
   - Secure file permissions for log files (600 or 640)
   - Use encrypted channels for network logging
   - Validate socket addresses to prevent SSRF
3. **Environment Variables**: Protect configuration in production environments

#### Potential Security Risks

1. **Code Injection**: Malicious source code could exploit AST parsing
2. **Information Disclosure**: Logs may contain sensitive data
3. **Network Security**: Socket mode may expose data over network
4. **File System Access**: File mode requires appropriate permissions

#### Mitigation Strategies

- Run go-annotate in isolated environments when processing untrusted code
- Implement log rotation and secure storage for sensitive applications
- Use network security controls (firewalls, VPNs) for socket mode
- Regular security updates and monitoring

## Security Features

- **Memory Safety**: Uses Go's memory-safe runtime
- **Input Validation**: AST parsing validates Go syntax
- **Non-blocking Operations**: Prevents denial-of-service through blocking
- **Error Handling**: Graceful failure modes prevent crashes

## Acknowledgments

We appreciate security researchers and users who report vulnerabilities responsibly.