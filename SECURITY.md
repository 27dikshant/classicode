# Security Policy

## Overview

ClassiCode is an enterprise-grade security extension designed to prevent code leakage through automated file classification and data loss prevention. The security of this tool is paramount given its role in protecting sensitive enterprise data.

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting Security Vulnerabilities

**DO NOT** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Instead, please report security vulnerabilities privately via email to:

**📧 Security Contact: Dikshant <27dikshant@gmail.com>**

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact on ClassiCode users and their data
- **Reproduction**: Step-by-step instructions to reproduce the issue
- **Environment**: VS Code version, ClassiCode version, operating system
- **Evidence**: Screenshots, logs, or proof-of-concept code (if applicable)

### Response Timeline

- **Acknowledgment**: Within 48 hours of report submission
- **Initial Assessment**: Within 5 business days
- **Resolution Timeline**: Varies by severity (Critical: 7-14 days, High: 30 days, Medium/Low: 60-90 days)

## Responsible Disclosure

We follow responsible disclosure principles:

1. **Report First**: Contact us privately before public disclosure
2. **Coordination**: Work with us to understand and validate the issue
3. **Timeline**: Allow reasonable time for fixes before public disclosure
4. **Credit**: We will acknowledge your contribution (unless you prefer anonymity)

## Security Considerations for ClassiCode

Given ClassiCode's security-focused nature, we are particularly concerned with:

### Critical Security Areas

- **Metadata Integrity**: Tampering with file classification data
- **DLP Bypass**: Circumventing data loss prevention controls
- **Privilege Escalation**: Unauthorized access to classified files
- **Data Leakage**: Unintended exposure of sensitive information
- **Authentication**: Verification of classification authority

### Out of Scope

The following are generally **not** considered security vulnerabilities:

- Issues requiring physical access to the user's machine
- Social engineering attacks
- Vulnerabilities in VS Code itself or third-party extensions
- Issues requiring user to install malicious extensions
- Denial of service against individual user installations

## Security Best Practices for Users

When using ClassiCode in enterprise environments:

- **Regular Updates**: Keep ClassiCode updated to the latest version
- **File System Permissions**: Ensure proper file system permissions
- **Network Security**: Use in secure network environments
- **Access Controls**: Implement appropriate user access controls
- **Audit Logging**: Monitor and review classification activities
- **Backup Verification**: Regularly verify classification metadata integrity

## Security Features

ClassiCode implements several security controls:

- **Extended Attributes (xattrs)**: Permanent metadata storage
- **Cryptographic Integrity**: Hash-based tamper detection
- **Multi-location Backup**: Redundant classification storage
- **Real-time Monitoring**: Active protection against unauthorized operations
- **Audit Trail**: Comprehensive logging of security events

## Contact

For security-related questions or concerns:

**📧 Dikshant <27dikshant@gmail.com>**

For general support and non-security issues, please use the [GitHub Issues](https://github.com/27dikshant/classicode/issues) page.

---

*This security policy is reviewed and updated regularly to ensure the highest standards of security for ClassiCode users.*