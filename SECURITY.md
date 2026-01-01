# Security Policy

Thank you for helping keep Hamburglar and its users safe. We take security seriously and appreciate responsible disclosure of vulnerabilities.

## Supported Versions

The following versions of Hamburglar receive security updates:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

We recommend always using the latest release for the most up-to-date security fixes.

## Reporting a Vulnerability

If you discover a security vulnerability in Hamburglar, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities.

2. **Email the maintainers directly** at: adam@needmorecowbell.dev

3. Include the following information in your report:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
- **Assessment**: We will investigate and assess the severity of the issue within 7 days.
- **Updates**: We will keep you informed of our progress throughout the process.
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days.
- **Credit**: With your permission, we will credit you in the security advisory and changelog.

### Scope

The following are considered in scope for security reports:

- Vulnerabilities in Hamburglar's core scanning functionality
- Issues that could allow arbitrary code execution
- Security issues in dependency handling
- Information disclosure vulnerabilities
- Vulnerabilities in the plugin system that could be exploited

### Out of Scope

The following are generally not considered security vulnerabilities:

- Issues requiring physical access to the machine running Hamburglar
- Issues in third-party dependencies (please report these to the respective projects)
- Social engineering attacks
- Denial of service attacks that require excessive resources
- Findings that Hamburglar correctly detects (this is expected behavior)

## Security Best Practices

When using Hamburglar:

1. **Run with minimal privileges**: Only grant Hamburglar the permissions it needs to read the files you want to scan.

2. **Review output carefully**: Findings may contain sensitive information. Handle scan results securely.

3. **Keep Hamburglar updated**: Always use the latest version to benefit from security patches.

4. **Validate plugins**: Only install plugins from trusted sources. Review plugin code before installation.

5. **Secure your scan results**: If storing results in a database or files, ensure appropriate access controls are in place.

## Security Features

Hamburglar includes several security-conscious features:

- **Read-only scanning**: Hamburglar only reads files; it does not modify scanned content.
- **Configurable output redaction**: Sensitive matches can be partially redacted in output.
- **Local processing**: All scanning happens locally; no data is sent to external services.
- **Sandboxed YARA execution**: YARA rules are executed in a controlled environment.

## Acknowledgments

We thank the following individuals for responsibly disclosing security issues:

*No security issues have been reported yet.*

---

For general bug reports and feature requests, please use the [GitHub Issues](https://github.com/needmorecowbell/Hamburglar/issues) page.
