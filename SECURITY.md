# Security Policy

## Responsible Use

jscript-agent is designed for **legitimate security research, authorized penetration testing, and
educational purposes**. Users must ensure they have proper authorization before deploying it in
any environment. See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

## Supported Versions

Security updates are applied to the latest version on the `main` branch only. We do not maintain
separate release branches at this time.

| Version | Supported |
|---------|-----------|
| `main` (latest) | Yes |
| Older commits | No |

## Reporting a Vulnerability

If you discover a security vulnerability in jscript-agent, please report it **privately** rather
than opening a public issue.

### How to Report

1. **Email:** Send a detailed report to the project maintainer (see GitHub profile for contact information)
2. **GitHub Security Advisories:** Use [GitHub's private vulnerability reporting](https://github.com/mrzaxaryan/jscript-agent/security/advisories/new) to submit a confidential advisory

### What to Include

- A clear description of the vulnerability
- Steps to reproduce the issue
- The affected host (mshta, cscript) and Windows version
- Any potential impact or exploit scenario
- Suggested fix, if available

### Response Timeline

- **Acknowledgment:** Within 48 hours of receiving the report
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Depends on severity and complexity; we aim to resolve critical issues as quickly as possible

### What to Expect

- We will acknowledge your report and keep you informed of progress
- We will credit you in the fix (unless you prefer to remain anonymous)
- We ask that you do not publicly disclose the vulnerability until a fix is available

## Detection Guidance

Defensive detection guidance for this agent — network and host indicators, hunting rules, a MITRE
ATT&CK mapping, and forensic triage steps — is maintained in [DEFENSE.md](DEFENSE.md).

## Scope

The following are considered in scope for security reports:

- The beacon protocol implementation (malformed-command handling, response encoding)
- The UpgradeNetFramework arm's payload parsing (header-line parsing, env-var application, blob decode)
- Identity derivation issues (accidental information disclosure beyond the documented header set)
- Memory or parser issues in the JScript engine triggered by this file's constructs

The following are **out of scope**:

- Misuse of jscript-agent for unauthorized purposes
- Vulnerabilities that require prior unauthorized access to the target machine
- Detection-evasion feature requests (obfuscation quality is the consuming C2's concern)
- Social engineering attacks

## Disclosure Policy

We follow a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. We acknowledge and assess the report
3. We develop and test a fix
4. We release the fix and publicly disclose the vulnerability
5. Reporter is credited (if desired)
