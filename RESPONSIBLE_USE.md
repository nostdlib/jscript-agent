# Responsible Use Policy

## Purpose

jscript-agent is developed and maintained for the following legitimate purposes:

- **Education** -- Studying legacy script engines (JScript 5.8 / Windows Script Host), COM automation surfaces, HTTP command-and-control protocol design, and defensive detection engineering against script-host implants
- **Authorized Security Testing** -- Supporting professional penetration testers and red team operators who hold explicit written authorization from the system owner to conduct security assessments
- **Capture The Flag (CTF) Competitions** -- Providing a reference for techniques commonly encountered in offensive security competitions held in controlled, sanctioned environments
- **Academic and Independent Research** -- Enabling security researchers to study, document, and develop defenses against real-world offensive techniques in a transparent, open-source context

Detection engineering against this agent should start with [DEFENSE.md](DEFENSE.md).

## Prohibited Uses

The following uses of this software are strictly prohibited:

- **Unauthorized access** -- Deploying jscript-agent against any system, network, or environment without explicit written authorization from the owner or authorized representative
- **Malware development or distribution** -- Using jscript-agent code or techniques to create, package, or distribute malicious software intended to harm individuals, organizations, or infrastructure
- **Data theft or exfiltration** -- Using jscript-agent to steal, collect, or exfiltrate personal data, credentials, intellectual property, or any information without authorization
- **Denial of service** -- Using jscript-agent to disrupt, degrade, or deny availability of systems, services, or networks
- **Evasion of lawful security controls** -- Using jscript-agent to circumvent security measures on systems you are not authorized to test
- **Surveillance** -- Using jscript-agent to monitor, track, or surveil individuals without proper legal authority and consent
- **Commercial exploitation without compliance** -- Redistributing or using jscript-agent in violation of the MIT license terms

## User Responsibility

By using this software, you acknowledge and agree to the following:

1. **Authorization** -- You will only deploy jscript-agent in environments where you have obtained explicit written authorization from the system owner or an authorized representative. Verbal agreements are insufficient.

2. **Legal compliance** -- You are solely responsible for ensuring your use of jscript-agent complies with all applicable local, state, federal, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

3. **Scope adherence** -- When conducting authorized security assessments, you will operate strictly within the agreed-upon scope, targets, and timeframes defined in your authorization documentation.

4. **Professional standards** -- You will follow industry-recognized standards and best practices for penetration testing and security research, such as those defined by PTES, OWASP, and NIST.

5. **No warranty** -- This software is provided "as is" without warranty of any kind. The authors and contributors are not responsible for any damages, legal consequences, or liabilities arising from the use or misuse of this software.

6. **Indemnification** -- You agree to indemnify and hold harmless the authors, contributors, and maintainers of jscript-agent from any claims, damages, or legal actions resulting from your use of the software.

## Reporting Vulnerabilities

If you discover a security vulnerability in jscript-agent itself, please follow the responsible disclosure process outlined in [SECURITY.md](SECURITY.md):

1. **Do not** open a public issue for security vulnerabilities
2. Report the vulnerability privately via [GitHub Security Advisories](https://github.com/mrzaxaryan/jscript-agent/security/advisories/new) or by contacting the maintainer directly
3. Include a clear description, reproduction steps, affected platforms, and potential impact
4. Allow reasonable time for the maintainers to develop and release a fix before any public disclosure

## Reporting Misuse

If you become aware of jscript-agent being used in violation of this policy or for unauthorized purposes, please report it to the project maintainers through the same private channels described in [SECURITY.md](SECURITY.md).

## Acknowledgment

By downloading, cloning, or otherwise using this software, you acknowledge that you have read, understood, and agree to abide by this Responsible Use Policy, the project [LICENSE](LICENSE), and the [Security Policy](SECURITY.md).
