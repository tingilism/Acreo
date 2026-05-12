# Security Policy

## Reporting a vulnerability

If you find a security issue in Acreo Protocol â€” in the contracts, the
documentation, or the threat model â€” please report it responsibly.

**Preferred channel:** open a private security advisory via GitHub at
https://github.com/spencerkourpa-debug/acreo/security/advisories/new

**Alternative:** contact the maintainers directly via DM on the Anba
Labs Twitter / X account.

## Disclosure window

We commit to:
- Acknowledge receipt within 72 hours
- Triage and respond with severity assessment within 7 days
- Coordinate public disclosure with the reporter, typically 30-90 days
  from initial report depending on severity and remediation complexity

## Scope

In scope:
- Smart contract vulnerabilities in any contract under `contracts/`
- Cryptographic flaws in policy designs
- Threat model gaps in the documentation

Out of scope:
- Issues in the example bot code or test scaffolding
- Theoretical attacks that require compromising hardware security
  (TEE root keys, etc.) â€” these are documented as acknowledged limits
- Phishing or social engineering against the Anba Labs team

## Recognition

Researchers who report valid issues will be credited in release notes
(unless they request anonymity). We are not currently offering
monetary bounties.
