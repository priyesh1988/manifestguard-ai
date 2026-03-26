# Security Policy

ManifestGuard changes infrastructure definitions, so default behavior should remain conservative.

## Supported versions
- 0.2.x

## Reporting a vulnerability
Please report vulnerabilities privately through your internal security contact or GitHub security advisories.

## Secure usage guidance
- Review auto-fixes in CI before enabling in-place writes on production repos.
- Keep the remediation history database protected because it contains resource names and issue metadata.
- Prefer pull-request workflows for write operations.
