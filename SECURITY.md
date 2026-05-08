# Security Policy

Codex Patcher CC is security/reverse-engineering tooling for local, authorized research on systems you control. Do not use this project to bypass safeguards for unauthorized access, abuse, credential theft, spam, or destructive activity.

## Supported Versions

Security fixes target the latest `main` branch.

## Reporting a Vulnerability

Please report vulnerabilities privately when possible:

- Use GitHub's **Report a vulnerability** flow for this repository if available.
- Otherwise open a minimal GitHub issue that does not include live secrets, private binaries, customer data, or weaponized payloads.
- For coordination, contact `v0idch3cksum` on Discord.

## Sensitive Data Guidelines

- Do not attach raw `.ccp/`, terminal-cache, or local backup state without reviewing and redacting it.
- Redact tokens, session cookies, private paths, hostnames, usernames, and license/subscription data.
- If patch logs or backup files captured credentials, rotate those credentials before sharing diagnostics.
