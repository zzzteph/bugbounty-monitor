---
category: cryptography
label: Cryptography (crypto)
report_count: 139
programs: [ibb, phabricator, slack, nextcloud, sorare, x, kubernetes, eternal, iandunn-projects, wordpress]
avg_bounty: 400
max_bounty: 1800
severity_distribution: critical: 0, high: 6, medium: 10, low: 8, none: 4
---

## Overview

Cryptographic vulnerabilities break the core security invariants of confidentiality, integrity, and authenticity by exploiting flaws in protocol design, implementation, or configuration. Developers frequently introduce these bugs due to incorrect assumptions about cryptographic primitives, insecure defaults, or incomplete threat models. Worst-case impact ranges from full account takeover and code execution to mass credential compromise or persistent backdoors in software supply chains.

## Root causes

- Use of unauthenticated encryption modes (e.g., AES-CBC without MAC or GCM)
- Weak, guessable, or hardcoded cryptographic keys and secrets
- Insecure random number generation or insufficient entropy
- Failure to validate certificates, signatures, or update authenticity
- Use of deprecated or broken algorithms (e.g., MD5, SHA1, 3DES, SSLv3, TLS 1.0)
- Insecure protocol implementations (timing leaks, padding oracles, length extension, etc.)
- Absence of integrity checks on downloaded code or dependencies

## Attack surface

- Parameters or headers carrying tokens, signatures, or encrypted data (e.g., `{token}`, `{hmac}`, `{signature}`, `{session}`)
- Endpoints handling authentication, password resets, invitations, or SSO flows
- File upload/download, backup/restore, and import/export features
- API endpoints that accept or return signed/encrypted payloads
- Build systems and CI/CD pipelines fetching dependencies or updates
- DNS records (CAA, SPF, DKIM, DMARC) and SMTP services
- TLS/SSL endpoints, especially those supporting legacy protocols or weak ciphers
- Client-side JS or mobile apps handling cryptographic operations

## Recon checklist

1. Enumerate all endpoints accepting or returning cryptographically protected data (tokens, signatures, encrypted blobs).
2. Identify all authentication, session, and password reset flows.
3. Inspect API schemas and OpenAPI/Swagger docs for cryptographic parameters.
4. Review JS bundles and mobile app code for client-side crypto usage.
5. Probe TLS/SSL endpoints for supported protocols and ciphersuites.
6. Check DNS for CAA, SPF, DKIM, and DMARC records.
7. Analyze build scripts and CI/CD configs for insecure dependency fetching.
8. Search for hardcoded secrets, keys, or weak random generation in source or config.

## Hunt methodology

1. Send manipulated `{token}` or `{signature}` values to endpoints and observe error handling.
2. Replay or modify cryptographically protected links (e.g., email confirmation, invite, password reset) and test for reusability or predictability.
3. Attempt length extension or padding oracle attacks on endpoints using MACs or block ciphers without integrity.
4. Test for timing side-channels in signature/HMAC comparisons by measuring response times with partial matches.
5. Scan TLS/SSL endpoints for deprecated protocols (SSLv3, TLS 1.0) and weak ciphers (3DES, RC4).
6. Intercept and tamper with dependency downloads or update channels; check for lack of integrity/authenticity checks.
7. Attempt to brute-force or guess weak/hardcoded keys and secrets in session cookies or tokens.
8. Manipulate DNS and SMTP records to test for missing CAA, SPF, DKIM, or open relays.

## Payload library

### Padding Oracle Attack
**Technique**: Exploits unauthenticated CBC-mode encryption by modifying ciphertext blocks and observing error messages or timing to recover plaintext.
**How to apply**: Capture a valid encrypted `{param}` from a response. Modify one or more bytes in a block and resend to the decryption endpoint. Repeat with systematic changes.
**Payload**:  
```
POST /api/endpoint
param={modified_ciphertext}
```
**Observe**: Distinct error messages or timing differences indicating padding vs. MAC failures.
**Seen in**: File encryption storage, login tokens, session cookies.

### Length Extension Attack
**Technique**: Exploits MACs constructed as `hash(secret + message)` (e.g., MD5/SHA1) to append data and forge a valid MAC.
**How to apply**: Obtain a valid `{hmac}` for a known `{message}`. Use a hash length extension tool to append `{extra}` and generate a new `{hmac}`.
**Payload**:  
```
GET /api/endpoint?param={message}{extra}&hmac={forged_hmac}
```
**Observe**: Endpoint accepts the modified message and MAC, processing attacker-controlled data.
**Seen in**: Redirect handlers, download links, API authentication.

### Timing Attack on HMAC/Signature Comparison
**Technique**: Exploits non-constant-time comparison functions to leak information about valid bytes in a signature or HMAC.
**How to apply**: Send requests with signatures/HMACs that incrementally match the valid value, measuring response times for each guess.
**Payload**:  
```
POST /api/endpoint
signature={partial_match}
```
**Observe**: Response time increases as more bytes match the valid signature.
**Seen in**: API authentication, session validation, webhook verification.

### Insecure Random/Weak Key Generation
**Technique**: Exploits predictable, short, or hardcoded keys/secrets in session tokens, cookies, or password reset links.
**How to apply**: Attempt to brute-force or guess `{token}` or `{key}` values; test for static or low-entropy patterns.
**Payload**:  
```
GET /api/endpoint?token={guessed_or_bruteforced_token}
```
**Observe**: Successful authentication or access with a guessed value.
**Seen in**: Session cookies, TOTP secrets, password reset tokens.

### Certificate/Signature Validation Bypass
**Technique**: Exploits missing or incorrect validation of SSL/TLS certificates or digital signatures.
**How to apply**: Intercept traffic or supply self-signed/invalid certificates; observe if the client accepts them without warning.
**Payload**:  
```
MITM proxy with self-signed cert; or
POST /api/endpoint
signature={invalid_signature}
```
**Observe**: Client or server accepts invalid certificate or signature.
**Seen in**: Desktop/mobile clients, SSO flows, update/download mechanisms.

### Insecure Dependency/Update Fetching
**Technique**: Exploits lack of integrity/authenticity checks when downloading dependencies or updates over insecure channels.
**How to apply**: MITM the download channel or supply a malicious dependency; observe if it is executed or installed.
**Payload**:  
```
Serve malicious file at {dependency_url} over HTTP
```
**Observe**: Build or update process accepts and executes the malicious file.
**Seen in**: CI/CD pipelines, plugin managers, auto-update features.

### DNS/Email Auth Record Weakness
**Technique**: Exploits missing or misconfigured CAA, SPF, DKIM, or DMARC records to spoof email or misissue certificates.
**How to apply**: Attempt to send spoofed emails or request certificates from unauthorized CAs.
**Payload**:  
```
Send email with forged From: {target_domain}
Request certificate for {target_domain} from random CA
```
**Observe**: Email is delivered/spoofed, or CA issues certificate.
**Seen in**: Email delivery, domain validation, phishing protections.

## Filter & WAF bypass

- Use alternate encodings (e.g., hex, base64, URL encoding) for ciphertext or MAC values.
- Insert null bytes or Unicode homoglyphs in tokens or parameters.
- Chunked transfer encoding for HTTP payloads to evade length checks.
- Manipulate case or whitespace in headers (e.g., `Authorization`, `Signature`).
- For timing attacks, randomize request order and use high-resolution timers to average out noise.
- For length extension, pad with crafted data to align block boundaries.

## Verification & impact

- **Confirmed vulnerable**: Ability to decrypt, forge, or tamper with protected data; successful MITM with invalid cert; privilege escalation via token reuse or manipulation; execution of attacker-supplied code via dependency injection.
- **False positive signals**: Generic error messages without cryptographic context; endpoints that reject all modified tokens; timing differences within network jitter.
- **Impact escalation**: Chain with IDOR, XSS, or SSRF for account takeover; use code execution in build/update flows for supply chain compromise; exploit weak email/DNS auth for phishing or credential theft.

## Triage & severity

- Typical CVSS: medium to high (5.0–8.8), critical if RCE or mass compromise is possible.
- Severity up: unauthenticated exploitation, access to sensitive data, code execution, supply chain impact, mass user compromise.
- Severity down: requires privileged access, mitigated by secondary controls (e.g., OAuth tokens), limited to non-sensitive data, deprecated features.

## Reporting tips

- Strong PoC: minimal reproducer showing exploitation (e.g., decrypting a sample, forging a valid token, MITM with invalid cert), with clear impact statement.
- Avoid: vague claims without proof, theoretical attacks with no practical exploit, reports on deprecated/unused endpoints.
- Evidence checklist: full request/response pairs, timing measurements (if relevant), screenshots or logs of successful exploitation, code snippets or scripts used, description of business impact.

## Real examples

- 2038484 — ibb: Node.js Diffie-Hellman key generation flaw allowed nonce reuse, breaking forward secrecy and confidentiality (medium, $1800)
- 213437 — ibb: JWE libraries vulnerable to Invalid Curve attack, enabling key compromise and message decryption (high, $1000)
- 216746 — phabricator: AES-CBC encryption without integrity check enabled padding oracle and chosen-ciphertext attacks (medium, $750)
- 327674 — slack: Invitation reminder emails used HTTP links, exposing users to MITM and phishing (low, $350)
- 1387366 — kubernetes: Weak Flask session secret allowed arbitrary session manipulation in election system (high, $250)
- 1039504 — ibb: Build dependencies downloaded over HTTP without integrity checks, enabling supply chain compromise (high, $1000)
- 275269 — rubygems: Gem signature forgery via tar archive ambiguity allowed malicious package installation (medium, $0)
- 251572 — eternal: Length extension attack on redirect handler enabled HTML injection via forged MAC (medium, $100)
- 277534 — iandunn-projects: Timing attack on password validation enabled brute-force of application passwords (high, $25)
- 1817214 — sorare: Reusable email confirmation link and weak token handling led to account takeover (low, $300)

## Bounty intelligence

Payouts for cryptographic vulnerabilities vary widely: low for theoretical or configuration-only issues, but high for practical exploits with real-world impact (e.g., account takeover, code execution, supply chain compromise). SaaS platforms, developer tools, and infrastructure providers pay most for crypto flaws, especially those affecting authentication, session management, or update mechanisms. Reports with clear exploitability and business impact (not just scanner output) are most likely to receive higher rewards.