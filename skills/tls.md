---
category: tls
label: TLS / Certificate Validation
report_count: 71
programs: [curl, nodejs, ibb, portswigger, nextcloud, ruby, brave, fanduel, endless_group, uber]
avg_bounty: 900
max_bounty: 2580
severity_distribution: critical: 4, high: 6, medium: 18, low: 12, none: 1
---

## Overview

TLS/certificate validation bugs break the core security invariant of encrypted transport: that the remote endpoint is authenticated and the connection is protected from interception or tampering. These flaws persist due to subtle implementation errors, library inconsistencies, and silent trust model changes. Worst-case impact is full session compromise—attackers can intercept, decrypt, modify, or inject traffic, often leading to credential theft, account takeover, or code execution.

## Root causes

- Misuse or misunderstanding of TLS library APIs (e.g., failing to enable hostname verification, incorrect parameter usage, or assuming defaults are secure).
- Incomplete or incorrect handling of certificate fields (e.g., not checking Subject Alternative Name, mishandling wildcards, or ignoring IP address validation rules).
- Silent fallback to insecure trust models (e.g., accepting self-signed certificates, disabling verification on error, or trusting user-supplied CA bundles without warning).
- Architectural anti-patterns: skipping certificate checks for proxies, session reuse, or alternate protocols (QUIC, HTTP/3, SFTP).
- Library or platform-specific bugs (e.g., OpenSSL/LibreSSL/BoringSSL API differences, Apple SecTrust legacy behaviors, wolfSSL/wolfSSH backend gaps).
- Inadequate revocation checking (OCSP/CRL ignored or bypassed, especially on session reuse or with alternate TLS backends).

## Attack surface

- Parameters controlling certificate validation: `{verify_peer}`, `{verify_host}`, `{rejectUnauthorized}`, `{ca_bundle}`, `{pinnedpubkey}`, `{known_hosts}`.
- Environment variables or config files that override trust stores (e.g., `CURL_CA_BUNDLE`, custom CA paths).
- Endpoint patterns: any feature making outbound TLS connections (API clients, webhooks, OAuth flows, federated login, email/SMS integrations, build/dependency fetchers, SFTP/SSH clients).
- Protocols and stacks: HTTP/3/QUIC, SFTP/SCP, SMTP/IMAP/POP, MQTT, and any use of alternate TLS libraries (mbedTLS, wolfSSL, GnuTLS, Apple SecTrust, NSS).
- Client-side: JS/TypeScript code using fetch, XMLHttpRequest, or custom TLS wrappers; mobile/desktop apps using platform TLS APIs.
- Build/deployment infrastructure fetching dependencies or artifacts over HTTP/TLS.

## Recon checklist

1. Enumerate all features and endpoints that initiate outbound TLS/SSH connections.
2. Identify parameters, config options, or environment variables that control certificate or host verification.
3. Review code and documentation for TLS library usage—note any custom verification logic, explicit disables, or alternate backends.
4. Check for proxy support and how HTTPS over proxy is handled (CONNECT vs. plain HTTP).
5. Inspect for support of certificate pinning, OCSP/CRL enforcement, and revocation checking.
6. Map all trust store sources (system, bundled, user-supplied, environment overrides).
7. For client apps, decompile or analyze JS/native code for TLS options and error handling.
8. Review build/deployment scripts for HTTP(S) or SFTP/SCP fetches, especially in CI/CD or plugin systems.

## Hunt methodology

1. Send outbound TLS requests to a controlled endpoint with a valid certificate; confirm connection succeeds.
2. Repeat with a certificate for the wrong hostname; observe if the connection is rejected.
3. Repeat with a self-signed certificate; observe if the connection is rejected.
4. Test with a revoked certificate (via OCSP/CRL); observe if the connection is rejected.
5. Supply a certificate with a wildcard or edge-case SAN/CN (e.g., leading dot, IDN, IP address); test if matching is correct.
6. For proxy flows, intercept traffic and present a forged certificate; check if MITM is possible.
7. Manipulate trust store via environment variable or config (e.g., set `{ca_bundle}` to a malicious CA); observe if connections are silently trusted.
8. For SFTP/SSH, remove host from `{known_hosts}` and attempt connection; check if host key verification is enforced.

## Payload library

### Hostname Verification Bypass
**Technique**: Exploit missing or incorrect hostname checks to accept certificates for the wrong host.
**How to apply**: Initiate a TLS connection to `{ip}` or `{hostname}` using a certificate with a mismatched CN/SAN or a wildcard intended to match only subdomains.
**Payload**:
```
curl https://{ip}/ --cacert {malicious_cert}
```
**Observe**: Connection succeeds without error when it should fail due to hostname mismatch.
**Seen in**: API clients using IP addresses, HTTP/3/QUIC flows, SFTP/SCP clients.

### Trust Store Override
**Technique**: Replace the trusted CA bundle with a malicious root CA to silently intercept connections.
**How to apply**: Set the environment variable or config option controlling the CA bundle to a file containing a malicious CA certificate.
**Payload**:
```
export {ca_bundle_env}={malicious_ca_path}
curl https://{hostname}/
```
**Observe**: Connection succeeds and attacker-controlled certificates are accepted.
**Seen in**: CLI tools, build systems, any app honoring environment CA overrides.

### Certificate Pinning Bypass
**Technique**: Exploit backend or protocol gaps where pinning is not enforced or is bypassed when verification is disabled.
**How to apply**: Set `{pinnedpubkey}` to a bogus value and connect to a valid server, or disable peer verification and observe if pinning is still enforced.
**Payload**:
```
curl --http3 --pinnedpubkey {bogus_pubkey} -k https://{hostname}/
```
**Observe**: Connection succeeds when it should fail due to pinning mismatch.
**Seen in**: HTTP/3/QUIC flows with wolfSSL, apps with optional pinning.

### Revocation/OCSP Bypass
**Technique**: Exploit session reuse, backend bugs, or alternate verification paths to skip revocation checks.
**How to apply**: Connect to a server with a revoked certificate, then reuse the session or trigger alternate verification logic.
**Payload**:
```
curl https://{revoked_cert_host}/ --cert-status
curl https://{revoked_cert_host}/ --cert-status  # session reuse
```
**Observe**: First connection fails, second (reused session) succeeds.
**Seen in**: OCSP/CRL enforcement, session reuse, Apple SecTrust, GnuTLS.

### Proxy MITM
**Technique**: Abuse lack of CONNECT tunneling or missing certificate checks when using HTTP proxies.
**How to apply**: Configure app to use an HTTP proxy, intercept traffic, and present a forged certificate or downgrade to plaintext.
**Payload**:
```
curl --proxy http://{proxy_host}:{proxy_port} https://{target}/
```
**Observe**: Proxy can read/modify HTTPS traffic; no certificate validation error.
**Seen in**: ProxyAgent flows, HTTP/HTTPS proxy support in HTTP clients.

### SFTP/SSH Host Key Verification Bypass
**Technique**: Connect to an SSH/SFTP server not present in `{known_hosts}` and observe if host key verification is enforced.
**How to apply**: Remove or omit the host from the known hosts file, then initiate an SFTP/SCP connection.
**Payload**:
```
curl sftp://{user}:{pass}@{host}/ --ssh-knownhosts {empty_file}
```
**Observe**: Connection and credential exchange succeed without host key prompt or error.
**Seen in**: SFTP/SCP clients, wolfSSH/libssh2 backends.

## Filter & WAF bypass

- Use IP addresses instead of hostnames to bypass SNI and hostname checks.
- Supply certificates with wildcards, leading dots, or IDN/punycode to test edge-case matching.
- Manipulate environment variables (e.g., `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) to override trust silently.
- For OCSP/CRL, trigger session reuse or alternate protocol flows to skip revocation checks.
- For SFTP/SSH, ensure `{known_hosts}` is missing or empty to test fallback behavior.

## Verification & impact

- **Confirmed vulnerable**: Connection to a server with a mismatched, self-signed, or revoked certificate succeeds without explicit override; MITM proxy can decrypt/modify traffic; host key verification is skipped.
- **False positive signals**: Connection fails with explicit "certificate verify failed" or "host key mismatch" errors; warnings are shown and connection is aborted.
- **Impact escalation**: Chain with credential theft, session hijack, code execution (malicious dependency injection), or privilege escalation via intercepted traffic.

## Triage & severity

- Typical CVSS: medium to critical (CVSS 6.0–9.8), depending on exploitability and data sensitivity.
- Severity increases if: affects default config, allows MITM for all users, impacts sensitive flows (auth, payments, code fetch), or is reachable by unauthenticated attackers.
- Severity decreases if: requires user opt-in (e.g., `--insecure`), only affects non-default backends, or is limited to non-sensitive flows.

## Reporting tips

- Strong PoC: minimal reproducer showing connection to a controlled server with a forged, mismatched, or revoked certificate; include both success and expected failure cases.
- Avoid: reporting expired or misconfigured certs without demonstrating bypass, or issues only affecting non-default/unsupported configs.
- Evidence checklist: full request/response logs, config/environment details, certificate chain used, backend/library version, and impact statement (what an attacker can do).

## Real examples

- 2435482 — ibb: TLS certificate check bypass with mbedTLS when connecting to IP addresses, allowing MITM on all TLS protocols (medium, $2580)
- 1455411 — ibb: OpenSSL mishandles internal errors in X509_verify_cert(), leading to undefined client behavior and potential bypass (medium, $1200)
- 1599063 — ibb: Undici ProxyAgent fails to verify upstream server certificates, enabling trivial MITM of HTTPS via proxy (high, $1000)
- 506161 — portswigger: Build infrastructure fetches dependencies over HTTP, exposing supply chain to MITM and code injection (medium, $1000)
- 3253725 — brave: SameSite cookie policy bypassed due to missing Sec-Fetch-Site header, leaking Strict cookies cross-site (high, $500)
- 1278254 — nodejs: `rejectUnauthorized: undefined` disables all TLS validation, breaking HTTPS security for affected apps (low, $150)
- 329645 — ibb: LibreSSL/BoringSSL fail to perform hostname validation with X509_VERIFY_PARAM_set1_host, accepting any trusted certificate (critical, $0)
- 3418776 — curl: Silent trust model hijacking via CURL_CA_BUNDLE allows MITM without user warning (critical, $0)
- 293358 — uber: Windows Phone app lacks certificate pinning, enabling full MITM of user traffic (critical, $0)
- 3455037 — curl: Hostname validation bypass via leading dot allows wildcard certs to match unintended hosts (medium, $0)

## Bounty intelligence

Payouts for TLS/certificate validation bugs range from $150 for low-impact or niche issues to $2,500+ for critical, default-path flaws affecting major protocols or user data. Programs with large user bases, financial or authentication flows, or developer tooling (e.g., CLI tools, SDKs, CI/CD) pay the most. Bounties are highest for bugs that enable silent MITM, affect default configurations, or break trust for all users without warning. Reports with clear, reproducible impact and cross-protocol relevance are most likely to receive top rewards.