---
category: cors
label: CORS / Origin Validation
report_count: 3
programs: [mozilla, revive_adserver]
avg_bounty: 100
max_bounty: 250
severity_distribution: low: 1, medium: 1, high: 1
---

## Overview
CORS/origin validation bugs break the browser's same-origin policy, allowing attackers to read or manipulate sensitive data cross-origin. Developers often misconfigure CORS headers or trust unvalidated origins, exposing internal APIs or user data to untrusted web pages. The worst-case impact is full account takeover, credential theft, or mass data exfiltration via malicious websites.

## Root causes
- Overly permissive CORS policies (e.g., `Access-Control-Allow-Origin: *` on sensitive endpoints)
- Reflection of unvalidated `Origin` or `Referer` headers in CORS responses
- Failure to restrict CORS to trusted domains or subdomains
- Inconsistent CORS enforcement between endpoints (e.g., public vs. private APIs)
- Trusting user-supplied input in origin validation logic
- Lack of defense-in-depth (e.g., missing authentication checks on CORS-enabled endpoints)

## Attack surface
- Endpoints accepting cross-origin requests with sensitive data in response
- API endpoints with `Access-Control-Allow-Origin` set to `*` or reflecting request `Origin`
- Endpoints handling user lookups, account recovery, or user enumeration
- Features: account recovery flows, user search/autocomplete, admin/user management panels
- HTTP headers: `Origin`, `Referer`, `Access-Control-Request-Method`, `Access-Control-Request-Headers`
- JavaScript code that fetches data from API endpoints and exposes it to the DOM or window

## Recon checklist
1. Enumerate all endpoints returning sensitive data (user info, account recovery, admin features).
2. Map CORS headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, etc.) for each endpoint.
3. Identify endpoints reflecting the `Origin` or `Referer` header in responses.
4. Check for differences in CORS policy between GET, POST, and preflight (OPTIONS) requests.
5. Review JavaScript for cross-origin fetch/XHR calls and dynamic origin handling.
6. Test authenticated vs. unauthenticated access to CORS-enabled endpoints.
7. Probe for wildcard origins or regex-based origin validation.
8. Inspect API documentation or OpenAPI/Swagger specs for CORS notes.

## Hunt methodology
1. Send requests with arbitrary `Origin: https://evil.com` to sensitive endpoints and observe CORS headers.
2. Attempt cross-origin XHR/fetch from a controlled domain to endpoints with sensitive data.
3. Test with `Origin: null`, `Origin: file://`, and malformed origins to bypass naive checks.
4. Probe endpoints with wildcard origins (`*`) and with/without `Access-Control-Allow-Credentials`.
5. Check if the server reflects the `Origin` header in `Access-Control-Allow-Origin`.
6. Attempt authenticated requests cross-origin and observe if credentials are accepted.
7. Test endpoints for information leakage (usernames, emails, hints) via cross-origin requests.
8. Chain CORS misconfigurations with other bugs (IDOR, weak auth) for impact escalation.

## Payload library

### Wildcard Origin Exposure
**Technique**: Exploits endpoints that set `Access-Control-Allow-Origin: *` and return sensitive data.
**How to apply**: Send a cross-origin XHR/fetch from any domain to a sensitive endpoint and observe if the response is accessible.
**Payload**:
```javascript
fetch('https://{target}/api/endpoint', {credentials: 'include'})
  .then(r => r.text()).then(console.log)
```
**Observe**: Response contains sensitive data and is accessible from the attacker's domain.
**Seen in**: Account recovery APIs, user info endpoints, admin panels.

### Origin Reflection
**Technique**: Server reflects the `Origin` header value in `Access-Control-Allow-Origin` without validation.
**How to apply**: Send a request with `Origin: https://evil.com` and observe if the response header reflects it.
**Payload**:
```
GET /api/endpoint HTTP/1.1
Origin: https://evil.com
```
**Observe**: `Access-Control-Allow-Origin: https://evil.com` in response.
**Seen in**: User lookup APIs, autocomplete/search features.

### Credentialed Requests Allowed
**Technique**: Server sets `Access-Control-Allow-Origin` to a non-wildcard value and `Access-Control-Allow-Credentials: true`, allowing credentialed cross-origin requests.
**How to apply**: Send a cross-origin XHR/fetch with `credentials: 'include'` and observe if cookies/auth tokens are sent and response is accessible.
**Payload**:
```javascript
fetch('https://{target}/api/endpoint', {credentials: 'include'})
```
**Observe**: Sensitive data returned and readable by attacker.
**Seen in**: Account management features, user search/autocomplete.

### Null/Obscure Origin Bypass
**Technique**: Some servers allow `Origin: null` or malformed origins, treating them as trusted.
**How to apply**: Send requests with `Origin: null` or `Origin: file://` and observe CORS headers.
**Payload**:
```
GET /api/endpoint HTTP/1.1
Origin: null
```
**Observe**: `Access-Control-Allow-Origin: null` in response, data accessible.
**Seen in**: Account recovery flows, internal APIs.

### Preflight/OPTIONS Policy Mismatch
**Technique**: Server responds permissively to preflight (OPTIONS) requests but restricts actual requests.
**How to apply**: Send an OPTIONS request with custom headers/methods and observe CORS headers.
**Payload**:
```
OPTIONS /api/endpoint HTTP/1.1
Origin: https://evil.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: X-Custom-Header
```
**Observe**: Permissive CORS headers in preflight response.
**Seen in**: User management APIs, file upload endpoints.

## Filter & WAF bypass
- Use mixed case in `Origin` header (`OrIgIn: https://evil.com`)
- Insert whitespace or tabs after colon (`Origin:    https://evil.com`)
- Use encoded Unicode in header value (`Origin: https://ｅｖｉｌ.com`)
- Try `Origin: null`, `Origin: file://`, or `Origin: http://localhost`
- Use non-standard ports (`Origin: https://evil.com:8080`)
- Exploit subdomain wildcards (`Origin: https://sub.evil.com`)

## Verification & impact
- **Confirmed vulnerable**: Sensitive data is accessible via cross-origin XHR/fetch from an attacker-controlled domain.
- **False positive signals**: CORS headers present but response not accessible (e.g., no credentials, preflight fails, opaque response).
- **Impact escalation**: Chain with IDOR, weak authentication, or user enumeration to exfiltrate PII, session tokens, or escalate to account takeover.

## Triage & severity
- Typical CVSS: 4.0–8.6 (medium to high), depending on data sensitivity and authentication.
- Severity increases if: endpoint exposes PII, credentials, or allows account actions; works for authenticated users; affects admin APIs.
- Severity decreases if: endpoint only leaks non-sensitive data, requires user interaction, or is mitigated by other controls (e.g., CSRF tokens, IP allowlists).

## Reporting tips
- Strong PoC: Cross-origin fetch/XHR from attacker domain, with screenshots or HAR showing readable sensitive data.
- Avoid: Reporting CORS headers on non-sensitive endpoints, or where browser still blocks access.
- Evidence checklist: Full request/response with headers, PoC code, description of data exposed, authentication state, and impact statement.

## Real examples
- 2256548 — mozilla: Account recovery hint leaked via direct API query with user email, enabling user enumeration and phishing escalation (low, $250)
- 3401464 — revive_adserver: User search feature leaked contact name and email of users in other accounts via unrestricted lookup, exposing PII (medium, $0)

## Bounty intelligence
Payouts for CORS/origin validation bugs range from $100–$1,000, with higher rewards for endpoints exposing PII, credentials, or admin functionality. SaaS, financial, and large consumer platforms pay most for impactful CORS issues, especially when chained with authentication or privilege escalation. Reports with clear cross-origin PoCs and demonstrated data exfiltration consistently earn higher bounties.