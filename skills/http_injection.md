---
category: http_injection
label: HTTP Injection
report_count: 127
programs: [shopify, ibb, nodejs, ruby, starbucks, mozilla, snapchat, nextcloud, legalrobot, owncloud]
avg_bounty: 1400
max_bounty: 5000
severity_distribution: critical: 1, high: 7, medium: 20, low: 12
---

## Overview
HTTP injection vulnerabilities break the trust boundary between user input and HTTP protocol handling, allowing attackers to manipulate request or response parsing, headers, or caching logic. Developers frequently introduce these flaws due to improper input sanitization, protocol parsing inconsistencies, and misplaced trust in upstream or downstream components. The worst-case impact includes request smuggling, cache poisoning, header injection, and even remote code execution or full account compromise.

## Root causes
- Inconsistent HTTP parsing between front-end proxies and back-end servers (e.g., TE/CL ambiguity, whitespace handling)
- Failure to sanitize user input before inserting into HTTP headers or protocol fields
- Trusting framework or library parsing logic without validating against RFC-compliant behavior
- Overly permissive or legacy protocol implementations (e.g., accepting non-standard delimiters, ignoring chunk extensions)
- Direct injection of user-controlled values into configuration or protocol fields (e.g., SMTP, Redis, HTTP headers)
- Lack of normalization or canonicalization of URLs, headers, or paths before processing

## Attack surface
- Parameters reflected in HTTP headers (e.g., Location, Set-Cookie, Content-Type, Host)
- User-controlled input in protocol fields (SMTP, Redis, LDAP, etc.)
- HTTP request headers: Host, X-Forwarded-*, Content-Length, Transfer-Encoding, Cookie, custom headers
- Endpoint patterns: authentication flows, password reset, file upload/download, redirects, API gateways, proxy endpoints
- Features: email sending, calendar invites, affiliate/product links, CDN/static asset delivery, OAuth callback handling
- Tech stacks: Node.js (llhttp), Ruby (Rack, WEBrick), Python (urllib), Java (Tomcat), Apache HTTPD, CDN/proxy layers
- Client-side: JS code that constructs URLs/headers from user input, or parses URLs with legacy APIs

## Recon checklist
1. Enumerate all endpoints that reflect or process user input in headers or redirects.
2. Identify all parameters, headers, and body fields that are user-controllable.
3. Map all proxy, CDN, or load balancer layers and their HTTP parsing behavior.
4. Review API schemas and OpenAPI/Swagger docs for header-injectable fields.
5. Analyze JavaScript and backend source for direct header construction or protocol usage.
6. Check for legacy or custom HTTP parsing libraries in use.
7. Inspect for features that interact with external protocols (SMTP, Redis, LDAP).
8. Probe for cache keys and cache behavior on static and dynamic resources.

## Hunt methodology
1. Send requests with payloads containing CR (`\r`), LF (`\n`), and CRLF (`\r\n`) in all user-controllable parameters and headers.
2. Test for HTTP request smuggling by crafting ambiguous Transfer-Encoding/Content-Length headers and chunked bodies.
3. Attempt header injection via reflected parameters in Location, Set-Cookie, Content-Type, and custom headers.
4. Manipulate URL paths and query strings to probe for cache poisoning and normalization inconsistencies.
5. Inject protocol-specific payloads (e.g., SMTP, Redis commands) into fields used in backend protocol connections.
6. Fuzz for whitespace, tab, and control character handling in header names and values.
7. Observe responses for header pollution, duplicated headers, unexpected status codes, or split responses.
8. Chain findings with authentication flows, cache behavior, or SSRF to demonstrate impact escalation.

## Payload library

### CRLF Injection in HTTP Headers
**Technique**: Injects CRLF sequences into header values or paths to break header boundaries and introduce new headers or split responses.
**How to apply**: Insert `%0d%0a` (or raw `\r\n`) into any user-controlled parameter or header that is reflected in HTTP response headers.
**Payload**:  
```
{param}=value%0d%0aInjected-Header: injected
```
**Observe**: Response contains the injected header, or response splitting occurs (multiple responses, altered headers).
**Seen in**: Redirect flows, password reset links, API endpoints reflecting user input in headers.

### HTTP Request Smuggling (TE.CL / CL.TE / TE-TE)
**Technique**: Exploits parsing discrepancies between front-end and back-end servers by crafting ambiguous or malformed Transfer-Encoding and Content-Length headers.
**How to apply**: Send requests with both `Transfer-Encoding: chunked` and `Content-Length: {value}` headers, or duplicate headers, and craft chunked bodies to desync request parsing.
**Payload**:  
```
POST /api/endpoint HTTP/1.1
Host: {host}
Content-Length: 6
Transfer-Encoding: chunked

0

GET /api/endpoint2 HTTP/1.1
Host: {host}

```
**Observe**: Smuggled requests processed out-of-band, responses mismatched, or victim requests poisoned.
**Seen in**: API gateways, reverse proxies, authentication endpoints.

### Header Injection via Protocol Fields (SMTP/Redis/LDAP)
**Technique**: Injects newline/control characters into protocol fields used in backend connections, enabling command injection or protocol smuggling.
**How to apply**: Supply `\r`, `\n`, or `%0d%0a` in fields passed to backend protocols (e.g., email, password, calendar invite).
**Payload**:  
```
{param}=attacker@example.com%0d%0aRCPT TO: victim@example.com
```
**Observe**: Backend protocol logs show injected commands, or application error messages leak protocol responses.
**Seen in**: Email sending, calendar invites, LDAP/SMTP/Redis integrations.

### Cache Poisoning via Path/Host/Method Manipulation
**Technique**: Manipulates cache keys by altering path separators, host headers, or HTTP methods to poison cache entries.
**How to apply**: Replace `/` with `\`, insert `../`, or modify `X-Forwarded-Host`/`X-HTTP-Method-Override` headers in requests for static or dynamic resources.
**Payload**:  
```
GET /static\js\app.js?cb={random} HTTP/1.1
Host: {cdn_host}
```
or  
```
X-Forwarded-Host: attacker.com
```
**Observe**: Legitimate users receive poisoned or error responses for targeted resources.
**Seen in**: CDN/static asset delivery, affiliate/product links, API endpoints with cache layers.

### Whitespace/Control Character Header Bypass
**Technique**: Uses tabs, spaces, or control characters to bypass header parsing or validation logic.
**How to apply**: Insert `%09`, `%0b`, or spaces before/after header names or colons in crafted requests.
**Payload**:  
```
Header%20Name : value
```
**Observe**: Header is parsed or ignored inconsistently between layers, enabling smuggling or bypass.
**Seen in**: Node.js, Ruby, Python HTTP servers, custom header validation logic.

### Chunk Extension/Newline Abuse
**Technique**: Abuses chunked transfer encoding extensions or newlines in chunk size lines to desync request parsing.
**How to apply**: Add chunk extensions or newlines in chunk size lines in chunked requests.
**Payload**:  
```
POST /api/endpoint HTTP/1.1
Host: {host}
Transfer-Encoding: chunked

5 ; attack=1
hello
0

```
**Observe**: Backend interprets additional requests or headers, or proxy/server desync occurs.
**Seen in**: Node.js (llhttp), Apache Traffic Server, custom HTTP parsers.

## Filter & WAF bypass
- Use URL-encoded CR (`%0d`) and LF (`%0a`) instead of raw characters.
- Double-encode (`%250d%250a`) to bypass naive decoding.
- Insert whitespace or tabs (`%09`, `%20`) before/after colons in headers.
- Use mixed case or alternate header spellings (`Transfer-Encoding`, `transfer-encoding`).
- Exploit chunk extensions or non-standard delimiters in chunked bodies.
- Use duplicate headers or split header values with commas.
- Leverage HTTP/2 to HTTP/1 downgrade inconsistencies.
- Insert null bytes (`%00`) if backend truncates on null.

## Verification & impact
- **Confirmed vulnerable**: Injection reflected in response headers, split responses, cache poisoning observed, or backend protocol logs show injected commands.
- **False positive signals**: Input echoed in response body only, header not actually split, or error responses without header manipulation.
- **Impact escalation**: Chain with authentication flows (e.g., set-cookie injection), SSRF, cache poisoning for DoS or credential theft, or protocol smuggling for RCE.

## Triage & severity
- Typical CVSS: 5.0–9.8 (medium to critical), depending on exploitability and impact.
- Severity up: Unauthenticated exploitation, RCE, account/session compromise, cross-protocol injection, cache poisoning affecting all users.
- Severity down: Requires authentication, limited to self, only affects non-sensitive headers, mitigated by downstream controls.

## Reporting tips
- Strong PoC: Minimal request showing header/body injection, with clear evidence (response headers, logs, cache poisoning effect).
- Avoid: Reports with only body reflection, no header manipulation, or requiring unrealistic attacker control.
- Evidence checklist: Full request/response pairs, screenshots of header injection or cache poisoning, logs or error messages from backend, description of affected features and impact.

## Real examples
- 1200647 — aiven_ltd: CRLF injection in SMTP server config led to RCE via Grafana image renderer (critical, $5000)
- 2280391 — ibb: Tomcat trailer header parsing flaw enabled request smuggling via oversized trailer (high, $4660)
- 2299692 — ibb: Tomcat trailer parsing bug allowed request smuggling with malformed trailer headers (high, $4660)
- 2327341 — ibb: Tomcat client-side desync via POST Content-Length mishandling led to info disclosure (high, $4660)
- 1667974 — ibb: Apache HTTPD pause-based desync enabled request smuggling and MITM JS injection (high, $4000)
- 1695604 — shopify: CDN cache poisoning via backslash/forward slash normalization mismatch caused DoS (medium, $3800)
- 2585373 — ibb: Apache HTTPD response splitting via faulty input validation in core (medium, $2600)
- 1168205 — ruby: CRLF injection in set_content_type enabled arbitrary header injection (high, $0)
- 713285 — x: Request smuggling on live streaming platform enabled CSRF bypass and account linking (high, $560)
- 1878489 — ibb: Node.js undici library allowed CRLF injection in Host header, enabling response splitting (medium, $600)
- 2279572 — shopify: Header injection in Rack 3/Pitchfork enabled response splitting and XSS (low, $800)
- 726773 — gsa_bbp: Request smuggling via TE/CL desync on government data portal (high, $750)
- 409512 — ibb: CRLF injection in Apache mod_userdir enabled response splitting (medium, $500)
- 965267 — ruby: WEBrick Transfer-Encoding parsing flaw enabled request smuggling (low, $500)
- 1002188 — nodejs: Node.js allowed duplicate Transfer-Encoding headers, enabling TE-TE smuggling (low, $250)
- 1238099 — nodejs: Node.js ignored chunk extensions, enabling HRS with ATS proxy (medium, $250)
- 1238709 — nodejs: Node.js accepted space before colon in headers, enabling HRS (medium, $250)
- 2147132 — mozilla: CRLF injection in OAuth redirect_uri enabled arbitrary header injection (low, $200)

## Bounty intelligence
Payouts for HTTP injection range from $200 for low-impact header injection to $5,000 for RCE or widespread request smuggling. Programs with complex proxy/CDN layers, authentication flows, or integrations with backend protocols (SMTP, Redis) pay the most. Demonstrating real-world impact (e.g., cache poisoning affecting all users, account takeover, or code execution) is key to maximizing rewards. Programs with mature triage expect clear evidence of header manipulation or protocol desync, not just input reflection.