---
category: dos
label: Denial of Service (DoS)
report_count: 427
programs: [shopify-scripts, gitlab, ibb, rootstocklabs, shopify, security, basecamp, kubernetes, x, slack]
avg_bounty: 3200
max_bounty: 10000
severity_distribution: critical: 0, high: 13, medium: 22, low: 5
---

## Overview
Denial of Service (DoS) vulnerabilities break the core invariant of service availability, allowing attackers to exhaust server resources, crash processes, or render features unusable for legitimate users. Developers repeatedly introduce these bugs due to missing resource limits, unsafe parsing of user input, and failure to anticipate pathological edge cases in protocol or application logic. The worst-case impact is a complete outage, data loss, or persistent lockout for all users, sometimes requiring manual intervention or server restarts.

## Root causes
- Absence of hard limits on input size, header count, or resource allocation (memory, file handles, CPU time)
- Trusting user-controlled input in parsers, regexes, or protocol handlers without complexity or recursion bounds
- Use of unsafe or legacy libraries (e.g., regex engines, XML/JSON parsers) that are vulnerable to algorithmic complexity attacks
- Inadequate isolation or sandboxing of user-supplied code or data (e.g., script sandboxes, plugin engines)
- Architectural anti-patterns: synchronous processing of untrusted data, lack of circuit breakers, or global locks
- Failure to validate or normalize input before processing (e.g., Unicode normalization, chunked encoding)

## Attack surface
- HTTP request headers and body fields: especially those parsed as JSON, XML, multipart, or supporting chunked encoding
- Parameters controlling user-generated content: descriptions, comments, names, labels, or any free-form text
- File upload and import endpoints, especially those parsing multipart or handling large numbers of files
- Features that process user-supplied markup, markdown, or diagrams (e.g., Markdown preview, Mermaid, urlize filters)
- Protocol implementations: HTTP/2 frame handling, compression/decompression, WebSockets, RPC
- Username, locale, or other fields normalized or validated with expensive operations (e.g., Unicode, regex)
- Client-side: any feature that renders user-controlled data in the DOM, especially with dynamic parsing or function overrides
- Tech stacks: Django forms and filters, Ruby/Rails parsers, Node.js HTTP servers, Java HTTP/2, C/C++ protocol libraries

## Recon checklist
1. Enumerate all endpoints accepting large or complex user input (file uploads, comments, descriptions, custom code).
2. Identify all fields processed by regex, XML, JSON, or other parsers (review API schemas, source, or OpenAPI docs).
3. Map all endpoints supporting HTTP/2, chunked encoding, or compression (check response headers, ALPN, or server banners).
4. Review client-side JS for dynamic parsing or rendering of user content (e.g., Markdown, diagram libraries).
5. Inspect server-side code for use of untrusted input in resource-intensive operations (search for regex, eval, parse).
6. Check for absence of input length, count, or recursion limits in form fields, headers, or protocol handlers.
7. Probe for cache keys derived from untrusted headers (Host, X-Forwarded-Host/Port) or parameters.
8. Identify endpoints that process user input asynchronously or in background jobs (e.g., preview, import, move operations).

## Hunt methodology
1. Send oversized payloads in all free-form fields ({param}) and observe for timeouts, 500 errors, or resource spikes.
2. Submit deeply nested or recursive structures in JSON/XML/multipart bodies to endpoints parsing user input.
3. Craft regex or markup payloads with exponential or polynomial complexity for fields processed by regex or markup engines.
4. Abuse HTTP/2 features: flood with CONTINUATION frames, excessive headers, or incomplete requests to protocol endpoints.
5. Manipulate Host/X-Forwarded-* headers to poison caches or trigger backend misrouting.
6. Send requests with unbounded chunk extensions or chained compression to test for resource exhaustion in protocol handlers.
7. Test for lack of normalization or validation by submitting large numbers of Unicode or special characters in sensitive fields.
8. Chain multiple requests or concurrent connections to amplify resource exhaustion and observe for global service impact.

## Payload library

### Oversized Input Exhaustion
**Technique**: Exploiting lack of input size or count limits to exhaust memory, CPU, or file handles.
**How to apply**: Submit extremely large values in {param}, or repeat structures in JSON/XML/multipart bodies to {endpoint}.
**Payload**: 
```
POST /api/endpoint
Content-Type: application/json

{"{param}": "A" * 1000000}
```
or
```
POST /api/endpoint
Content-Type: multipart/form-data; boundary=...

--boundary
Content-Disposition: form-data; name="{param}"

A... (repeat 1M times)
--boundary--
```
**Observe**: Slow responses, timeouts, 500 errors, or server resource exhaustion (OOM, too many open files).
**Seen in**: Issue/comment fields on collaboration platforms, file upload endpoints, admin login forms.

### Algorithmic Complexity (ReDoS/Parser Bombs)
**Technique**: Triggering worst-case time complexity in regex, XML, or markup parsers.
**How to apply**: Submit crafted input to {param} or {body} that causes exponential or polynomial backtracking.
**Payload**: 
```
POST /api/endpoint
Content-Type: application/json

{"{param}": "(?:){4294967295}"}
```
or
```
POST /api/endpoint
Content-Type: text/plain

[a](/a/a/a/a/a/a/a/a/a/a/a/a/a/a... (repeat 50000 times))
```
**Observe**: High CPU usage, long processing times, or service unavailability.
**Seen in**: Markdown preview, color code validation, locale/username normalization, XML/REXML parsing.

### Protocol Abuse (HTTP/2, Chunked, Compression)
**Technique**: Exploiting protocol features to bypass resource limits or trigger memory/CPU exhaustion.
**How to apply**: Send HTTP/2 frames (CONTINUATION, HEADERS) or chunked/compressed requests with unbounded size to {endpoint}.
**Payload**: 
```
# HTTP/2 CONTINUATION flood (using h2c or custom tool)
HEADERS + N * CONTINUATION frames (large headers, no END_HEADERS)
```
or
```
POST /api/endpoint
Transfer-Encoding: chunked

1
A
0;ext=AAAA... (repeat 1M times)
```
or
```
GET /api/endpoint
Accept-Encoding: gzip,deflate,br
# Server responds with chained compression layers
```
**Observe**: Memory exhaustion, server crashes, or persistent open connections.
**Seen in**: HTTP/2 connectors on web servers, Node.js/Java HTTP servers, curl/libcurl clients.

### Cache Poisoning for Persistent DoS
**Technique**: Poisoning shared caches with untrusted headers or parameters to block legitimate access.
**How to apply**: Send requests with manipulated Host or X-Forwarded-* headers to cacheable endpoints.
**Payload**: 
```
GET /api/endpoint
Host: {host}:1337
```
or
```
GET /api/endpoint
X-Forwarded-Host: {host}:123
```
**Observe**: Subsequent requests for affected resources fail or return invalid responses.
**Seen in**: Redirect handlers, static asset endpoints, web cache layers.

### Sandbox/Interpreter Abuse
**Technique**: Submitting code or data that triggers infinite loops, recursion, or crashes in interpreters/sandboxes.
**How to apply**: Supply crafted code or input to code execution endpoints or plugin engines.
**Payload**: 
```
<<''.a begin
```
or
```
def foo; end; class X; alias_method :initialize, :send; end; X.new.send(:foo)
```
**Observe**: Process hangs, infinite loops, or interpreter crashes.
**Seen in**: Script/plugin execution sandboxes, code preview features.

### Client-side Rendering DoS
**Technique**: Injecting markup or attributes that override DOM functions or crash client-side rendering.
**How to apply**: Submit HTML/JS with name attributes matching document functions or extremely long values in user-controlled fields.
**Payload**: 
```
<img src=x name="write">
```
or
```
{param}: "A" * 1000000
```
**Observe**: Browser tab crashes, UI freezes, or persistent lockout from affected pages.
**Seen in**: Post/comment rendering, contact/profile pages, diagram/markdown rendering.

## Filter & WAF bypass
- Use chunked encoding with large or repeated chunk extensions: `0;ext=AAAA...`
- Abuse HTTP/2 frame fragmentation (CONTINUATION, HEADERS) to bypass header size limits.
- Chain multiple compression algorithms in Accept-Encoding: `gzip,deflate,br`
- Use deeply nested or recursive JSON/XML structures to evade shallow parsing limits.
- Encode payloads with Unicode, null bytes, or alternate whitespace to bypass naive input filters.
- For cache poisoning, use alternate headers (X-Forwarded-Host, X-Forwarded-Port) if Host is filtered.

## Verification & impact
- **Confirmed vulnerable**: Service becomes unresponsive, returns 500/timeout, or resource metrics (CPU, memory, file handles) spike abnormally. For cache poisoning, legitimate users are persistently blocked.
- **False positive signals**: Temporary slowness without persistent impact, errors only for the attacker, or rate-limited responses.
- **Impact escalation**: Chain with privilege escalation (e.g., DoS on auth endpoints), data loss (OOM kills), or persistent lockout (cache poisoning, client-side crash).

## Triage & severity
- Typical CVSS: 5.0–7.5 (medium to high), depending on scope and persistence.
- Severity increases if: unauthenticated vector, global service impact, persistent lockout, or affects critical infrastructure (auth, payment, blockchain nodes).
- Severity decreases if: only affects single user/session, requires authentication, or mitigated by rate limiting or circuit breakers.

## Reporting tips
- Strong PoC: Minimal input that triggers the bug, with clear before/after impact (e.g., server logs, screenshots, resource metrics).
- Avoid: Reports with only theoretical impact, no reproducible steps, or affecting only the attacker's session.
- Evidence checklist: Full request/response pairs, resource usage graphs, affected feature description, and confirmation of persistent/global impact.

## Real examples
- 187305 — shopify-scripts: Infinite loop in Ruby heredoc parser causes unkillable process (high, $10000)
- 180695 — shopify-scripts: Large input crashes code execution service (high, $8000)
- 183425 — shopify-scripts: Segfault via Object#send in sandboxed Ruby (high, $8000)
- 1543718 — gitlab: Markdown preview with crafted input burns CPU, DoS for all users (high, $7640)
- 2105808 — rootstocklabs: UDP packet triggers infinite loop, server OOM and crash (high, $5000)
- 2586226 — ibb: Apache Tomcat HTTP/2 header miscount keeps connections open, OOM (high, $4920)
- 2334401 — ibb: HTTP/2 CONTINUATION flood causes Tomcat OOM and persistent DoS (high, $4860)
- 363636 — rootstocklabs: Peer discovery logic allows attacker to exhaust node table, DoS (high, $4000)
- 1518036 — ibb: Rust regex crate allows exponential regex, CPU DoS (high, $4000)
- 1929567 — ibb: Ruby Time parser ReDoS via crafted header, DoS in Rails apps (high, $4000)

## Bounty intelligence
High-impact DoS reports (global outage, persistent lockout, protocol-level flaws) regularly earn $4k–$10k, especially on infrastructure, SaaS, or blockchain programs. Application-level DoS (parser bombs, ReDoS, cache poisoning) typically pay $1k–$4k, with higher rewards for unauthenticated or persistent vectors. Programs with critical uptime requirements (payments, blockchain, developer platforms) pay the most and often scope protocol and parser bugs for maximum bounties.