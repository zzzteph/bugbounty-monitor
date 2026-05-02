---
category: info_disclosure
label: Information Disclosure
report_count: 1098
programs: [security, gitlab, shopify, ibb, x, basecamp, torproject]
avg_bounty: 4200
max_bounty: 25000
severity_distribution: critical: 4, high: 6, medium: 26, low: 2, none: 1
---

## Overview

Information disclosure bugs break the expectation that sensitive data is only accessible to authorized users or systems. These flaws persist due to overbroad serialization, missing access checks, leaky error messages, and architectural shortcuts. The worst-case impact ranges from credential and PII leaks to full account takeover or lateral movement via exposed secrets.

## Root causes

- Overly permissive or missing authorization checks on data-fetching endpoints (e.g., GraphQL, REST, feeds).
- Insecure serialization: exposing internal fields or objects in API responses without filtering sensitive attributes.
- Misconfigured storage (e.g., public S3 buckets, world-readable files) or caching (e.g., public cache of session cookies).
- Legacy or third-party components with known memory disclosure or side-channel vulnerabilities.
- Incomplete redaction or filtering logic, especially in automated exports or bot responses.
- Inconsistent privacy controls between UI and API endpoints.

## Attack surface

- API endpoints returning user, project, or resource objects in JSON/GraphQL (especially `.json`, `/api/`, `/graphql`).
- File upload/download handlers, especially those serving user-generated or internal files.
- Atom/RSS feeds, export/download endpoints, or preview links.
- Public cloud storage buckets or CDN URLs.
- Error messages, debug output, or status fields in API responses.
- OAuth, SSO, or authentication/authorization flows.
- Application logs, build logs, or CI/CD artifacts.
- GraphQL queries exposing nested objects or fields.
- Features: collaborator/invite flows, report exports, profile/metrics endpoints, chat/order lookup, advanced vetting downloads.
- Tech stacks: Rails Active Storage, Django REST, Node.js with overbroad serialization, misconfigured NGINX/QUIC, legacy Flash/JavaScript, curl/libcurl, OpenSSL, etc.

## Recon checklist

1. Enumerate all API endpoints and export/download features (REST, GraphQL, feeds, file handlers).
2. Map all object types and their serialized fields via introspection, schema docs, or fuzzing.
3. Identify endpoints that accept resource IDs, tokens, or usernames as parameters.
4. Check for public or unauthenticated access to storage buckets, CDN URLs, or preview links.
5. Review GraphQL schema for sensitive fields or nested objects accessible to low-privilege users.
6. Inspect error messages, status codes, and debug output for leaked identifiers or sensitive data.
7. Analyze caching headers and CDN/proxy behavior for sensitive endpoints.
8. Review client-side code for hidden API calls, preview URLs, or feature toggles.

## Hunt methodology

1. Send unauthenticated and low-privilege requests to all API endpoints and export/download features.
2. Query for objects by ID, token, or username and inspect all response fields for sensitive data.
3. Attempt to access feeds, exports, or preview links without proper authentication or with alternate tokens.
4. Use GraphQL introspection to enumerate fields, then query for nested sensitive attributes.
5. Manipulate request parameters (e.g., resource IDs, usernames, file paths) to access unauthorized data.
6. Analyze error messages and status codes for information about existence, permissions, or internal state.
7. Test file upload/download endpoints for path traversal, symlink, or storage misconfiguration.
8. Review caching headers and test for cache poisoning or leakage of session/cookie data.

## Payload library

### Overbroad Serialization / Sensitive Field Exposure
**Technique**: Exploit endpoints that serialize entire objects, leaking internal or sensitive fields.
**How to apply**: Send a GET or POST request to an object-fetching endpoint (e.g., `/api/endpoint/{id}.json`, GraphQL query for `{object(id: {id}) { ... }}`) and inspect the full response for unexpected fields.
**Payload**:
```
GET /api/endpoint/{id}.json
```
or
```
POST /graphql
{"query":"{object(id: \"{id}\") { id, email, token, backup_codes, ... }}"}
```
**Observe**: Presence of sensitive fields (emails, tokens, backup codes, secrets) in the response.
**Seen in**: JSON endpoints for user/project objects, GraphQL queries for team or report objects, collaborator/invite flows.

### Authorization Bypass / Insecure Direct Object Reference
**Technique**: Access resources or data by manipulating IDs, tokens, or usernames without proper authorization checks.
**How to apply**: Change `{id}`, `{token}`, or `{username}` in API requests to values belonging to other users or resources.
**Payload**:
```
GET /api/endpoint/{id}
POST /graphql
{"query":"{resource(id: \"{id}\") { ... }}"}
```
**Observe**: Data for unauthorized users/resources is returned.
**Seen in**: Order lookup in chat apps, collaborator/invite flows, report exports, vetting downloads.

### Public/Unprotected Export, Feed, or Storage Access
**Technique**: Access feeds, exports, or storage objects via public or weakly protected URLs.
**How to apply**: Attempt to access known or guessable export, feed, or storage URLs without authentication or with alternate tokens.
**Payload**:
```
GET /feeds/{resource}.atom
GET /storage/{bucket}/{object}
GET /exports/{resource}.csv
```
**Observe**: Sensitive data (orders, images, reports, PII) is accessible without proper authorization.
**Seen in**: Atom/RSS feeds, S3 buckets, vetting/export downloads, CDN URLs.

### Cache/Proxy Leakage
**Technique**: Sensitive data (e.g., session cookies) is cached and served to other users due to misconfigured headers.
**How to apply**: Trigger a request to a file-serving endpoint, observe caching headers, and attempt to access the same resource from another session or user.
**Payload**:
```
GET /files/{blob_id}
```
**Observe**: Session cookies or user-specific data present in cached responses.
**Seen in**: File serving via Active Storage, CDN-backed endpoints.

### Error Message/Side Channel Enumeration
**Technique**: Infer existence or properties of resources via error messages, status codes, or timing/ordering side channels.
**How to apply**: Request resources with varying parameters and analyze error responses or timing/order of responses.
**Payload**:
```
GET /api/endpoint/{nonexistent_id}
POST /graphql
{"query":"{resource(id: \"{id}\") { ... }}"}
```
**Observe**: Differences in error messages, status codes, or response timing reveal resource existence or attributes.
**Seen in**: Application name enumeration, private program detection, HTTP/2 stream timing.

### Path Traversal / File Read via Upload/Download
**Technique**: Abuse file upload/download endpoints to read arbitrary files within allowed paths.
**How to apply**: Manipulate file path parameters or multipart field names to reference internal files.
**Payload**:
```
POST /api/endpoint
Content-Type: multipart/form-data; boundary=...

--boundary
Content-Disposition: form-data; name="[file]"; filename="{filename}"
Content-Type: application/octet-stream

{file contents}
--boundary--
```
or
```
POST /api/endpoint?file.path=/etc/passwd
```
**Observe**: Contents of internal files returned in response.
**Seen in**: File upload/download handlers, wiki attachment endpoints.

### Memory Disclosure / Side-Channel Attacks
**Technique**: Exploit vulnerabilities in libraries (e.g., outdated image processors, NGINX QUIC, OpenSSL) to leak memory or sensitive data.
**How to apply**: Upload crafted files or send protocol-specific requests to trigger memory disclosure.
**Payload**:
```
Upload crafted SVG/image file
Send QUIC packets with large MTU
Send timing-sensitive RSA ciphertexts
```
**Observe**: Leaked memory fragments, secrets, or decrypted data in responses.
**Seen in**: SVG/image uploaders, NGINX QUIC endpoints, OpenSSL-backed services.

## Filter & WAF bypass

- Use alternate HTTP methods (e.g., POST vs GET) or multipart field names to bypass method-based filters.
- Encode path traversal payloads with URL encoding, double encoding, or Unicode homoglyphs.
- Manipulate case sensitivity in domain/cookie parameters (e.g., `domain=co.UK`).
- Use GraphQL introspection and field aliasing to bypass field-level access controls.
- Exploit weak or missing authentication tokens in preview/export URLs.
- Abuse chunked encoding or smuggling for endpoints with incomplete request parsing.

## Verification & impact

- **Confirmed vulnerable**: Sensitive data (PII, credentials, tokens, internal fields, private resource content) is returned to an unauthorized or unauthenticated user.
- **False positive signals**: Presence of non-sensitive metadata, or fields intentionally exposed to all users; error messages without actual data leakage.
- **Impact escalation**: Use leaked credentials/tokens for account takeover, lateral movement, or privilege escalation; chain with IDOR or SSRF for further compromise; use PII for phishing or social engineering.

## Triage & severity

- Typical CVSS: Medium to Critical (4.0–9.8), depending on data sensitivity and exploitability.
- Severity up: Leaks of credentials, tokens, PII, or secrets; unauthenticated access; ability to chain to account takeover or RCE.
- Severity down: Only non-sensitive metadata exposed; authenticated-only; mitigated by additional controls (e.g., IP allowlist, short-lived tokens).

## Reporting tips

- Provide a minimal PoC that demonstrates unauthorized access to sensitive data (request + response).
- Clearly state what data is exposed, who can access it, and why it is sensitive.
- Avoid reports based solely on metadata or non-sensitive fields.
- Include evidence: full request/response, screenshots, and impact statement.
- Note any chaining potential or business impact (e.g., account takeover, compliance violation).

## Real examples

- 3000510 — security: Sensitive user attributes (emails, OTP backup codes, tokens) leaked via overbroad JSON serialization on report endpoints (critical, $25000)
- 509924 — gitlab: Project model serialization exposed runner tokens via Quick Actions, enabling token theft (critical, $12000)
- 850447 — gitlab: File upload bypass allowed reading arbitrary files in allowed paths, leaking sensitive server files (critical, $10000)
- 2107680 — basecamp: SVG upload triggered memory disclosure in image processing, leaking AWS keys and user cookies (high, $8868)
- 2032716 — security: GraphQL mutation leaked any user's email via collaborator invite flow (high, $12500)
- 807448 — security: Email disclosure of any user via invite and token flows (high, $7500)
- 188719 — security: Skills API leaked report titles submitted as proof, exposing private report info (medium, $10000)
- 1256375 — shopify: Atom feed for password-protected blogs accessible via preview links, bypassing authentication (medium, $5000)
- 3082917 — ibb: Active Storage served session cookies with public cache headers, risking session theft via cache (high, $4323)
- 968165 — shopify: Chat app order lookup endpoint allowed brute-forcing order details with partial email, leaking customer data (medium, $2500)

## Bounty intelligence

Payouts range from $1,500 for minor leaks (metadata, low-sensitivity info) to $25,000 for critical credential or PII exposure. SaaS platforms, developer tools, and cloud providers pay highest for leaks enabling account takeover, credential theft, or lateral movement. Reports with clear exploitability, unauthenticated access, or business-critical data exposure consistently command higher bounties and faster triage.