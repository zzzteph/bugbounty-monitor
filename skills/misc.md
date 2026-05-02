---
category: miscellaneous
label: Miscellaneous
report_count: 1574
programs: [shopify, security, cosmos, ibb, nextcloud, gitlab, rails]
avg_bounty: 5900
max_bounty: 50000
severity_distribution: critical: 3, high: 11, medium: 24, low: 1
---

## Overview
Miscellaneous vulnerabilities break invariants that don't fit classic bug classes, often surfacing from unique business logic, misconfigurations, or overlooked edge cases in complex systems. These bugs persist because they fall outside standard security checklists, involve subtle trust boundaries, or result from framework/library misuse. Worst-case impacts range from full infrastructure compromise (token leaks, RCE) to privilege escalation, data exposure, or platform-wide DoS.

## Root causes
- Overly permissive or missing validation on critical parameters or configuration fields.
- Insecure default settings or failure to enforce least privilege (e.g., file permissions, API exposure).
- Race conditions or concurrency issues in business logic not designed for parallel execution.
- Trusting client-supplied data or failing to authenticate/authorize sensitive operations.
- Misuse or misunderstanding of framework/library features (e.g., GraphQL, mod_rewrite, ORM APIs).
- Lack of defense-in-depth, allowing single points of failure to escalate into critical impact.

## Attack surface
- API tokens, secrets, or credentials embedded in client-side code, config files, or public artifacts.
- GraphQL endpoints with object ID access, unrestricted queries, or mutation aliasing.
- HTTP headers (Range, Accept, custom headers) and body fields processed by middleware or frameworks.
- File upload, import, or parsing endpoints (especially those handling YAML, multipart, or custom config).
- Admin or staff permission management APIs, especially with complex role hierarchies.
- Publicly exposed internal services (metrics, debug, or admin APIs) lacking authentication.
- Features relying on concurrency limits or stateful logic (e.g., faucets, rate-limited endpoints).
- Server-side URL rewriting/proxying rules (mod_rewrite, mod_proxy, NGINX, etc.).
- Client-side or desktop app packaging (ASAR, Electron, etc.) and integrity checks.
- Cloud provider integrations and plugin configuration interfaces.

## Recon checklist
1. Enumerate all endpoints, including GraphQL schemas, REST APIs, and undocumented admin/debug interfaces.
2. Download and decompile client apps (Electron, mobile, desktop) to search for embedded secrets or config files.
3. Review JavaScript bundles and source maps for references to sensitive variables or endpoints.
4. Map all HTTP headers accepted by the server and test for non-standard or legacy header handling.
5. Identify all permission/role management features and enumerate possible privilege escalation paths.
6. Inspect exposed file upload/import features for accepted file types, parsing logic, and error handling.
7. Analyze server response to malformed or boundary-case input (oversized, encoded, or concurrent requests).
8. Review server and framework version info for known CVEs or insecure defaults.

## Hunt methodology
1. Search for exposed secrets or credentials in client-side code, config files, and public repositories.
2. Enumerate GraphQL object types and test for unauthorized access to sensitive objects via ID enumeration.
3. Send concurrent requests to endpoints with stateful logic to identify race conditions or concurrency flaws.
4. Manipulate HTTP headers (Range, Accept, Content-Type) to test for DoS, parsing, or smuggling vulnerabilities.
5. Probe admin, staff, or permission management APIs for privilege escalation or bypasses.
6. Test file upload/import endpoints with crafted files (YAML, multipart, config) for injection or RCE.
7. Fuzz URL rewriting/proxying rules with encoded, malformed, or ambiguous paths to trigger SSRF, RCE, or bypasses.
8. Attempt to access internal or debug endpoints (metrics, pprof, admin) from unauthenticated contexts.

## Payload library

### Exposed Secrets in Client Artifacts
**Technique**: Sensitive tokens or credentials are left in client-distributed files or public repositories.
**How to apply**: Extract all files from packaged apps or public artifacts, search for variables like `{TOKEN}`, `{SECRET}`, `{API_KEY}` in config or source files.
**Payload**:  
```
grep -iE '(token|secret|key|password)' {extracted_dir}/*
```
**Observe**: Discovery of valid credentials; test them against the relevant API with:
```
curl -H "Authorization: token {token}" https://api.github.com/user
```
**Seen in**: Desktop app packaging, Electron ASAR archives, public .env/config files.

### GraphQL Object Enumeration & Overbroad Access
**Technique**: GraphQL endpoints allow access to sensitive objects by guessing or enumerating IDs.
**How to apply**: Query the GraphQL API with incrementing or pattern-based `{id}` values for sensitive object types.
**Payload**:  
```
{"query":"{node(id:\"{object_id}\"){... on {ObjectType}{id,name}}}"}
```
**Observe**: Unauthorized data returned for objects outside your scope.
**Seen in**: Asset/program enumeration, private report title disclosure, internal object leaks.

### GraphQL Mutation Aliasing for DoS
**Technique**: Multiple aliases of expensive mutations in a single GraphQL request cause linear resource exhaustion.
**How to apply**: Craft a mutation with multiple aliases of the same expensive operation.
**Payload**:  
```
mutation MultiAlias($input: InputType!) {
  op1: expensiveMutation(input: $input) { result }
  op2: expensiveMutation(input: $input) { result }
  op3: expensiveMutation(input: $input) { result }
}
```
**Observe**: Server response time increases linearly with the number of aliases.
**Seen in**: Account recovery, verification, or resource-intensive GraphQL mutations.

### HTTP Header Manipulation (Range, Accept, etc.)
**Technique**: Malformed or oversized headers trigger DoS, parsing errors, or bypasses in middleware.
**How to apply**: Send requests with crafted headers to endpoints processing files or parsing headers.
**Payload**:  
```
Range: bytes=0-999999999999999999999
Accept-Encoding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
**Observe**: Excessive server response time, large responses, or error logs.
**Seen in**: File serving middleware, Rails/Rack, NGINX, Apache.

### Race Condition via Concurrent Requests
**Technique**: Lack of atomicity in stateful logic allows bypassing limits or quotas.
**How to apply**: Send multiple concurrent requests to endpoints enforcing limits (e.g., token faucets, rate-limited APIs).
**Payload**:  
```
for i in {1..50}; do curl -X POST -d '{"address":"{victim_address}"}' https://{host}/api/endpoint & done
```
**Observe**: Limit exceeded, duplicated actions, or inconsistent state.
**Seen in**: Token faucets, balance updates, quota enforcement.

### File Parsing/Upload Injection
**Technique**: Uploading crafted files (YAML, config, multipart) triggers code execution or privilege escalation.
**How to apply**: Upload a file with malicious payload (e.g., YAML object, symlink, or oversized field) to the import or upload endpoint.
**Payload**:  
- Malicious YAML:
  ```
  !!python/object/apply:os.system ["id"]
  ```
- Oversized multipart:
  ```
  --boundary
  Content-Disposition: form-data; name="file"; filename="test.txt"
  Content-Type: text/plain

  {very_large_string}
  --boundary--
  ```
**Observe**: Code execution, file overwrite, or excessive processing time.
**Seen in**: Config import, documentation generators, multipart parsers.

### URL Rewriting/Proxy Rule Abuse
**Technique**: Malformed or encoded URLs bypass rewrite/proxy rules, leading to SSRF, RCE, or source disclosure.
**How to apply**: Send requests with encoded path segments, ambiguous separators, or crafted query strings.
**Payload**:  
```
GET /{encoded_path}%3F{param} HTTP/1.1
Host: {host}
```
**Observe**: Access to unintended files, SSRF, or backend request smuggling.
**Seen in**: Apache mod_rewrite, mod_proxy, NGINX proxy_pass.

### Permission Escalation via API/Role Misconfiguration
**Technique**: Insufficient checks on role/permission APIs allow privilege escalation or unauthorized actions.
**How to apply**: Use API endpoints to assign higher privileges or access restricted features with lower-privileged accounts.
**Payload**:  
```
PUT /api/endpoint/{id}
Authorization: Bearer {low_priv_token}
Content-Type: application/json

{"role": "admin"}
```
**Observe**: Privilege escalation, access to restricted features, or unauthorized data modification.
**Seen in**: Staff/role management, project/group visibility, invite flows.

## Filter & WAF bypass
- Use alternate encodings (`%0d%0a`, `%25`, `%3F`, `%2F`, `%5C`) in URLs and headers.
- Exploit Unicode normalization (e.g., homoglyphs, overlong UTF-8).
- Insert null bytes (`\0`) in parameters to truncate or bypass string checks.
- Abuse HTTP/2 pseudo-headers or malformed header casing.
- Use chunked encoding or split requests to evade length-based or line-based filters.
- For multipart or YAML, use deeply nested or oversized fields to trigger parser edge cases.

## Verification & impact
- **Confirmed vulnerable**: Unauthorized data access, privilege escalation, code execution, or DoS (measurable resource exhaustion, server crash, or deadlock).
- **False positive signals**: Error messages without impact, rejected requests, or non-exploitable parsing errors.
- **Impact escalation**: Chain token/secret exposure to infrastructure compromise; combine race conditions with quota bypass; SSRF to internal network access; DoS to platform-wide outage.

## Triage & severity
- Typical CVSS: Medium to Critical (4.0–10.0), depending on exploitability and impact.
- Severity up: Unauthenticated exploitation, infrastructure compromise, RCE, privilege escalation, or platform-wide DoS.
- Severity down: Requires local access, only affects non-sensitive features, or mitigated by defense-in-depth.

## Reporting tips
- Strong PoC: Minimal reproducer (e.g., curl or script), clear impact demonstration (e.g., unauthorized access, privilege escalation, or code execution).
- Avoid: Reports with only theoretical impact, missing proof, or vague reproduction steps.
- Evidence checklist: Full request/response pairs, screenshots or logs of impact, description of root cause, and impact statement.

## Real examples
- 1087489 — shopify: GitHub access token exposed in desktop app, leading to full repo compromise (critical, $50000)
- 1618347 — security: GraphQL endpoint leaked private program asset data via ID enumeration (critical, $25000)
- 3018307 — cosmos: Malicious group weights triggered chain halt via exponent out-of-range, causing DoS (high, $15000)
- 3287208 — security: GraphQL mutation aliasing allowed single-request DoS via resource exhaustion (high, $12500)
- 1258871 — shopify: Exposed Cortex metrics/debug API allowed unauthenticated access and DoS (medium, $6300)
- 2520679 — ibb: Crafted Range headers in Rack caused large responses and DoS (high, $5420)
- 1438052 — cosmos: Race condition in faucet allowed bypass of token limits (critical, $5000)
- 2585378 — ibb: Apache mod_rewrite allowed code execution/source disclosure via unsafe substitutions (high, $4920)
- 2438265 — ibb: RDoc YAML parsing allowed RCE via crafted .rdoc_options (high, $4860)
- 2094785 — ibb: Cargo archive extraction ignored umask, enabling local code injection (high, $4660)
- 2646493 — ibb: Django QuerySet.values() SQLi via crafted JSONField key (high, $4263)
- 1804128 — ibb: ReDoS in rails-html-sanitizer allowed DoS via SVG attribute parsing (high, $4000)
- 1044285 — shopify: Download link endpoint exposed latest digital asset to any user (medium, $2900)
- 2584376 — ibb: ReDoS in Rack Accept header parsing led to DoS (medium, $2642)
- 2526046 — ibb: NGINX HTTP/3 QUIC module allowed worker crash via crafted encoder instructions (medium, $2600)
- 2271095 — ibb: ASAR integrity bypass via filetype confusion enabled code loading outside validated archive (medium, $2540)
- 2071556 — ibb: Rack header parsing ReDoS allowed DoS via crafted input (medium, $2540)
- 1872682 — ibb: Apache Airflow log file permissions allowed privilege escalation via symlink attack (medium, $2400)
- 1594627 — ibb: Apache mod_proxy_ajp request smuggling enabled backend attacks (medium, $2400)
- 1391549 — ibb: HTTP/2 request line injection in mod_proxy enabled cache poisoning and bypasses (medium, $1200)

## Bounty intelligence
Payouts for miscellaneous vulnerabilities vary widely, with critical infrastructure or credential exposure (e.g., token leaks, RCE, chain halts) commanding $10k–$50k+. High-impact DoS, SSRF, or privilege escalation typically land in the $2k–$10k range. Programs with broad scope (cloud, SaaS, blockchain, infrastructure) and those accepting novel or "out-of-class" bugs pay best, especially when the report demonstrates real-world exploitability and business impact.