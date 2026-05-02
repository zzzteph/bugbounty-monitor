---
category: injection
label: Injection (Other)
report_count: 41
programs: [gitlab, kubernetes, nextcloud, deptofdefense, nodejs-ecosystem, monero, phpbb, shopify, stripe, ruby, revive_adserver, liberapay, curl]
avg_bounty: 2100
max_bounty: 8690
severity_distribution: critical: 3, high: 2, medium: 15, low: 7, none: 3
---

## Overview

This category covers injection flaws outside classic SQL/command/XSS, including LDAP, object, CSS, HTML, and protocol-specific injections. These bugs break the assumption that user input is inert in resource identifiers, configuration, or protocol fields, often due to missing neutralization or unsafe interpolation. Impact ranges from privilege escalation and account takeover to RCE, authentication bypass, and phishing, depending on the context and the resource being injected.

## Root causes

- Trusting user input in resource selectors, configuration fields, or protocol messages without strict validation or encoding.
- Overly generic deserialization or parsing logic (e.g., object injection, unserialize, YAML/JSON config import).
- Incomplete or misapplied sanitization (e.g., CSS/HTML sanitizers missing edge cases, improper allowlists).
- Insufficient normalization or canonicalization (e.g., whitespace, Unicode, or delimiter confusion).
- Insecure default behaviors in frameworks/libraries (e.g., QDesktopServices::openUrl, LDAP filter construction).
- Lack of defense-in-depth when integrating with external systems (e.g., cloud controllers, OAuth, desktop clients).

## Attack surface

- Parameters or fields used as resource selectors: filenames, config URLs, template names, protocol fields, object keys.
- Any endpoint accepting user-controlled configuration or metadata (e.g., import/export, integration setup, profile fields).
- Features that reflect user input into HTML, CSS, or protocol messages (e.g., status messages, group names, email templates).
- API endpoints that proxy or fetch external resources based on user input (e.g., Swagger/OpenAPI configUrl, file importers).
- Authentication flows using LDAP, OAuth, or custom protocols with user-controlled fields.
- Desktop or mobile clients that open URLs or files based on server-supplied data.
- Systems that allow user-controlled tags or metadata (e.g., cloud resource tagging, K8s annotations).
- Inputs that are parsed or interpreted by downstream libraries (e.g., SQLString, LDAPjs, YAML/JSON parsers).

## Recon checklist

1. Enumerate all parameters and fields that are used as selectors, identifiers, or configuration (including hidden fields and JSON keys).
2. Review API schemas and OpenAPI/Swagger docs for endpoints that accept URLs, filenames, or config objects.
3. Analyze client-side JS and desktop app code for gadgets that process data-* attributes, open URLs, or parse HTML/CSS.
4. Inspect integrations with external systems (LDAP, OAuth, cloud controllers) for user input flowing into protocol messages or resource selectors.
5. Map all import/export, integration, and admin/configuration features for user-controlled resource references.
6. Check for reflection of user input in HTML, CSS, or protocol responses (including error messages and notifications).
7. Identify any deserialization, unserialize, or dynamic object construction from user input.
8. Look for normalization gaps: whitespace, Unicode, delimiter confusion, or case-insensitive comparisons.

## Hunt methodology

1. Identify all endpoints and features that accept user input as resource selectors, config, or protocol fields.
2. Send payloads containing special characters, delimiters, and protocol-specific metacharacters in these fields.
3. Attempt to inject control characters (e.g., null bytes, SOH, newlines) and observe parsing or protocol boundary confusion.
4. Test for HTML/CSS/JS injection in any field reflected into rendered content, including data-* attributes and style blocks.
5. For cloud or integration features, try to create or tag resources with colliding or confusing identifiers.
6. Attempt to supply crafted objects or arrays where primitives are expected (object injection, type confusion).
7. For desktop clients, deliver links or metadata with dangerous URI schemes or file extensions.
8. Observe responses, logs, and downstream effects for evidence of injection, privilege escalation, or resource manipulation.

## Payload library

### LDAP Injection
**Technique**: Injecting LDAP filter metacharacters to manipulate queries or cause DoS.
**How to apply**: Supply payloads with `*`, `)`, `(`, `|`, or crafted filter expressions in any field used in LDAP queries (e.g., {username}, {email}).
**Payload**: `*)(cn=*)(cn=*`
**Observe**: Application errors, authentication bypass, or slow/failed responses indicating filter expansion.
**Seen in**: Login forms with LDAP backend, registration flows with directory lookups.

### Object/Type Confusion Injection
**Technique**: Supplying objects or arrays where primitives are expected, causing logic or query confusion.
**How to apply**: Send JSON with an object or array in place of a string or number parameter (e.g., `{ "email": { "email": 1 }, "password": "{value}" }`).
**Payload**: `{"{param}": {"{key}": 1}, "password": "{value}"}`
**Observe**: Authentication bypass, logic errors, or SQL/NoSQL query confusion.
**Seen in**: API login endpoints, deserialization features.

### HTML/CSS Injection via Sanitizer Bypass
**Technique**: Exploiting incomplete HTML/CSS sanitization to inject markup or styles.
**How to apply**: Inject HTML or CSS payloads into fields reflected in rendered content (e.g., {status}, {group_name}, {title}).
**Payload**: `<img src=x onerror=alert(1)>`, `<style>.overlay{position:fixed!important;top:0;left:0;width:100%;height:100%;z-index:9999;}</style>`
**Observe**: Rendered HTML/CSS, overlays, or execution of injected markup.
**Seen in**: Status messages, group names, BBCode tags, email templates.

### Protocol Field Injection (Delimiter Confusion)
**Technique**: Injecting control characters or delimiters into protocol fields to manipulate downstream parsing.
**How to apply**: Supply payloads with control characters (e.g., `\x01`, `\n`, `\r`) in fields used in protocol messages (e.g., {username} in OAuth/SASL).
**Payload**: `user\x01host=evil.com`
**Observe**: Manipulation of protocol fields, log tampering, or credential spoofing.
**Seen in**: OAuth/SASL authentication flows, IMAP/SMTP clients.

### Resource Selector/Config Injection
**Technique**: Supplying crafted resource identifiers, URLs, or config values to manipulate resource selection or import.
**How to apply**: Inject arbitrary URLs, filenames, or config objects in parameters used for resource loading (e.g., {configUrl}, {template}, {filename}).
**Payload**: `{ "configUrl": "https://attacker.com/malicious.json" }`
**Observe**: Loading of attacker-controlled resources, spoofed content, or XSS.
**Seen in**: Swagger/OpenAPI UIs, import/export features, file/template selectors.

### Cloud Resource Tag/ID Injection
**Technique**: Creating or tagging cloud resources with identifiers that collide or are selected by controllers.
**How to apply**: Create resources with tags or IDs matching those expected by controllers (e.g., {tag_key}={tag_value}).
**Payload**: `aws ec2 create-tags --resources {sg_id} --tags "Key={tag_key},Value={tag_value}"`
**Observe**: Hijacking of resource association, privilege escalation, or deletion of legitimate resources.
**Seen in**: Cloud controller integrations, K8s ingress/annotation flows.

### Symlink/Path Traversal Injection
**Technique**: Using symlinks or crafted paths to inject or read arbitrary files during resource generation.
**How to apply**: Create symlinks or supply path traversal sequences in fields used for file operations (e.g., {filename}).
**Payload**: `ln -s /etc/passwd {filename}`
**Observe**: Inclusion of unintended file content in output or documentation.
**Seen in**: Static site generators, documentation tools, file importers.

### Whitespace/Unicode Normalization Injection
**Technique**: Using whitespace or Unicode variants to create visually indistinguishable or colliding identifiers.
**How to apply**: Supply identifiers with leading/trailing whitespace or Unicode homoglyphs (e.g., `{username}` = " admin").
**Payload**: `" admin"`
**Observe**: Creation of accounts indistinguishable from privileged users in UI/logs.
**Seen in**: User registration, account creation, audit logs.

## Filter & WAF bypass

- Use control characters (`\x01`, `\x00`, `\n`, `\r`) to break protocol parsing.
- Encode payloads using Unicode or percent-encoding to bypass naive filters.
- Exploit incomplete allowlists (e.g., `position: fixed !important` bypasses `position: fixed` block).
- Use alternate delimiters or nesting (e.g., `data:image/png,x);background:url(//attacker)` for CSS injection).
- Supply objects/arrays in JSON where strings are expected to confuse type checks.
- Use whitespace or invisible Unicode (e.g., U+200B) for normalization attacks.

## Verification & impact

- **Confirmed vulnerable**: Observe direct manipulation of resource selection, protocol fields, or rendered content (e.g., attacker-controlled POST requests, XSS, privilege escalation, authentication bypass, resource hijack).
- **False positive signals**: Input reflected but not interpreted; errors without downstream effect; input sanitized or rejected.
- **Impact escalation**: Chain resource injection to privilege escalation (e.g., admin account creation), data exfiltration (e.g., file inclusion), RCE (e.g., desktop URI handler), or phishing (e.g., overlay attacks).

## Triage & severity

- **Typical CVSS range**: Medium to Critical, depending on privilege and exploitability.
- **Severity up**: Unauthenticated exploitation, privilege escalation, RCE, account takeover, or impact on sensitive resources.
- **Severity down**: Requires admin interaction, limited to cosmetic/UI spoofing, or mitigated by sandboxing/defense-in-depth.

## Reporting tips

- Provide a minimal, reproducible PoC showing how input flows to the vulnerable sink and the resulting impact.
- Clearly state the affected feature, required privileges, and attacker-controlled fields.
- Avoid reports based only on reflection or error messages without demonstrated impact.
- Evidence checklist: request/response pairs, screenshots, logs, proof of resource manipulation or privilege escalation, and impact statement.

## Real examples

- 1409788 — gitlab: HTML injection in notebook triggers arbitrary POST as victim via JS gadget (high, $8690)
- 1533976 — gitlab: Content injection in Jira issue title enables POST as victim, leading to admin account creation (high, $8690)
- 790634 — gitlab: Branch named as git hash enables reference confusion, breaking code integrity (medium, $2000)
- 1935628 — gitlab: HTML injection in email confirmation dialog via unconfirmed email, partial admin interaction required (low, $1060)
- 1078002 — nextcloud: Desktop client RCE via malicious URI schemes in login flow (medium, $1000)
- 1238017 — kubernetes: AWS Load Balancer Controller allows attacker to replace managed security groups via tag collision (medium, $500)
- 1238482 — kubernetes: Attacker can modify rules of any tagged Security Group via controller (medium, $500)
- 906959 — nodejs-ecosystem: LDAP injection in cloudron-surfer enables DoS via crafted filter (critical, $0)
- 907311 — nodejs-ecosystem: LDAP injection in meemo-app enables DoS via crafted filter (critical, $0)
- 501585 — monero: Zero-amount miner TX + RingCT allows wallet to receive arbitrary XMR (critical, $0)
- 3590583 — nextcloud: CSS injection via unquoted background attribute bypasses remote image blocking (medium, $0)
- 3590586 — nextcloud: position: fixed !important bypasses CSS sanitizer, enables phishing overlays (medium, $0)
- 3584865 — curl: SOH character in username corrupts OAuth2 SASL message, enables protocol field injection (medium, $0)
- 3413764 — revive_adserver: Username normalization missing, enables whitespace-based impersonation (medium, $0)
- 1278050 — deptofdefense: LDAP injection in Webfinger protocol (CVE-2021-29156) enables data exfiltration (medium, $0)
- 1183335 — stripe: Object injection in login enables authentication bypass via type confusion (low, $0)
- 1374318 — ruby: Arbitrary file injection via symlink attack in documentation generator (none, $0)

## Bounty intelligence

Payouts for "Injection (Other)" are highly variable, with critical business logic or privilege escalation bugs (e.g., arbitrary POST as victim, cloud resource hijack) reaching $8k+, while protocol or UI-only injections are often lower or unawarded. SaaS platforms, cloud controllers, and integrations with external systems (LDAP, OAuth, desktop clients) tend to pay best, especially when the injection leads to privilege escalation, RCE, or account takeover. Reports with clear, reproducible impact and exploit chains (not just reflection or error) are most likely to receive higher bounties.