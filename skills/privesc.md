---
category: privilege-escalation
label: Privilege Escalation (privesc)
report_count: 292
programs: [gitlab, elastic, kubernetes, shopify, ibb, semmle, acronis, glasswire, brave, cosmos]
avg_bounty: 1700
max_bounty: 12000
severity_distribution: critical: 7, high: 7, medium: 19, low: 7
---

## Overview

Privilege escalation breaks the intended boundaries between user roles, processes, or system components, allowing attackers to gain unauthorized capabilities or access. These bugs persist due to complex permission models, implicit trust in user-supplied data, and overlooked edge cases in access control logic. The worst-case impact ranges from full system or cluster takeover, arbitrary code execution, or mass data exfiltration.

## Root causes

- Incomplete or inconsistent authorization checks on sensitive actions or endpoints.
- Implicit trust in user-controlled input for resource identifiers, file paths, or configuration parameters.
- Overly broad permissions granted to service accounts, tokens, or internal APIs.
- Insecure default configurations (e.g., world-writable files, permissive RBAC, untrusted search paths).
- Unsafe deserialization, prototype pollution, or injection into privileged contexts.
- Weak separation between user and system contexts (e.g., container/host boundaries, Electron contextBridge).

## Attack surface

- Parameters controlling user roles, permissions, or resource ownership (e.g., `{role}`, `{user_id}`, `{group_id}`, `{namespace_id}`)
- Endpoints accepting resource creation, import, or template selection (e.g., "project creation", "template import", "resource move")
- Features exposing token or credential generation (e.g., "project tokens", "service account tokens")
- File upload, import, or configuration endpoints that influence backend file paths or system config
- API endpoints or GraphQL mutations for webhook, staff, or admin actions
- RBAC/permission models in orchestrators (Kubernetes, cloud platforms)
- Dynamic plugin/driver loading (e.g., ODBC/JDBC, DLL search paths)
- Daemon/service startup routines and log file handling
- Client-side JS exposing privileged APIs via contextBridge or process.binding
- Subdomain or FQDN registration flows (for domain or subdomain takeover)

## Recon checklist

1. Enumerate all endpoints and parameters related to user, group, or resource management.
2. Map all features allowing resource import, template selection, or configuration injection.
3. Identify endpoints or flows that generate or expose tokens, credentials, or service accounts.
4. Review API schemas and GraphQL introspection for permission-altering mutations.
5. Inspect client-side JS for exposed privileged APIs or context bridging.
6. Check for dynamic plugin/driver loading features and their configuration options.
7. Analyze RBAC policies, default roles, and service account bindings.
8. Review file and directory permissions for world-writable or insecure defaults.
9. Identify all places where user input influences backend file paths, config, or system commands.
10. Look for endpoints or flows that allow domain or subdomain registration or verification.

## Hunt methodology

1. Identify endpoints or features that change roles, permissions, or resource ownership.
2. Attempt to supply unauthorized or higher-privilege values in relevant parameters (`{role}`, `{user_id}`, `{group_id}`).
3. Test resource creation/import flows with references to privileged or internal resources (`{template_id}`, `{namespace_id}`).
4. Probe for token/service account generation as a lower-privileged user and attempt to use resulting tokens for privileged actions.
5. Supply crafted file paths, symlinks, or config payloads to file upload/import/configuration endpoints.
6. Attempt to register or claim domains/subdomains using alternate encodings or FQDN tricks (e.g., trailing dot).
7. For plugin/driver loading, supply paths to attacker-controlled binaries or libraries.
8. Review and manipulate client-side JS or Electron APIs for context isolation or process.binding bypasses.

## Payload library

### Insecure Direct Object Reference (IDOR) on Privileged Actions
**Technique**: Exploit missing or incomplete authorization checks by referencing privileged resources or actions.
**How to apply**: As a low-privileged user, send requests to endpoints that accept `{user_id}`, `{group_id}`, `{resource_id}`, or `{role}` and supply values belonging to higher-privileged users or groups.
**Payload**:
```
POST /api/endpoint
{
  "user_id": "{admin_user_id}",
  "role": "admin"
}
```
**Observe**: The action is performed with elevated privileges, or the response contains data/actions not permitted for the current user.
**Seen in**: User management APIs, staff/admin creation flows, resource move/import endpoints.

### Token or Credential Generation Abuse
**Technique**: Abuse token or credential generation endpoints to obtain higher-privilege access.
**How to apply**: As a user with limited access, request a new token or credential for a resource or project, then use it to access or modify privileged resources.
**Payload**:
```
POST /api/endpoint
{
  "resource_id": "{privileged_resource_id}",
  "action": "generate_token"
}
# Use returned {token} for privileged API calls
GET /api/privileged_resource
Authorization: Bearer {token}
```
**Observe**: Access to privileged data or actions using the generated token.
**Seen in**: Project/service account token generation, API key creation flows.

### Configuration Injection / Path Traversal in Resource Definitions
**Technique**: Inject file paths or configuration directives to access or control privileged files or settings.
**How to apply**: Supply crafted values in parameters like `{path}`, `{config}`, or `{template}` that reference sensitive files or inject directives.
**Payload**:
```
POST /api/endpoint
{
  "path": "/var/run/secrets/kubernetes.io/serviceaccount/token"
}
```
or
```
POST /api/endpoint
{
  "config": "{alias /etc/shadow/;}location ~* ^/aaa"
}
```
**Observe**: Sensitive file contents are returned or privileged configuration is applied.
**Seen in**: Ingress/resource definition APIs, file import/configuration endpoints.

### Prototype Pollution / Unsafe Deserialization
**Technique**: Inject properties or objects that alter prototype chain or deserialize into privileged context.
**How to apply**: Supply JSON or object data with keys like `__proto__`, `constructor.prototype`, or nested unserializable objects.
**Payload**:
```
{
  "influencers": [
    {"influencer_field_name": "foo.__proto__.sourceURL", "influencer_field_values": "{payload}"}
  ]
}
```
**Observe**: Execution of attacker-controlled code or privilege escalation in backend logic.
**Seen in**: Telemetry, analytics, or rule processing features.

### Dynamic Plugin/Driver/DLL Loading
**Technique**: Supply paths to attacker-controlled binaries or libraries in plugin/driver configuration.
**How to apply**: Upload or reference a malicious binary/library in configuration parameters like `{driver_path}`, `{driver_class}`, or similar.
**Payload**:
```
{
  "driver_path": "/tmp/malicious.so",
  "driver_class": "EvilClass"
}
```
**Observe**: Execution of attacker code with elevated privileges.
**Seen in**: ODBC/JDBC provider configuration, DLL search path abuse.

### Symlink or File Replacement Attacks
**Technique**: Replace or symlink files in shared directories to escalate privileges or access host files.
**How to apply**: Remove a file and create a symlink to a sensitive file, then trigger a process that copies or reads it.
**Payload**:
```
rm {log_file} && ln -s /etc/passwd {log_file}
```
**Observe**: Contents of the target file are exposed or copied to attacker-controlled location.
**Seen in**: Build logs, backup/restore flows, container/host boundary crossings.

### FQDN/Domain Takeover via Alternate Encodings
**Technique**: Register or claim domains/subdomains using alternate representations (e.g., trailing dot).
**How to apply**: Supply `{domain}.` instead of `{domain}` to bypass existing ownership checks.
**Payload**:
```
POST /api/endpoint
{
  "domain": "{victim_domain}."
}
```
**Observe**: Ability to claim or serve content on a domain already in use.
**Seen in**: Domain registration/verification flows, subdomain management.

### Context Isolation/Process Binding Bypass
**Technique**: Abuse context bridging or process.binding to escape sandbox or policy restrictions.
**How to apply**: Supply unserializable objects or call internal bindings to bypass isolation.
**Payload**:
```js
const { spawn } = process.binding("spawn_sync");
spawn({ args: ["node", "-e", "require('fs').readFileSync('/etc/shadow')"] });
```
**Observe**: Access to privileged APIs or data from a restricted context.
**Seen in**: Electron apps, Node.js with experimental policies.

## Filter & WAF bypass

- Use alternate encodings for domain names (e.g., trailing dot, Unicode normalization).
- Encode path traversal with URL encoding, double encoding, or null byte injection (`%2e%2e%2f`, `%00`).
- For prototype pollution, use variations like `__proto__`, `constructor.prototype`, or Unicode homoglyphs.
- For DLL hijacking, exploit writable directories in PATH or user-controlled environment variables.
- For config injection, use comment injection or split directives with whitespace or unusual delimiters.

## Verification & impact

- **Confirmed vulnerable**: Successful privilege escalation (e.g., role change, unauthorized resource access, code execution, SYSTEM/root shell, or sensitive file read).
- **False positive signals**: Error messages without privilege change, access denied responses, or actions limited to current user scope.
- **Impact escalation**: Chain with SSRF, XSS, or RCE for full system compromise; use obtained tokens for lateral movement; exploit file read for credential theft.

## Triage & severity

- Typical CVSS: Medium to Critical (4.0–10.0), depending on scope and impact.
- Severity up: Unauthenticated exploitation, full admin/system compromise, cluster-wide impact, or ability to execute arbitrary code.
- Severity down: Requires local access, only affects non-sensitive resources, or mitigated by defense-in-depth controls.

## Reporting tips

- Provide a minimal PoC showing privilege escalation from a low-privileged to a high-privileged context.
- Include both the request(s) and the resulting impact (e.g., new admin user, SYSTEM shell, sensitive data access).
- Avoid reports based solely on error messages or theoretical impact without demonstrated escalation.
- Evidence checklist: affected endpoint/parameter, request/response pairs, before/after privilege state, and screenshots/logs of impact.

## Real examples

- 689314 — gitlab: Project template import allowed copying private/confidential resources to unauthorized namespaces (critical, $12000)
- 852613 — elastic: Prototype pollution in telemetry collector led to RCE via crafted saved objects (critical, $10000)
- 1168765 — elastic: Reporting feature invoked headless Chromium with `--no-sandbox`, enabling RCE via HTML injection (critical, $10000)
- 861744 — elastic: Prototype pollution in SIEM signal feature enabled RCE via crafted ML anomaly (critical, $5000)
- 1382919 — kubernetes: Ingress path config injection exposed service account token with cluster-wide secret access (high, $2500)
- 1842829 — kubernetes: GCP state bucket exposure allowed pod users to escalate to cluster admin and compromise GCP project (high, $2500)
- 694181 — semmle: Symlink attack in worker container allowed arbitrary file read from host (critical, $2000)
- 697055 — semmle: Symlink to config file enabled host file read after build (critical, $2000)
- 2930811 — cosmos: Capability checks bypassed, allowing contracts to execute any action regardless of declared capabilities (low, $2000)
- 1086108 — shopify: FQDN trailing dot bypass allowed wholesale domain takeover (medium, $3100)

## Bounty intelligence

Critical privilege escalation with RCE or full admin/system compromise can fetch $5,000–$12,000+ on mature SaaS, cloud, or infrastructure programs. Kubernetes, CI/CD, and cloud platform bugs are especially valued. Lower-impact or local-only privesc typically earns $250–$2,500. Programs with complex permission models or multi-tenant features (e.g., GitLab, Shopify, Elastic) pay top dollar for reliable, high-impact privilege escalation chains.