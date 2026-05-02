---
category: idor
label: IDOR / Broken Access Control
report_count: 40
programs: [gitlab, shopify, reddit, security, ibb, eternal, x, phabricator, owncloud, pixiv]
avg_bounty: 5400
max_bounty: 22300
severity_distribution: critical: 4, high: 12, medium: 22, low: 2
---

## Overview

IDOR and Broken Access Control bugs break the core invariant that users can only act on resources they own or are authorized for. These flaws persist because developers rely on client-supplied identifiers, trust frontend logic, or misapply framework-level access checks. The worst-case impact is full account takeover, mass data exfiltration, or privilege escalation—often with a single modified request.

## Root causes

- Relying on client-supplied identifiers without server-side ownership or permission checks.
- Inconsistent or missing authorization logic between API endpoints, web UI, and background jobs.
- Overly permissive or misconfigured access policies (e.g., default-allow, missing deny rules).
- Trusting frontend-enforced restrictions (e.g., UI hiding, client-side checks) instead of enforcing on the backend.
- Insecure import/export flows that allow arbitrary object references or attribute injection.
- Incomplete patching—blocking one vector but leaving alternate fields or flows open.

## Attack surface

- Numeric or UUID resource identifiers in URL paths, query parameters, POST bodies, or GraphQL variables (e.g., `{id}`, `{user_id}`, `{resourceId}`).
- Bulk import/export features accepting user-supplied object references or attributes.
- Invitation, registration, or onboarding flows that link accounts or grant roles.
- File download/upload endpoints, especially with presigned URLs or indirect references.
- GraphQL mutations and queries with insufficient resolver-level access checks.
- OAuth/OIDC callback and redirect flows, especially with open `redirect_uri`.
- Internal proxy, admin, or debug endpoints exposed to untrusted users.
- Features gated by frontend logic (e.g., buttons hidden in UI) but not enforced server-side.
- Permission models or access control middleware with experimental or misconfigured settings.

## Recon checklist

1. Enumerate all endpoints accepting resource identifiers as parameters, path segments, or in request bodies.
2. Map all GraphQL operations and variables—look for IDs, especially in mutations.
3. Review API documentation or OpenAPI/GraphQL schemas for resource-modifying operations.
4. Identify import/export, clone, or copy features—inspect accepted fields and file formats.
5. Analyze invitation, onboarding, and role assignment flows for trust boundaries.
6. Check for presigned URLs, download tokens, or temporary access links in responses.
7. Inspect client-side JS for hidden features, privilege checks, or conditional UI logic.
8. Review authentication and authorization middleware for gaps or bypasses.

## Hunt methodology

1. Identify endpoints or GraphQL operations that accept `{id}`, `{user_id}`, `{resourceId}`, or similar parameters.
2. Send authorized requests for your own resources and capture the full request/response.
3. Modify the identifier to reference another user's resource (increment, decrement, or guess plausible IDs).
4. Observe if the response returns unauthorized data, allows modification, or leaks metadata.
5. Repeat with different HTTP methods (GET, POST, PUT, DELETE, PATCH) and for both API and web UI endpoints.
6. For import/export flows, craft payloads referencing arbitrary object IDs or injecting attributes.
7. Test invitation or onboarding flows by accepting invites with attacker-controlled accounts or emails.
8. Attempt to access or modify resources after role changes (e.g., demotion, deactivation, block) to check for stale permissions.

## Payload library

### Direct ID Manipulation
**Technique**: Exploit endpoints that use user-supplied IDs without verifying ownership or permissions.
**How to apply**: Replace `{id}` in any request (URL, body, or GraphQL variable) with another user's or resource's ID.
**Payload**:  
`GET /api/endpoint/{id}`  
or  
`POST /api/endpoint` with body `{ "id": "{target_id}" }`
**Observe**: Access to or modification of another user's resource, or leakage of sensitive data.
**Seen in**:  
- Message deletion APIs on messaging platforms  
- Billing document queries in SaaS admin panels  
- Spotlight/video deletion in social media content management

### Attribute Injection in Import/Export
**Technique**: Abuse import/export features that accept arbitrary object references or attributes.
**How to apply**: Craft import payloads (e.g., JSON, tarballs) with fields like `{foreign_key_ids}` or nested attributes referencing unauthorized resources.
**Payload**:  
`{ "attributes": { "resource_ids": [ {target_id} ] } }`
**Observe**: Imported data includes or links to resources owned by other users.
**Seen in**:  
- Project import/export on code hosting platforms  
- Bulk data migration tools in enterprise SaaS  
- Service template injection in project creation flows

### GraphQL Operation Abuse
**Technique**: Invoke GraphQL queries or mutations with arbitrary IDs, bypassing resolver-level access checks.
**How to apply**: Send GraphQL requests with `{id}` or `{resourceId}` variables set to unauthorized values.
**Payload**:  
```json
{
  "operationName": "{Operation}",
  "variables": { "id": "{target_id}" },
  "query": "query {Operation}($id: ID!) { resource(id: $id) { ... } }"
}
```
**Observe**: Data returned or modified for resources not owned by the attacker.
**Seen in**:  
- Billing, invoice, or file operations in admin panels  
- Certification/license management in user profiles  
- Mod log access in community management tools

### Authorization Bypass via Alternate Flows
**Technique**: Use alternate endpoints, embedded forms, or invitation flows to bypass enforced restrictions.
**How to apply**: Submit requests via less-protected flows (e.g., embedded forms, invitation acceptance, or onboarding endpoints).
**Payload**:  
`POST /api/endpoint` with body `{ "email": "{target_email}", ... }`
**Observe**: Privilege escalation, bypass of 2FA or jurisdiction restrictions, or unauthorized account linking.
**Seen in**:  
- Embedded submission forms bypassing 2FA  
- Invitation acceptance without email verification  
- Sandbox/testimonial flows allowing self-promotion

### File/Object Reference via Predictable IDs
**Technique**: Reference files or objects by predictable or incremental IDs in download/upload endpoints.
**How to apply**: Guess or enumerate `{file_id}` or `{object_id}` in download URLs or API requests.
**Payload**:  
`GET /api/files/{file_id}`  
or  
`GET /download?object={object_id}`
**Observe**: Download or access to files belonging to other users.
**Seen in**:  
- Artifact download endpoints in CI/CD systems  
- File copy or presigned URL download features  
- Address enumeration in e-commerce or delivery platforms

### OAuth/Open Redirect Parameter Abuse
**Technique**: Manipulate redirect or callback parameters to leak tokens or authorization codes.
**How to apply**: Supply crafted `redirect_uri` or similar parameters in OAuth/OIDC flows.
**Payload**:  
`redirect_uri=https://attacker.com/callback`
**Observe**: Authorization code or token delivered to attacker-controlled endpoint.
**Seen in**:  
- OAuth callback flows on SaaS apps  
- SSO integrations with insufficient redirect validation

### Permission Model/Policy Bypass
**Technique**: Exploit misconfigurations or bypasses in experimental permission models or policy enforcement.
**How to apply**: Use alternate APIs, internal modules, or wildcard patterns to access restricted resources.
**Payload**:  
- Use `Module._load()` or `require.extensions` in Node.js  
- Supply wildcard paths like `/path/*` in permission flags
**Observe**: Access to files, modules, or APIs outside intended scope.
**Seen in**:  
- Node.js permission model and policy enforcement  
- Internal admin/debug endpoints

## Filter & WAF bypass

- Use numeric, UUID, or base64-encoded IDs—avoid obvious payloads.
- For GraphQL, try both string and integer representations of IDs.
- In import/export, nest forbidden fields inside allowed objects or attributes.
- For file/object endpoints, brute-force or enumerate IDs with timing or error-based feedback.
- In OAuth flows, use path traversal (`../`) or encoded slashes in `redirect_uri`.
- For permission models, exploit undocumented or legacy API routes, or use alternate HTTP verbs.

## Verification & impact

- **Confirmed vulnerable**: Successful access, modification, or deletion of another user's resource; data returned for unauthorized IDs; privilege escalation or role change; download of non-owned files.
- **False positive signals**: "Not found" or generic error responses without data leakage; UI-only restrictions with backend enforcement; rate-limited or throttled responses without actual access.
- **Impact escalation**: Chain with account takeover (e.g., via OAuth), data exfiltration (billing, PII, files), privilege escalation (role/owner changes), or RCE (via policy bypass or service injection).

## Triage & severity

- Typical CVSS: Medium to High (4.3–8.8), Critical if mass compromise or privilege escalation is possible.
- Severity increases with: unauthenticated access, sensitive data (PII, billing, secrets), privilege escalation, mass impact (bulk import/export), or RCE potential.
- Severity decreases with: authenticated-only access, limited scope (single resource), mitigations (rate limiting, audit logs), or non-sensitive data.

## Reporting tips

- Strong PoC: Minimal request/response pair showing unauthorized access or modification, with clear before/after state.
- Avoid: Reports with only UI bugs, missing impact, or speculative claims without evidence.
- Evidence checklist:  
  - Full request/response (with redacted sensitive info)  
  - Steps to reproduce (including how target ID was obtained)  
  - Impact statement (what attacker can do, who is affected)  
  - Screenshots or logs if applicable  
  - Any relevant code snippets or logic analysis

## Real examples

- 1685822 — gitlab: Arbitrary local repository import via crafted URL in project import (medium, $22,300)
- 743953 — gitlab: Importing crafted project exports to steal private issues/merge requests (critical, $20,000)
- 767770 — gitlab: Attribute injection in import bypassing previous fix, stealing private objects (critical, $20,000)
- 1819832 — snapchat: Deleting any user's viral video by manipulating ID in delete request (high, $15,000)
- 2122671 — security: Deleting all licenses/certifications by changing ID in GraphQL mutation (high, $12,500)
- 446585 — gitlab: Service template injection via project import, exfiltrating repo data (critical, $11,000)
- 418767 — security: Bypassing 2FA and blacklist via embedded submission form (medium, $10,000)
- 2967634 — reddit: Exposed proxy allows access to internal domains (high, $7,500)
- 1439026 — x: Bypassing privacy settings to enumerate accounts by email/phone (high, $5,040)
- 1213237 — reddit: Deleting all private messages via missing permission check (high, $5,000)

## Bounty intelligence

Bounties for IDOR/Broken Access Control range from $1,000 for low-impact or authenticated-only issues, up to $20,000+ for mass compromise, privilege escalation, or critical data exfiltration. SaaS platforms, code hosting, and fintech/commerce programs pay highest for IDORs affecting sensitive data or business logic. Reports with clear mass impact, unauthenticated access, or privilege escalation consistently receive top-tier rewards.