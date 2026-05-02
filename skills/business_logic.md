---
category: business_logic
label: Business Logic
report_count: 358
programs: [gitlab, valve, reddit, stripe, security, ibb, indrive, x, upserve, shopify]
avg_bounty: 1800
max_bounty: 12000
severity_distribution: critical: 3, high: 2, medium: 20, low: 15
---

## Overview

Business logic vulnerabilities break the intended workflows, rules, or constraints of an application, allowing attackers to manipulate processes for financial gain, privilege escalation, or data access. These bugs persist because developers focus on technical controls and miss edge cases in complex, multi-step flows, especially where trust boundaries or state transitions are involved. The worst-case impact includes unauthorized fund transfers, privilege escalation, bypassing critical reviews, or mass data exfiltration.

## Root causes

- Missing or incomplete server-side validation of workflow state or user actions
- Trusting client-side enforcement for limits, quotas, or eligibility
- Failing to lock or synchronize state transitions (race conditions)
- Overly permissive or misapplied access control on sensitive actions
- Inadequate tracking of resource ownership or assignment
- Insufficient validation of cross-system integrations or callback flows

## Attack surface

- Parameters controlling state transitions (e.g., status, approval, role, ownership)
- Identifiers for resources, orders, or users in API requests (especially PATCH/PUT/POST)
- Bulk or batch operation endpoints (e.g., mass update, import, transfer)
- Payment and discount redemption flows
- Invitation, onboarding, or access grant mechanisms
- Account linking, OAuth, or SSO integrations
- File or asset reference fields (IDs, URLs) in edit or attach flows
- Features with client-side limits (e.g., item selection, modifier counts)
- Endpoints lacking idempotency or transactional locking
- Cloud resource or domain claim flows (subdomain, bucket, or package linking)
- Flows involving external providers (payment, notification, storage)

## Recon checklist

1. Enumerate all state-changing endpoints and parameters via OpenAPI, JS, or proxy logs.
2. Identify all fields controlling workflow state, ownership, or privilege (e.g., status, role, approval).
3. Map all resource identifiers and test for predictability or IDOR potential.
4. Review client-side JS for business rules not enforced server-side (limits, eligibility, quotas).
5. Check for batch or bulk operation endpoints and their parameterization.
6. Identify integrations with external systems (payment, SSO, notifications, storage).
7. Review invitation, onboarding, or access grant flows for token reuse or replay.
8. Analyze race condition potential by searching for non-atomic multi-step flows.

## Hunt methodology

1. Intercept and modify state transition requests (e.g., approval, activation, ownership) to unauthorized or edge-case values.
2. Manipulate resource identifiers in API requests to target resources not owned by the current user.
3. Remove, duplicate, or reorder client-enforced limits in request payloads (e.g., item counts, modifiers, discount codes).
4. Replay or parallelize sensitive actions (e.g., redemption, transfer, approval) to test for race conditions.
5. Attempt to reuse or share invitation/access tokens across multiple accounts or sessions.
6. Fuzz integration endpoints with crafted or reordered parameters to test for signature or logic bypass.
7. Claim or register unowned resources (domains, buckets, packages) referenced in the application.
8. Chain business logic flaws with technical vulnerabilities (e.g., IDOR + privilege escalation) to maximize impact.

## Payload library

### Unauthorized State Transition
**Technique**: Bypass workflow or approval steps by directly setting privileged or final states in API requests.
**How to apply**: Intercept a PATCH/PUT/POST to a workflow endpoint and set `{status}` or `{approval}` fields to privileged values (e.g., "APPROVED", "ACTIVE", "OWNER").
**Payload**:
```
PATCH /api/endpoint/{resource_id}
Content-Type: application/json

{"status":"ACTIVE","approval":"APPROVED"}
```
**Observe**: Resource transitions to privileged state without required review or payment.
**Seen in**: Ad approval flows, campaign activation, user role assignment.

### Resource Ownership Manipulation
**Technique**: Assign or transfer ownership of a resource to another user without authorization.
**How to apply**: Modify `{owner_id}` or similar fields in resource update requests to a target user ID.
**Payload**:
```
POST /api/endpoint/{resource_id}/transfer
Content-Type: application/json

{"owner_id":"{target_user_id}"}
```
**Observe**: Resource is reassigned, or actions are performed as the target user.
**Seen in**: CI/CD job runners, group/project ownership, file or asset assignment.

### Race Condition Exploitation
**Technique**: Simultaneously submit multiple requests to bypass limits or redeem benefits multiple times.
**How to apply**: Use Turbo Intruder or similar to send concurrent requests to endpoints handling redemption, transfer, or creation.
**Payload**:
```
POST /api/endpoint/redeem
Content-Type: application/json

{"discount_id":"{discount_id}"}
```
**Observe**: Multiple redemptions or resource creation beyond intended limits.
**Seen in**: Discount redemption, credit transfer, resource creation (locations, invites).

### Client-side Limit Bypass
**Technique**: Exceed client-enforced limits by modifying request payloads.
**How to apply**: Add extra items, modifiers, or options in the request body beyond UI-allowed values.
**Payload**:
```
POST /api/endpoint/order
Content-Type: application/json

{"items":[{"id":"{item_id}","modifiers":["{mod1}","{mod2}","{mod3}"]}]}
```
**Observe**: Order or resource is accepted with more options than allowed.
**Seen in**: E-commerce item selection, food ordering, booking flows.

### Invitation/Token Replay
**Technique**: Reuse or share invitation/access tokens to onboard multiple users or gain repeated access.
**How to apply**: Use the same `{invite_token}` or `{access_link}` across multiple accounts or sessions.
**Payload**:
```
GET /api/endpoint/join?token={invite_token}
```
**Observe**: Multiple users gain access or repeated onboarding is possible.
**Seen in**: Private program invitations, team onboarding, access grant flows.

### External Integration Parameter Smuggling
**Technique**: Inject or reorder parameters in requests to external providers to manipulate transaction values.
**How to apply**: Craft parameters (e.g., `{amount}`, `{email}`) to create ambiguous or concatenated values, bypassing signature or validation.
**Payload**:
```
POST /api/endpoint/payment
Content-Type: application/x-www-form-urlencoded

MerchantID={id}&Amount2=000&CustomerEmail=brix&amount=100&ab=c%40{domain}
```
**Observe**: Transaction processed with manipulated amount or recipient.
**Seen in**: Payment provider integrations, wallet top-ups, checkout flows.

### Resource Claim/Hijack
**Technique**: Register or claim unowned resources (domains, buckets, packages) referenced by the application.
**How to apply**: Identify unclaimed resource references and register them with the external provider.
**Payload**: N/A (out-of-band action)
**Observe**: Ability to serve content, intercept data, or escalate via claimed resource.
**Seen in**: Subdomain takeovers, package registry links, custom domain features.

## Filter & WAF bypass

- Use alternate parameter names or order to bypass naive server-side checks (e.g., `Amount2=000` + `amount=100`).
- Exploit case sensitivity or Unicode homoglyphs in parameter names.
- Leverage chunked encoding or multi-part requests to race or split logic.
- Use null bytes or unexpected delimiters in resource identifiers.
- For race conditions, use high-concurrency tools (Turbo Intruder, custom scripts) to maximize timing windows.

## Verification & impact

- **Confirmed vulnerable**: State change or resource assignment occurs without intended preconditions (e.g., approval, payment, ownership).
- **False positive signals**: UI changes without backend effect, error messages, or temporary state that reverts.
- **Impact escalation**: Chain with IDOR, privilege escalation, or technical flaws to achieve account takeover, financial theft, or mass data access.

## Triage & severity

- Typical CVSS: Medium to Critical (4.0–10.0), depending on privilege and asset sensitivity.
- Severity increases with: unauthenticated exploitation, financial or privilege impact, mass resource access, or ability to chain with other bugs.
- Severity decreases with: limited scope (single user), sandboxed or test environments, or strong compensating controls.

## Reporting tips

- Strong PoC: Step-by-step reproduction with clear before/after state, showing unauthorized action or bypass.
- Avoid: Reports based only on UI changes, missing backend effect, or speculative impact.
- Evidence checklist: Full request/response pairs, screenshots or video of state change, account roles used, and impact statement quantifying business risk.

## Real examples

- 894569 — gitlab: Attacker can run pipeline jobs as arbitrary user, gaining access to private repos via CI token (critical, $12000)
- 1295844 — valve: Manipulated payment provider request to generate wallet balance by smuggling parameters (critical, $7500)
- 1543159 — reddit: Changed ad status to active/approved via API, bypassing payment and review (high, $5000)
- 1849626 — stripe: Fee discounts could be redeemed multiple times, resulting in unlimited fee-free transactions (medium, $5000)
- 334205 — security: Automated harvesting of private invites via leave program and email forwarding logic (medium, $2500)
- 1565623 — ibb: curl removes wrong file on error, leading to data loss (medium, $2400)
- 1565624 — ibb: curl reuses TLS/SSH connections with wrong security context, risking credential leakage (medium, $2400)
- 1614331 — ibb: curl fails to preserve file permissions, leaking sensitive data (medium, $2400)
- 1912778 — ibb: curl reuses FTP connections with wrong credentials, risking data access (medium, $2400)
- 2588329 — indrive: Phone number change accepted any OTP, enabling account takeover (critical, $2000)
- 263760 — x: Cached search widget leaks private/deleted tweets via callback manipulation (medium, $1120)
- 226199 — security: Multiple logic flaws allowed attacker to change victim's JIRA integration settings (medium, $1000)
- 462503 — gitlab: Claimed package names in auto-linking feature, enabling malicious package install (low, $1000)
- 312118 — gitlab: Logic flaw in custom domain assignment allowed mass domain hijacking (high, $750)

## Bounty intelligence

Payouts range from $300 for low-impact or niche logic bugs to $12,000+ for critical business process breaks (e.g., privilege escalation, financial theft, mass data access). SaaS, fintech, and developer platform programs pay the most for logic flaws, especially where financial or privilege impact is demonstrated. Reports with clear, reproducible impact and evidence of real-world abuse potential are most likely to receive top-tier bounties.