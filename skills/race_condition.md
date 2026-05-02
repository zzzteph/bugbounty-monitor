---
category: race_condition
label: Race Conditions
report_count: 33
programs: [shopify, ibb, security, judgeme, weblate, stagingdoteverydotorg, stripo, mozilla, curl, kubernetes, reddit, stripe]
avg_bounty: 1700
max_bounty: 15250
severity_distribution: critical: 1, high: 3, medium: 8, low: 21
---

## Overview

Race conditions break the assumption that operations on shared resources are atomic and isolated, allowing attackers to manipulate timing and state transitions for privilege escalation, business logic abuse, or system compromise. Developers introduce these bugs by failing to synchronize access to critical sections, especially when relying on naive checks or assuming single-threaded execution. The worst-case impact ranges from full account takeover and arbitrary file manipulation to financial fraud and remote code execution.

## Root causes

- Lack of atomicity in multi-step operations (e.g., check-then-act patterns without locking)
- Missing or insufficient locking/synchronization on shared resources (DB rows, files, in-memory objects)
- Reliance on client-side or stateless validation for stateful operations
- Inadequate use of database transactions or improper transaction isolation levels
- Trusting external state (DNS, file system, remote APIs) between check and use
- Global variables or singletons accessed by multiple threads without protection

## Attack surface

- Parameters controlling resource creation, deletion, or modification (e.g., {id}, {token}, {email})
- Endpoints handling state transitions: "confirm", "redeem", "verify", "join", "add", "claim", "submit"
- Features with limits or quotas: promo codes, invitations, payment, feedback, resource allocation
- File operations: upload, download, delete, resume, or overwrite logic
- Authentication and authorization flows, especially with multi-step verification
- API endpoints that perform a check followed by an action (TOCTOU)
- Systems using global or shared objects in multi-threaded environments (e.g., caches, file descriptors)
- Tech stacks: web apps with ORM but no transaction enforcement, C/C++/Rust code with file or memory ops, cloud-native apps with distributed state, legacy code with global variables

## Recon checklist

1. Enumerate endpoints and parameters that mutate state or resources.
2. Identify features with quotas, limits, or one-time actions (e.g., redemption, invitations).
3. Review API schemas and documentation for multi-step flows (check-then-act).
4. Inspect client-side JS for hints of stateful operations or raceable actions.
5. Analyze server responses for idempotency, error handling, and duplicate detection.
6. Map out database or storage backends—look for lack of transaction boundaries.
7. Check for global/static variables or shared memory in open-source or binary code.
8. Identify external dependencies (DNS, file system, third-party APIs) used in security decisions.

## Hunt methodology

1. Select a state-changing endpoint or feature with a quota, limit, or critical action.
2. Capture the relevant request (e.g., POST to /api/endpoint with {param}).
3. Prepare a script or tool (Turbo Intruder, Race the Web, custom Python) to send N concurrent requests with identical or slightly varied parameters.
4. Launch the race, opening the "gate" to send all requests simultaneously.
5. Observe responses for multiple successes, duplicate resource creation, or inconsistent state.
6. Check for side effects: extra credits, multiple group memberships, duplicate payments, or bypassed limits.
7. For file or system-level races, orchestrate timing between check and use (e.g., swap symlinks, change files, alter DNS).
8. Document the minimal sequence and timing required to reliably trigger the race.

## Payload library

### Parallel Resource Creation
**Technique**: Exploits lack of atomicity in resource creation, allowing multiple instances or bypassing limits.
**How to apply**: Send N concurrent POST requests to a resource creation endpoint with the same or colliding {param} (e.g., {invite_token}, {promo_code}, {email}).
**Payload**:
```
POST /api/endpoint
Content-Type: application/json

{"param": "{value}"}
```
**Observe**: Multiple resources created, limit exceeded, or duplicate entries in response.
**Seen in**: Group join flows, promo code redemption, email add endpoints.

### Check-Then-Act (TOCTOU)
**Technique**: Exploits a window between validation (check) and action (use), allowing state to change in between.
**How to apply**: Trigger the "check" (e.g., stat, DNS lookup, email validation), then rapidly change the underlying resource or state before the "use" (e.g., file open, proxy, confirmation).
**Payload**:
```
# Example: File operation
1. Send stat/check request for {resource}
2. Swap {resource} (e.g., symlink, DNS, file)
3. Send action request (open/delete/confirm)
```
**Observe**: Action performed on unintended or attacker-controlled resource.
**Seen in**: File deletion/upload, DNS-based proxying, email confirmation.

### Quota/Limit Bypass
**Technique**: Races multiple requests to bypass per-user or per-resource limits.
**How to apply**: Send concurrent requests to endpoints enforcing a limit (e.g., max N emails, one-time codes).
**Payload**:
```
POST /api/endpoint
Content-Type: application/json

{"param": "{value}"}
```
**Observe**: More than allowed resources created or actions performed.
**Seen in**: Email add, promo code redemption, credential claim.

### Duplicate Payment/Reward
**Technique**: Races payment or reward confirmation endpoints to receive multiple credits or payouts.
**How to apply**: Send multiple confirmation requests for the same {transaction_id} or {token}.
**Payload**:
```
POST /api/endpoint
Content-Type: application/json

{"transaction_id": "{id}", "token": "{token}"}
```
**Observe**: Multiple payments, credits, or coins awarded for a single transaction.
**Seen in**: Payment confirmation, coin purchase, retest reward flows.

### File System/Descriptor Races
**Technique**: Exploits race between file checks and file operations (stat/open, remove/check).
**How to apply**: Orchestrate timing so that after a check (stat, is_dir), the file is swapped (symlink, rename) before the operation (open, delete).
**Payload**:
```
# Pseudocode
1. stat({filename})
2. swap {filename} with symlink or different file
3. open({filename}) or remove({filename})
```
**Observe**: Sensitive file overwritten, deleted, or accessed.
**Seen in**: File upload, cookie jar, SFTP resume, directory deletion.

### Global Variable/Data Structure Races
**Technique**: Multiple threads access or modify global/shared variables or data structures without synchronization.
**How to apply**: Trigger concurrent actions that use or modify the same global object (e.g., cache, context, file descriptor).
**Payload**:
```
# No HTTP payload; trigger via multi-threaded actions or API calls
```
**Observe**: Crashes, heap corruption, double-free, or data leakage.
**Seen in**: DNS cache, GSS-API negotiation, file descriptor handling.

## Filter & WAF bypass

- Use concurrent connections and pipelining to maximize timing window (Turbo Intruder, Race the Web).
- Vary request headers or minor parameters to avoid basic deduplication.
- For file system races, use atomic operations (renameat2, symlink swap) to ensure precise timing.
- For DNS races, use custom DNS servers with zero TTL and rapid response changes.
- For web endpoints, pipeline requests or use HTTP/2 multiplexing to increase race likelihood.

## Verification & impact

- **Confirmed vulnerable**: Multiple successful responses for a single-limited action, duplicate resource creation, limit exceeded, or unintended file/system modification.
- **False positive signals**: Duplicate requests with only one success, or errors indicating proper locking (e.g., "already exists", "limit reached").
- **Impact escalation**: Chain to account takeover (email confirmation), business logic abuse (multiple payments/credits), file overwrite (RCE or data theft), or privilege escalation (bypassing authorization checks).

## Triage & severity

- Typical CVSS: Low to Medium for business logic/DoS; High to Critical for privilege escalation, file system, or authentication bypass.
- Severity increases with: unauthenticated exploitation, financial or sensitive data impact, ability to chain to RCE or account takeover, or affecting core authentication/authorization.
- Severity decreases with: authenticated-only exploitation, limited scope (e.g., only affects own account), or presence of compensating controls (idempotency, deduplication).

## Reporting tips

- Provide a minimal, reliable reproducer (script or Turbo Intruder config) showing multiple successes.
- Include before/after state: screenshots, logs, or database entries proving impact.
- Clearly state the business/security impact (e.g., "account takeover", "multiple payments", "file overwrite").
- Avoid vague claims—demonstrate the race is not just a UI bug but affects backend state.
- Evidence checklist: request/response pairs, timing details, affected resource IDs, impact proof (e.g., extra coins, duplicate group membership).

## Real examples

- 300305 — shopify: Race in email confirmation allowed attacker to confirm arbitrary emails and take over accounts via collaborator conversion (critical, $15250)
- 1520931 — ibb: TOCTOU in Rust std::fs::remove_dir_all() enabled symlink attacks to delete arbitrary files (high, $4000)
- 3335085 — curl: TOCTOU in HTTP/2 connection reuse allowed certificate validation bypass and MITM (high, $4000)
- 2078571 — ibb: TOCTOU in curl fopen logic let attackers overwrite protected files via symlink swap (medium, $2480)
- 3432833 — curl: SFTP resume logic race allowed arbitrary file append via symlink swap (medium, $2000)
- 3645361 — curl: Data race in DNS cache caused heap corruption and double-free, potential RCE (medium, $2000)
- 801743 — reddit: Race in coin purchase verification allowed inflation of coins via repeated requests (medium, $1500)
- 994051 — stripo: Race in folder creation endpoint allowed duplicate folder creation (medium, $1000)
- 429026 — security: Retest confirmation race allowed duplicate payments to be issued (medium, $1000)
- 859962 — kubernetes: DNS-based TOCTOU in proxy filter allowed bypass of proxy restrictions (medium, $1000)

## Bounty intelligence

Race conditions see wide payout variance: logic-only or low-impact races (e.g., duplicate follows, feedback) often pay $0–$500, while those enabling privilege escalation, file system compromise, or financial fraud can reach $1,000–$15,000. SaaS, fintech, and infrastructure programs pay most for races affecting authentication, payment, or file operations. Impact clarity and reliable exploitation (not just theoretical) are key to higher rewards.