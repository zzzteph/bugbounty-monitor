---
category: authn
label: Authentication & Session
report_count: 589
programs: [shopify, gitlab, slack, basecamp, nextcloud, kubernetes, snapchat, ibb, security, mozilla]
avg_bounty: 2100
max_bounty: 10500
severity_distribution: critical: 3, high: 13, medium: 20, low: 4
---

## Overview

Authentication and session bugs break the trust boundary between user identity and application state, allowing attackers to bypass login, escalate privileges, or hijack sessions. These flaws persist due to complex integrations (SSO, OAuth, federated identity), inconsistent validation, and subtle state management errors. Worst-case impact includes full account takeover, privilege escalation, or persistent backdoors, often with minimal user interaction.

## Root causes

- Inconsistent or missing validation of authentication/session tokens across endpoints or flows.
- Trusting user-controlled input (headers, cookies, parameters) for identity or session state.
- Weak or misconfigured integration with third-party identity providers (SSO, OAuth, federated login).
- Failure to enforce session expiration or revocation on logout, password change, or privilege changes.
- Insufficient brute-force protection or rate limiting on authentication endpoints.
- Overly permissive or misapplied access controls, especially in multi-tenant or delegated admin scenarios.

## Attack surface

- Parameters: `{token}`, `{session_id}`, `{auth_code}`, `{email}`, `{id}`, `{provider_id}`, `{redirect_uri}`, `{client_id}`, `{cookie}`.
- Headers: `Authorization`, `Cookie`, custom SSO/OAuth headers.
- Endpoint patterns: `/login`, `/logout`, `/session`, `/auth`, `/token`, `/oauth/authorize`, `/oauth/token`, `/api/session`, `/account/destroy`, `/reset`, `/verify`, `/external-login`, `/preview`, `/notifications`.
- Features: SSO integrations, OAuth flows, federated sharing, password reset, MFA/2FA, session management, account linking, public link sharing, admin/bot APIs, file providers, deep links.
- Tech stacks: Flask/Django session handling, Node.js policy enforcement, Ruby CGI cookie parsing, NGINX/OpenSSL TLS session resumption, Android/iOS deep link and content providers.
- Client-side: Deep link handlers, JS bridges exposing authentication tokens, mobile app intent filters.

## Recon checklist

1. Enumerate all endpoints handling authentication, session, and token exchange (API docs, OpenAPI, JS source, proxy logs).
2. Map all parameters and headers involved in authentication/session flows.
3. Identify all third-party integrations (SSO, OAuth, federated login, external login providers).
4. Review session and token storage mechanisms (cookies, localStorage, JWTs, device-bound tokens).
5. Analyze rate limiting and brute-force protections on login, password reset, and MFA endpoints.
6. Inspect client-side code for deep link handlers, intent filters, and JS/native bridges.
7. Check for public or unprotected preview, share, or invite links.
8. Review logout, session revocation, and privilege change flows for proper session invalidation.

## Hunt methodology

1. Probe all authentication and session endpoints with manipulated or replayed `{token}`, `{session_id}`, `{auth_code}`, and `{cookie}` values.
2. Attempt to bypass login or MFA by altering parameters (`{mode}`, `{provider_id}`, `{email}`) or switching authentication methods mid-flow.
3. Replay valid tokens or session cookies after logout, password change, or privilege downgrade to test for session fixation or insufficient expiration.
4. Test for brute-force by automating login, password reset, or MFA attempts, varying `{email}`, `{id}`, and using IP rotation if needed.
5. Manipulate OAuth/SSO flows: alter `{redirect_uri}`, `{client_id}`, `{state}`, or `{entityId}` to test for trust boundary confusion or privilege escalation.
6. Abuse public or unprotected links (preview, share, invite) to access protected resources or escalate privileges.
7. Fuzz API endpoints for privilege escalation by altering `{id}`, `{app_id}`, `{provider_id}` or omitting required authentication headers.
8. Review client-side and mobile app flows for token leakage via deep links, intent URIs, or exposed JS/native bridges.

## Payload library

### Token Replay / Session Fixation
**Technique**: Reuse or replay valid tokens or session cookies after logout, password change, or privilege downgrade to maintain access.
**How to apply**: Capture a valid `{session_id}` or `{token}` during an authenticated session. After the user logs out or changes password, replay requests using the old token/cookie.
**Payload**:  
```
GET /api/endpoint HTTP/1.1
Cookie: session={session_id}
```
**Observe**: Access to authenticated resources after supposed session invalidation.
**Seen in**: Session revocation flows, logout flows, password reset flows.

### Parameter Manipulation / Trust Boundary Confusion
**Technique**: Manipulate authentication parameters (e.g., `{entityId}`, `{mode}`, `{provider_id}`) to confuse backend logic and gain access or escalate privileges.
**How to apply**: Alter parameters in authentication or SSO/OAuth requests (e.g., append whitespace, switch modes, spoof IDs).
**Payload**:  
```
POST /api/authenticate
Content-Type: application/json

{"entityId": "{victim_entity} ", "token": "{valid_token}"}
```
**Observe**: Authentication against one entity, but access or provisioning in another.
**Seen in**: SSO integrations, federated login, MFA flows.

### OAuth/OpenID Connect Flow Abuse
**Technique**: Abuse OAuth/OIDC flows by manipulating `{redirect_uri}`, `{client_id}`, `{state}`, or bypassing consent/validation steps.
**How to apply**: Craft authorization requests with attacker-controlled `{redirect_uri}` or `{client_id}`; attempt to bypass email verification or consent screens.
**Payload**:  
```
GET /oauth/authorize?client_id={client_id}&redirect_uri={attacker_url}&response_type=code&scope={scope}
```
**Observe**: Authorization codes or tokens issued to attacker-controlled endpoints, or account takeover via unverified email.
**Seen in**: OAuth authorization flows, external login linking, group-level app setup.

### Brute-force / Rate Limit Bypass
**Technique**: Bypass or evade rate limiting on authentication endpoints to brute-force credentials or tokens.
**How to apply**: Automate requests to login or reset endpoints, varying `{email}` or `{token}`; use whitespace, alternate encodings, or IP rotation to evade detection.
**Payload**:  
```
POST /api/login
Content-Type: application/json

{"email": "{email} ", "password": "{password}"}
```
**Observe**: Successful login or token issuance after expected lockout.
**Seen in**: Login endpoints, password reset, MFA verification.

### Public/Unprotected Link Abuse
**Technique**: Access protected resources via public or unprotected preview, share, or invite links.
**How to apply**: Obtain a preview or share link (from referrer, social media, or API), access it directly or share with others.
**Payload**:  
```
GET /preview/{token}
```
**Observe**: Access to protected content without authentication.
**Seen in**: Preview links, public share links, federated shares.

### Deep Link / Intent Abuse
**Technique**: Exploit deep link or intent handlers to bypass authentication or leak tokens.
**How to apply**: Craft a deep link or intent URI targeting a protected resource or triggering token leakage.
**Payload**:  
```
adb shell am start -n {package}/{activity} -d "https://app.com/{id}/verify?proceed_to={attacker_url}"
```
**Observe**: Access to protected resources or exfiltration of authentication tokens.
**Seen in**: Mobile app deep links, JS/native bridges, preview handlers.

### Cookie Prefix/Name Spoofing
**Technique**: Exploit parsing inconsistencies or URL decoding in cookie handling to spoof security prefixes or override protected cookies.
**How to apply**: Send cookies with encoded or alternate names to bypass prefix checks.
**Payload**:  
```
Cookie: __%48ost-session={value}; __Host-session={attacker_value}
```
**Observe**: Application uses attacker-supplied cookie value.
**Seen in**: Ruby CGI cookie parsing, custom session middleware.

### TLS/Transport Layer Authentication Confusion
**Technique**: Abuse TLS session resumption or misconfigured client authentication to access resources across virtual hosts.
**How to apply**: Resume a TLS session from one host on another, or manipulate SNI/Host headers.
**Payload**:  
```
TLS session resumption with ticket from host A, connect to host B with matching SNI.
```
**Observe**: Access to resources on host B without proper authentication.
**Seen in**: NGINX/OpenSSL multi-tenant setups.

## Filter & WAF bypass

- Whitespace padding: `{email} `, `{id}\t`, `{entityId}\n`
- Alternate encodings: URL-encoded parameters (`%20`, `%09`, `%0a`), Unicode homoglyphs
- Null byte injection: `{param}\x00`
- Case manipulation: `{Token}`, `{SESSION_ID}`
- Header smuggling: duplicate headers, mixed casing (`authorization`, `Authorization`)
- Chunked encoding for POST bodies
- Cookie name encoding: `%48ost-` for `Host-`
- IP rotation or X-Forwarded-For spoofing for rate limit bypass

## Verification & impact

- **Confirmed vulnerable**: Access to protected resources, successful login, or privilege escalation without intended authentication or after session invalidation.
- **False positive signals**: Error messages without access, token reuse failing due to proper expiration, preview links requiring additional authentication.
- **Impact escalation**: Chain with XSS or CSRF for account takeover, use session/token theft for privilege escalation, abuse public links for data exfiltration, combine with logic bugs for persistent backdoors.

## Triage & severity

- **Typical CVSS**: Medium to High (6.5–8.8); Critical (9.0+) if full account takeover, privilege escalation, or persistent backdoor is possible.
- **Severity up**: Affects all users, enables account takeover, persistent access after logout/password change, impacts sensitive data or admin functions, works cross-tenant.
- **Severity down**: Requires user interaction, limited to single session, mitigated by additional controls (IP allowlist, device binding), affects non-sensitive features.

## Reporting tips

- Strong PoC: Minimal reproducible steps, showing unauthorized access or privilege escalation, with screenshots or logs.
- Avoid: Reports with only error messages, no clear impact, or requiring unrealistic attacker capabilities.
- Evidence checklist: Full request/response pairs, token/session values, screenshots of unauthorized access, description of attack chain, impact statement.

## Real examples

- 976603 — superhuman: SSO entityId whitespace confusion allowed attacker to DOS org SSO and provision users into attacker org (high, $10500)
- 265943 — snapchat: Chained SSO flaws allowed attacker to steal SSO login tokens and control victim accounts (high, $7500)
- 1372667 — basecamp: Deep link + JS bridge allowed attacker to steal bearer tokens via crafted preview_url (high, $6337)
- 1148364 — gitlab: Group-level OAuth app setup bypassed CSRF, attacker could mint access tokens for targeted users (high, $5580)
- 1170024 — nextcloud: Federated share notification handler allowed privilege escalation from read to write with only a token (high, $4000)
- 421859 — shopify: Unauthenticated preview links bypassed storefront password protection (critical, $3000)
- 1380121 — urbancompany: Weak Flask session signing enabled full compromise via session forgery (critical, $1500)
- 1464396 — ibb: Ruby CGI::Cookie.parse allowed cookie prefix spoofing via URL-decoded names (high, $2000)
- 1580493 — kubernetes: AWS IAM Authenticator accepted manipulated tokens, enabling privilege escalation (high, $2500)
- 2978267 — ibb: TLS session tickets not isolated across virtual hosts, allowing client auth bypass (medium, $2162)

## Bounty intelligence

Authentication and session bugs consistently command high payouts, especially when they enable account takeover, privilege escalation, or persistent access. SaaS, cloud, and developer platform programs pay most for these, particularly for SSO/OAuth flaws and session invalidation issues. Reports with clear, reproducible impact and minimal user interaction (e.g., token replay, privilege escalation, public link abuse) are most likely to receive top-tier bounties and, in some cases, multipliers for affecting sensitive or admin-level features.