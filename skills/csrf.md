---
category: csrf
label: CSRF
report_count: 282
programs: [gitlab, security, shopify, pixiv, magic-bbp, mozilla, discourse, cs_money, bumble, x, nextcloud, kubernetes]
avg_bounty: 700
max_bounty: 4660
severity_distribution: critical: 0, high: 7, medium: 19, low: 14
---

## Overview

CSRF breaks the trust boundary between user intent and authenticated actions by allowing attackers to force state-changing requests from a victim’s browser. Developers repeatedly introduce CSRF by relying on weak or misapplied anti-CSRF controls, trusting browser defaults, or omitting protections on non-traditional endpoints (APIs, mobile, OAuth, deep links). The worst-case impact is full account takeover, data exfiltration, or arbitrary actions performed as the victim, often with no user interaction.

## Root causes

- Relying solely on SameSite cookies or Referer/Origin checks, which are bypassable in many real-world scenarios.
- Missing or improperly validated CSRF tokens on sensitive endpoints, especially APIs, OAuth flows, and mobile deep links.
- Accepting state-changing requests via GET or other “simple” methods.
- Inconsistent enforcement of Content-Type or CORS policies, allowing cross-origin requests to succeed.
- Weak token generation (predictable, not per-session/user, or not tied to the session).
- Trusting third-party integrations (OAuth, SAML, webhooks) to handle CSRF, or leaking state/nonce values.

## Attack surface

- State-changing HTTP endpoints accepting POST, PUT, PATCH, DELETE, or even GET without robust CSRF protection.
- API endpoints (REST, GraphQL) that lack CSRF tokens or accept “simple” cross-origin requests.
- OAuth, SAML, OIDC, and other federated login/integration flows, especially those using GET or missing state validation.
- Mobile and desktop app deep links that trigger actions without user confirmation.
- Endpoints accepting non-standard Content-Types (e.g., text/plain, application/x-www-form-urlencoded) or not enforcing CORS preflight.
- Features like password/email change, account linking, API key generation, file upload, and integration setup.
- Frameworks where CSRF protection is opt-in or can be bypassed (e.g., custom middleware, legacy routes, or development tools).

## Recon checklist

1. Enumerate all endpoints that change state (CRUD actions, settings, integrations, etc.).
2. Identify which endpoints accept GET for state changes or allow non-idempotent actions.
3. Inspect forms and API docs for presence and handling of CSRF tokens (hidden fields, headers, cookies).
4. Analyze JavaScript and mobile app code for deep links, custom schemes, or API calls lacking CSRF.
5. Check for inconsistent Content-Type handling or CORS headers on sensitive endpoints.
6. Review OAuth/SAML/OIDC flows for state parameter usage and validation.
7. Test for token reuse, predictability, or cross-user applicability.
8. Map out third-party integrations and their callback/redirect handling.

## Hunt methodology

1. Identify state-changing endpoints and enumerate all HTTP methods they accept.
2. Attempt to perform actions via GET and POST without a CSRF token or with a manipulated token.
3. Test if endpoints accept requests with Content-Type: text/plain or application/x-www-form-urlencoded.
4. Craft cross-origin requests (form POST, fetch, XHR) and observe if cookies are sent and actions succeed.
5. For OAuth/SAML/OIDC, manipulate or omit the state parameter and observe callback handling.
6. Test mobile/desktop deep links and custom schemes for automatic action execution.
7. Attempt to reuse CSRF tokens across sessions or users; check for token predictability.
8. Chain with other bugs (open redirect, XSS, CORS misconfig) to escalate impact.

## Payload library

### Simple Cross-Origin Form Submission
**Technique**: Exploits endpoints that lack CSRF tokens and accept browser-sent cookies.
**How to apply**: Create an HTML form targeting the sensitive endpoint, set method to POST or GET, and include required parameters as hidden fields.
**Payload**:
```html
<form action="https://{target}/api/endpoint" method="POST">
  <input type="hidden" name="{param}" value="{value}">
  <input type="submit">
</form>
<script>document.forms[0].submit()</script>
```
**Observe**: Action is performed as the victim (e.g., settings changed, resource created).
**Seen in**: Account/email change forms, API key regeneration, file uploads.

### Content-Type and CORS Bypass
**Technique**: Sends requests with Content-Type: text/plain or application/x-www-form-urlencoded to bypass CORS preflight and trigger state changes.
**How to apply**: Use fetch/XHR or a form with enctype set to text/plain; target endpoints that do not enforce strict Content-Type or CORS.
**Payload**:
```javascript
fetch('https://{target}/api/endpoint', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: '{ "param": "{value}" }'
})
```
**Observe**: State change occurs without preflight; action is performed.
**Seen in**: Internal admin APIs, Kubernetes dashboards, developer tools.

### GET-Based State Changes
**Technique**: Leverages endpoints that perform sensitive actions via GET requests.
**How to apply**: Embed an <img> or <iframe> tag, or use a hyperlink to trigger the GET request.
**Payload**:
```html
<img src="https://{target}/api/endpoint?param={value}">
```
**Observe**: State change or side effect (e.g., resource added, integration connected).
**Seen in**: OAuth/SAML flows, integration setup, notification subscriptions.

### OAuth/SAML/OIDC State Parameter Manipulation
**Technique**: Manipulates or omits the state parameter to bypass CSRF protection in federated login/integration flows.
**How to apply**: Initiate an OAuth/SAML/OIDC flow with a crafted or missing state value, or inject null bytes/unicode to bypass validation.
**Payload**:
```
https://{target}/auth/callback?code={code}&state={attacker_state}%00
```
**Observe**: Victim account linked to attacker’s third-party account or session hijack.
**Seen in**: OAuth login, SSO integrations, account linking.

### Deep Link/Custom Scheme CSRF
**Technique**: Triggers actions in mobile/desktop apps via crafted deep links or custom schemes.
**How to apply**: Create a link or QR code using the app’s custom scheme and action parameters.
**Payload**:
```html
<a href="{app-scheme}://action/{id}/do">Trigger Action</a>
```
**Observe**: App performs the action automatically (e.g., follow, unlock, install).
**Seen in**: Mobile follow actions, lens unlocks, app-specific integrations.

### Path/Extension Manipulation
**Technique**: Bypasses CSRF protection by altering endpoint paths or file extensions.
**How to apply**: Remove or change file extensions in endpoint URLs to evade token checks.
**Payload**:
```
POST /api/endpoint/{id}
```
**Observe**: Action succeeds without CSRF token.
**Seen in**: REST APIs with extension-based routing.

### Token Reuse or Predictability
**Technique**: Exploits CSRF tokens that are not unique per session/user or are predictable.
**How to apply**: Reuse a known token from one session/user in another, or brute-force predictable tokens.
**Payload**:
```
csrfmiddlewaretoken={known_token}
```
**Observe**: Action succeeds for multiple users or sessions.
**Seen in**: Django, Rails, custom token implementations.

### Cross-Site Script Inclusion (XSSI)
**Technique**: Reads sensitive JSON responses via <script> tags or Flash, bypassing CORS.
**How to apply**: Include the endpoint as a <script> src or via Flash, then parse the response.
**Payload**:
```html
<script src="https://{target}/api/endpoint?param={value}"></script>
```
**Observe**: Sensitive data is accessible in attacker-controlled context.
**Seen in**: JSON API endpoints, real-time auth tokens.

## Filter & WAF bypass

- Use Content-Type: text/plain or application/x-www-form-urlencoded to avoid triggering CORS preflight.
- Encode path traversal as %2e%2e%2f or use unicode variants to bypass path filters.
- Insert null bytes (%00) or unicode in state/nonce parameters to bypass strict equality checks.
- Manipulate Referer/Origin headers using browser quirks (e.g., Safari’s handling of `{`/`}` in hostnames).
- Omit or randomize CSRF token parameters if the backend does not enforce strict validation.
- Use alternate HTTP methods (e.g., GET for actions expected to be POST).
- Leverage browser-specific behaviors (e.g., Safari’s relaxed CORS, legacy Flash crossdomain.xml).

## Verification & impact

- **Confirmed vulnerable**: State-changing action is performed as the victim without their intent (e.g., account takeover, data modification, integration enabled).
- **False positive signals**: Action appears to succeed but is not reflected in the victim’s account; token is required but not validated; CORS or browser restrictions block the request.
- **Impact escalation**: Chain with open redirect, XSS, or OAuth misconfig to achieve account takeover, data exfiltration, or privilege escalation.

## Triage & severity

- **Typical CVSS**: 4.3–8.8 (medium to high), depending on action sensitivity.
- **Severity up**: Unauthenticated exploitation, account takeover, sensitive data exposure, privilege escalation, or affecting admin-level actions.
- **Severity down**: Requires user interaction, affects only non-critical actions, or mitigated by additional controls (e.g., SameSite=Strict, 2FA).

## Reporting tips

- Provide a minimal PoC (HTML/JS) that triggers the action as the victim.
- Include clear before/after evidence (screenshots, video, or logs) showing the state change.
- State the exact impact (e.g., account takeover, data loss, integration hijack).
- Avoid reports where the action requires user confirmation or is protected by browser restrictions.
- Checklist: endpoint, method, parameters, PoC code, observed effect, and why existing protections are insufficient.

## Real examples

- 2326194 — ibb: CSRF on internal API allowed attacker to create admin pods on Kubernetes via Argo CD, leading to cluster compromise (high, $4660)
- 1122408 — gitlab: CSRF on GraphQL endpoint allowed mutations via GET, bypassing token checks (high, $3370)
- 805073 — x: CSRF in iOS app deep link allowed attacker to force follows in Periscope (low, $2940)
- 170552 — security: CSRF in OAuth integration setup enabled attacker to connect their Slack to victim’s account, leading to potential account takeover (high, $2500)
- 1923672 — gitlab: CSRF via SAML RelayState open redirect enabled theft of Bitbucket access tokens (medium, $2450)
- 994504 — shopify: CSRF token not properly validated, allowed attacker to change business info (medium, $1900)
- 583987 — x: Android app deep link CSRF enabled forced follows in Periscope (low, $1540)
- 1353103 — gitlab: CSRF in dev tool allowed drive-by arbitrary file deletion via crafted POST (medium, $750)
- 423022 — discourse: No CSRF protection on Yahoo account linking enabled account takeover (high, $512)
- 226418 — security: CSRF in report escalation to JIRA allowed attacker to steal private report details (medium, $500)

## Bounty intelligence

Payouts for CSRF range from $100–$5,000, with the highest rewards for account takeover, privilege escalation, or critical integrations (e.g., OAuth, admin APIs). SaaS platforms, developer tools, and cloud dashboards pay most for CSRF that leads to cross-account impact or infrastructure compromise. Reports with clear, reproducible PoCs and demonstrated business impact (especially account or infrastructure takeover) consistently earn higher bounties and faster triage.