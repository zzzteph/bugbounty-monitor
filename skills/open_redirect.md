---
category: open_redirect
label: Open Redirect
report_count: 197
programs: [ibb, x, upserve, gitlab, rails, expediagroup_bbp, gsa_bbp, clario, chaturbate, affirm]
avg_bounty: 500
max_bounty: 2400
severity_distribution: critical: 0, high: 3, medium: 8, low: 22
---

## Overview
Open Redirects break the invariant that only trusted URLs are used for server-initiated redirects, allowing attackers to steer users to arbitrary destinations. Developers frequently introduce these bugs by trusting user-supplied input in redirect logic or by implementing incomplete validation. The worst-case impact includes phishing, credential theft, OAuth token leakage, and privilege escalation via token or session hijacking.

## Root causes
- Direct use of user-controlled parameters in redirect destinations without strict allowlisting.
- Incomplete or naive validation (e.g., only checking for "http://" or "https://", or failing to handle protocol-relative URLs).
- Framework helpers (e.g., `redirect_to` in Rails) misused with untrusted input.
- Incorrect parsing or normalization of URLs, especially with encoded characters or alternate URL forms.
- Overreliance on client-side validation or UI warnings instead of enforcing server-side checks.
- Misinterpretation of URL-encoded or Unicode characters, leading to bypasses.

## Attack surface
- Query parameters like `{next}`, `{redirect_uri}`, `{return_url}`, `{url}`, `{rurl}`, `{continue}`, `{dest}`, `{target}`, `{location}`.
- POST body fields controlling navigation or callback destinations.
- URL path segments that are interpreted as redirect targets (e.g., `/http://{host}/`).
- OAuth and SSO flows, especially `redirect_uri` and `state` parameters.
- Logout, login, password reset, and invitation flows that redirect after action.
- Features that generate links in emails or notifications based on user input.
- JavaScript code using `window.location`, `window.location.replace`, or `window.open` with untrusted data.
- Tech stacks: Ruby on Rails (pre-7.0.4.1), Node.js/Express apps, legacy PHP, and any custom URL handling logic.
- Client-side: JS that decodes and redirects based on URL parameters, or iframes without sandboxing.

## Recon checklist
1. Enumerate all endpoints accepting navigation or callback parameters via query, body, or path.
2. Identify OAuth, SSO, and federated login flows and their parameters.
3. Review JavaScript bundles for client-side redirect logic using `window.location` or similar.
4. Map all email, invite, and notification templates for user-controlled links.
5. Check for URL shortener or dynamic link features.
6. Inspect for protocol-relative URLs, double slashes, and encoded/Unicode variants in parameters.
7. Review server-side code for use of redirect helpers/functions with untrusted input.
8. Test for presence of link warning or allowlist logic and its bypassability.

## Hunt methodology
1. Send requests to endpoints with navigation parameters, supplying absolute URLs (`http://{host}`) as values.
2. Test protocol-relative URLs (`//{host}`) and alternate encodings (`%2f%2f{host}`) in parameters and paths.
3. Attempt open redirects via path-based tricks (e.g., `/{scheme}://{host}/`).
4. Supply payloads with alternate protocols (`javascript:`, `data:`, `ftp:`) to test for XSS or non-HTTP redirects.
5. Manipulate OAuth/SSO flows by setting `redirect_uri` or similar to attacker-controlled URLs.
6. Use Unicode and right-to-left override characters to obfuscate redirect destinations.
7. For client-side redirects, supply base64-encoded or obfuscated URLs if decoding is present.
8. Observe responses for `Location` headers, meta refresh tags, or JS-based navigation, confirming external redirection.

## Payload library

### Absolute URL parameter injection
**Technique**: Directly supplying an absolute URL in a navigation parameter to trigger a redirect.
**How to apply**: Set `{param}` (e.g., `next`, `redirect_uri`, `return_url`) to `http://{host}` in a request to any endpoint that accepts navigation parameters.
**Payload**: `?{param}=http://attacker.com`
**Observe**: Response issues a 3xx redirect or navigates to the attacker-controlled domain.
**Seen in**: OAuth callback flows on SaaS apps, login/logout flows on consumer platforms, password reset confirmation handlers.

### Protocol-relative and encoded URL bypass
**Technique**: Using protocol-relative URLs (`//{host}`) or encoded forms (`%2f%2f{host}`) to bypass naive validation.
**How to apply**: Set `{param}` or path segment to `//attacker.com` or `%2f%2fattacker.com`.
**Payload**: `?{param}=//attacker.com` or `/%2f%2fattacker.com`
**Observe**: Redirect to `attacker.com` despite validation intended to block external domains.
**Seen in**: SSO and OAuth flows, path-based navigation handlers, legacy PHP/Node.js apps.

### Path-based open redirect
**Technique**: Supplying an absolute URL as a path segment, exploiting frameworks that interpret paths as redirect targets.
**How to apply**: Access `/http://attacker.com/` or similar on endpoints that parse path for navigation.
**Payload**: `/http://attacker.com/`
**Observe**: Server issues a redirect to the supplied external URL.
**Seen in**: RESTful route handlers, file/resource downloaders, legacy Rails/Express apps.

### Alternate protocol injection
**Technique**: Supplying non-HTTP(S) protocols (e.g., `javascript:`, `data:`, `ftp:`) to escalate to XSS or client-side attacks.
**How to apply**: Set `{param}` to `javascript:alert(1)` or `data:text/html;base64,...`.
**Payload**: `?{param}=javascript:alert(1)`
**Observe**: Browser executes JS or loads data URI, indicating XSS or client-side compromise.
**Seen in**: Login/next flows, OAuth callback handlers, client-side JS redirects.

### Unicode and RTL character obfuscation
**Technique**: Using Unicode control characters (e.g., RTLO, LTR, RLO) to disguise the true redirect destination.
**How to apply**: Insert `%E2%80%AE` or similar into `{param}` to manipulate display or parsing.
**Payload**: `?{param}=http://%E2%80%AEattacker.com`
**Observe**: Redirect occurs to attacker.com, but UI or logs may show a benign domain.
**Seen in**: Link warning pages, email link generators, social platforms.

### Base64 or encoded redirect parameter
**Technique**: Supplying a base64-encoded URL in a parameter that is decoded and used for navigation.
**How to apply**: Encode `http://attacker.com` in base64 and set as `{param}`.
**Payload**: `?{param}=aHR0cDovL2F0dGFja2VyLmNvbQ==`
**Observe**: Redirect to attacker.com after decoding, often in client-side JS.
**Seen in**: Unsupported browser warnings, email verification flows, JS-heavy apps.

### Host header injection
**Technique**: Manipulating the `Host` header to influence generated links or redirects.
**How to apply**: Send requests with `Host: attacker.com` to endpoints that reflect or use the header for redirects.
**Payload**:
```
GET / HTTP/1.1
Host: attacker.com
```
**Observe**: Links or redirects in responses point to attacker.com.
**Seen in**: Password reset flows, link generators, apps using Host for absolute URLs.

### window.opener/tabnabbing
**Technique**: Using `window.opener` or unsandboxed iframes to redirect the original tab after opening a link in a new tab.
**How to apply**: Open a link with `target="_blank"` to an attacker-controlled page containing JS to set `window.opener.location`.
**Payload**:
```html
<script>
if (window.opener) window.opener.location = 'http://attacker.com';
</script>
```
**Observe**: Original tab navigates to attacker.com after user clicks a link.
**Seen in**: Messaging/inbox UIs, notification links, unsandboxed preview iframes.

## Filter & WAF bypass
- Use double slashes (`//attacker.com`) to bypass checks for `http://` or `https://`.
- Encode slashes: `%2f%2fattacker.com` or `%252f%252fattacker.com`.
- Insert Unicode control characters (e.g., `%E2%80%AE`) to obfuscate the domain.
- Use alternate protocols (`javascript:`, `data:`, `ftp:`) if not explicitly filtered.
- Exploit path traversal (`..;/`) or userinfo (`user@host`) in URLs.
- Chain redirects through intermediate endpoints or via chained parameters.
- Use base64 or hex encoding if the app decodes before redirecting.

## Verification & impact
- **Confirmed vulnerable**: Server issues a 3xx redirect (Location header) or client-side JS navigates to an attacker-controlled domain. For OAuth, tokens or credentials are sent to the attacker.
- **False positive signals**: Redirects only to internal URLs, or external redirects are gated by explicit user warnings or allowlists.
- **Impact escalation**: Chain with OAuth flows to steal tokens, use for phishing, escalate to XSS via `javascript:` URIs, or abuse for session fixation/account takeover.

## Triage & severity
- **Typical CVSS**: Low to Medium (3.1–6.1), but can be High if tokens or credentials are exposed.
- **Severity up**: Redirect in authentication, OAuth, or sensitive flows; leaks tokens or credentials; no user warning; affects all users.
- **Severity down**: Only internal redirects, explicit user warnings, allowlist enforced, or requires user interaction with clear warning.

## Reporting tips
- Strong PoC: Minimal URL or request that triggers the redirect, with clear evidence (screenshot, video, or HTTP trace).
- Avoid: Reporting only UI-level redirects with no external navigation, or cases where allowlist/warning is present and effective.
- Evidence checklist: Vulnerable endpoint, full request/response, payload used, observed redirect, and impact statement (e.g., token leakage, phishing scenario).

## Real examples
- 1865991 — ibb: Bypass of Rails 7.0 open redirect protection via crafted URL in `redirect_to` (medium, $2400)
- 683298 — x: Open redirect via `next` parameter, also allowed `javascript:` URIs for XSS (medium, $1540)
- 469803 — upserve: Path-based open redirect using `/http://{host}/` pattern (medium, $1200)
- 1788006 — expediagroup_bbp: Open redirect via `logout` parameter, enabled phishing (medium, $1000)
- 904059 — rails: Open redirect in error handler, allowed POST-to-GET redirect to attacker (high, $1000)
- 665651 — gsa_bbp: OAuth `redirect_uri` open redirect, leaked access tokens (high, $750)
- 635597 — x: Unicode RTLO character in parameter led to redirect to disguised domain (low, $560)
- 781673 — x: Client-side error message OK button redirected to attacker site (medium, $560)
- 1145563 — security: Tabnabbing via `window.opener` in inbox links (low, $500)
- 1066410 — clario: Dynamic link shortener misconfiguration enabled open redirect (medium, $300)

## Bounty intelligence
Open Redirects typically pay $100–$1000, with higher payouts ($1000–$2400) for cases involving OAuth token leakage, authentication flows, or bypasses of existing protections. SaaS, fintech, and platforms with SSO/OAuth integrations pay most, especially when the bug enables account takeover or credential theft. Reports with clear impact (token theft, phishing, or XSS) and bypasses of prior fixes are rewarded at the top end.