---
category: xss
label: XSS
report_count: 40
programs: [gitlab, shopify, reddit, valve, basecamp, upserve, ibb, security]
avg_bounty: 5700
max_bounty: 16000
severity_distribution: critical: 2, high: 22, medium: 13, low: 0

---

## Overview

XSS breaks the core browser security invariant: untrusted input must never execute as code in the victim's browser context. Developers repeatedly introduce XSS through unsafe templating, incomplete sanitization, and trusting user-controlled data in dynamic content. Worst-case, XSS enables full account takeover, credential theft, arbitrary actions as the victim, and in some cases, remote code execution or privilege escalation.

## Root causes

- Direct interpolation of user input into HTML, JS, or attribute contexts without proper escaping.
- Incomplete or misapplied sanitization libraries (e.g., allowing dangerous tags/attributes, or failing to update sanitization logic for new browser features).
- Unsafe handling of user-controlled URLs, especially in href/src attributes or redirect parameters.
- Trusting third-party integrations or external API responses without re-sanitizing their content.
- Client-side rendering with frameworks that allow bypassing of built-in protections (e.g., React's dangerouslySetInnerHTML, Vue's v-html).
- Insufficient validation of file uploads (SVG, images) or rich text content (Markdown, WYSIWYG editors).

## Attack surface

- Any user-editable field rendered as HTML: comments, descriptions, profile fields, custom labels, etc.
- Rich text editors (Markdown, WYSIWYG, HTML editors) and their preview/render flows.
- File upload endpoints accepting SVG, HTML, or other browser-interpreted formats.
- URL parameters reflected in HTML, JS, or attribute contexts (e.g., search, redirect, callback, or preview endpoints).
- API integrations that render third-party data (e.g., external issue trackers, webhooks, federated content).
- Dynamic attribute injection in templates (e.g., data-*, aria-*, on* event handlers).
- Client-side code using innerHTML, document.write, or DOM sinks with user data.
- Features supporting custom emojis, diagrams (Mermaid, Kroki), or embedded media.
- PostMessage handlers or cross-window communication without strict origin and data validation.
- Frameworks/libraries with known sanitizer bypasses (e.g., Rails::Html::Sanitizer, ActionText, Trix, Markdown parsers).

## Recon checklist

1. Enumerate all user-editable fields and content types (text, HTML, files, URLs).
2. Map all endpoints that reflect input in responses (search, preview, error, redirect, etc.).
3. Identify all places where third-party or federated data is rendered (integrations, webhooks, external APIs).
4. Review client-side code for DOM sinks (innerHTML, outerHTML, insertAdjacentHTML, eval, setAttribute, etc.).
5. Inspect CSP headers and sanitizer configurations for gaps (allowed tags, attributes, unsafe directives).
6. Analyze file upload flows for SVG, HTML, or other active content types.
7. Review JS source for postMessage handlers, especially those lacking strict origin checks.
8. Check for legacy or fallback rendering paths (e.g., Markdown, WYSIWYG, fallback templates).

## Hunt methodology

1. Submit payloads in all user-editable fields, focusing on HTML/JS context escapes and event handlers.
2. Upload SVG or HTML files with embedded scripts or event handlers to file upload endpoints.
3. Intercept API requests to third-party integrations; inject XSS payloads in fields rendered by the app.
4. Manipulate URL parameters (query, fragment, path) to test for reflected XSS in responses.
5. Test rich text editors and Markdown rendering for filter bypasses (e.g., malformed tags, attribute injection).
6. Send crafted postMessage events to windows/frames; test for DOM XSS via message handlers.
7. Probe for CSP bypasses using <base>, <iframe srcdoc>, or external script inclusion.
8. Chain XSS with privilege escalation: attempt to steal tokens, perform actions as the victim, or escalate to RCE.

## Payload library

### Basic HTML/JS Injection
**Technique**: Injects script or event handler payloads into fields rendered as HTML or attributes.
**How to apply**: Submit payloads in {param} fields, file names, or any user-controlled input rendered in the DOM.
**Payload**: 
```
"><img src=x onerror=alert(1)>
<script>alert(document.domain)</script>
<svg/onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```
**Observe**: Alert box, JS execution, or DOM modification when viewing the rendered content.
**Seen in**: Rich text editors, profile fields, project/issue descriptions, approval rule names.

### Attribute Injection / Context Escape
**Technique**: Breaks out of attribute context to inject new attributes or tags.
**How to apply**: Inject payloads containing quotes or angle brackets into fields reflected inside HTML attributes.
**Payload**:
```
" onmouseover=alert(1) x="
' onerror=alert(1) '
"><svg/onload=alert(1)>
```
**Observe**: Execution of JS when hovering/clicking, or new elements/attributes in the DOM.
**Seen in**: Filename fields, custom emoji URLs, diagram type attributes, data-* attributes.

### JavaScript URI Injection
**Technique**: Injects javascript: URLs into href/src attributes or redirect parameters.
**How to apply**: Submit `javascript:alert(1)` as the value for any URL, redirect, or link field.
**Payload**:
```
javascript:alert(1)
```
**Observe**: Clicking the link or following the redirect executes JS.
**Seen in**: Redirect parameters, external integration URLs, breadcrumb links.

### SVG/Embedded File XSS
**Technique**: Uploads SVG or other files containing script/event handler payloads.
**How to apply**: Upload a file with embedded `<script>`, event handlers, or XML entities as {file}.
**Payload**:
```xml
<svg onload="alert(1)">
<svg><script>alert(1)</script></svg>
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>
```
**Observe**: Script execution when the file is viewed or previewed.
**Seen in**: File upload features, custom emoji, app icons, rich text image embeds.

### Markdown/WYSIWYG Filter Bypass
**Technique**: Exploits parser quirks or incomplete sanitization in Markdown/WYSIWYG rendering.
**How to apply**: Submit malformed or nested tags, or abuse allowed tags/attributes in {param}.
**Payload**:
```
<pre data-sourcepos='" href="x" onmouseover="alert(1)'></pre>
</http:<marquee>hello
<gl-emoji data-name='" onload="alert(1)"' data-unicode-version="x"></gl-emoji>
```
**Observe**: HTML/JS injection in rendered Markdown/WYSIWYG content.
**Seen in**: Issue comments, notes, wiki pages, diagram blocks.

### Prototype Pollution / JS Object Injection
**Technique**: Injects __proto__ or constructor properties to pollute global objects, leading to XSS or DoS.
**How to apply**: Submit JSON or directive payloads with `__proto__` keys in diagram or config fields.
**Payload**:
```
%%{init: { '__proto__': {'template': '<iframe srcdoc="<script>alert(1)</script>"></iframe>'} }}%%
```
**Observe**: XSS or application breakage after user interaction or on page load.
**Seen in**: Diagram rendering features (Mermaid, Kroki), config objects.

### DOM-based XSS via postMessage
**Technique**: Sends crafted postMessage events to windows/frames with payloads that reach DOM sinks.
**How to apply**: Use `window.postMessage({type: {value}, payload: {payload}}, "*")` from any origin, targeting windows listening for messages.
**Payload**:
```js
window.postMessage({type: "change", payload: {title: "<img src=x onerror=alert(1)>"}}, "*")
```
**Observe**: XSS triggered in the target window/frame.
**Seen in**: Digital wallet dialogs, login pages, embedded widgets.

## Filter & WAF bypass

- Use alternate encodings: `&#x3C;script&#x3E;`, `\u003Cscript\u003E`, or base64-encoded SVGs.
- Exploit allowed but dangerous tags: `<svg>`, `<math>`, `<style>`, `<base>`, `<iframe>`.
- Abuse attribute injection: inject quotes to break out of attributes, e.g., `'" onerror=alert(1) x="`.
- Use event handler attributes (`onerror`, `onload`, `onclick`) on allowed tags.
- Leverage <base> tag to change the base URI and load attacker-controlled scripts.
- Use malformed or nested tags to confuse parsers (e.g., `<select<style/>W<xmp<script>alert(1)</script>`).
- For CSP bypass: use `<iframe srcdoc>`, `<base>`, or exploit nonce leakage in script tags.

## Verification & impact

- **Confirmed vulnerable**: JS executes in the victim's browser (alert, token exfil, DOM change), or attacker-controlled HTML is rendered.
- **False positive signals**: Payload appears as text, is HTML-encoded, or triggers only in preview but not in final render; CSP blocks execution (but content is still injected).
- **Impact escalation**: Use XSS to steal session tokens, perform actions as the victim, escalate to admin via social engineering, or chain with CSRF/RCE primitives.

## Triage & severity

- **Typical CVSS**: High (7.1–8.8) for authenticated or persistent XSS, Critical (9.0+) if pre-auth or leads to full account compromise; Medium (4.3–6.5) for reflected or sandboxed cases.
- **Severity up**: No authentication required, affects admin/moderator panels, leads to token theft or privilege escalation, CSP bypassed, or impacts multiple users.
- **Severity down**: Requires user interaction (e.g., clicking), limited to self, blocked by CSP, or only affects non-sensitive features.

## Reporting tips

- Strong PoC: Minimal payload that triggers JS execution, with clear reproduction steps and screenshots/video.
- Avoid: Reports where payload is only reflected as text, or where CSP blocks all exploitation and no impact is possible.
- Evidence checklist: 
  - Exact payload and where it was injected
  - Screenshots/video of execution
  - Full request/response pairs
  - Impact statement (what attacker can do)
  - Any CSP or filter bypasses used

## Real examples

- 1212067 — gitlab: Markdown design reference filter allowed attribute injection in links, chained with ReferenceRedactor for arbitrary HTML (critical, $16000)
- 1542510 — gitlab: ZenTao integration rendered unsanitized API data, enabling XSS via crafted API responses (high, $13950)
- 1481207 — gitlab: Markdown syntax_highlight_filter allowed <base> tag injection, enabling CSP bypass and script execution (high, $13950)
- 1578400 — gitlab: Customer Relations quick commands rendered unescaped contact names, leading to stored XSS (high, $13950)
- 1731349 — gitlab: Kroki diagram rendering allowed attribute injection in <img> tags via crafted lang attributes (high, $13950)
- 1444682 — shopify: Old Swagger-UI exposed, allowing configUrl parameter XSS and account takeover (medium, $9400)
- 409850 — valve: BBCode [url] tag in chat client allowed javascript: URI XSS, persistent across sessions (critical, $7500)
- 1147433 — shopify: Rich text editor allowed direct HTML injection in product/collection descriptions (medium, $5300)
- 1276742 — shopify: Data URL SVGs in rich text editors led to stored XSS when viewed directly (medium, $5300)
- 1962645 — reddit: Redirect parameter accepted javascript: URLs, leading to post-login XSS (high, $5000)
- 1549206 — reddit: Reflected XSS in search parameter, triggered on mouseover (high, $5000)
- 232174 — shopify: SVG icon upload with XML entity bypassed whitelist, leading to XSS in admin panels (high, $5000)
- 299728 — security: Markdown parser quirk allowed tag/attribute injection via malformed input (high, $5000)
- 836649 — gitlab: ReferenceRedactor allowed arbitrary HTML injection via data-original attribute (high, $5000)
- 982291 — basecamp: HTML sanitizer bypass in email rendering allowed arbitrary HTML and JS execution (critical, $5000)
- 1930763 — reddit: RichText parser failed to sanitize links in scheduled posts, leading to stored XSS (high, $5000)
- 508184 — gitlab: Project import logic allowed direct injection of XSS payloads in Note objects (high, $4500)
- 946728 — gitlab: SafeParamsHelper failed to filter dangerous keys, enabling XSS via script_name/domain (high, $4000)
- 1410459 — shopify: Reflected XSS in Github integration setup flow via installation_id parameter (medium, $3500)
- 723307 — gitlab: Merge request branch name rendered unsanitized, enabling stored XSS (high, $3500)
- 231053 — shopify: Digital wallet dialog accepted postMessage with structured clone, bypassing escaping for DOM XSS (DOM, $3000)
- 299424 — shopify: SVG upload with malformed content bypassed filters, leading to stored XSS (high, $3000)
- 856554 — gitlab: CI/CD job page rendered unescaped namespace from YAML, leading to stored XSS (high, $3000)
- 856836 — gitlab: PyPi package metadata rendered unsanitized, enabling stored XSS in package listings (medium, $3000)
- 948929 — shopify: Staff name field allowed blind stored XSS in admin settings (high, $3000)
- 1103258 — gitlab: Mermaid diagram fontFamily directive allowed style injection and XSS (high, $3000)
- 1280002 — gitlab: Mermaid prototype pollution enabled stored XSS via template attribute (high, $3000)
- 1342009 — gitlab: Approval rule name rendered unsanitized in merge request creation, CSP bypass via iframe/srcdoc (high, $3000)
- 1398305 — gitlab: SyntaxHighlightFilter and gl-emoji allowed stored XSS in issue comments (high, $3000)
- 1472471 — shopify: Shopify Email branding field allowed stored XSS in email templates (medium, $2900)
- 2542806 — ibb: ActionText ContentAttachment in Rails allowed unsanitized HTML in Trix editor (medium, $2600)
- 647130 — gitlab: Group name field allowed stored XSS, triggered on new project creation (high, $2500)
- 603764 — upserve: DOM-based XSS via postMessage with incomplete origin validation (high, $2500)
- 449351 — security: Asset identifier field allowed stored XSS, triggered in multiple views (medium, $2500)
- 1599573 — ibb: Rails::Html::SafeListSanitizer allowed <style> and <select> tag XSS in certain configs (medium, $2400)

## Bounty intelligence

High-impact XSS (stored, pre-auth, or CSP-bypassing) regularly earns $5,000–$16,000, especially on platforms with sensitive user data or admin panels. SaaS platforms, developer tools, and e-commerce admin interfaces pay most for XSS that enables account takeover or privilege escalation. Reports with clear CSP bypass, multi-user impact, or novel filter bypasses are more likely to receive top-tier payouts and bounty multipliers. Reflected or low-impact XSS (e.g., requiring user interaction or blocked by CSP) typically earns $2,000–$3,500.