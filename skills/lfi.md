---
category: lfi
label: LFI / Path Traversal
report_count: 257
programs: [gitlab, ibb, mozilla, valve, rails, rubygems, nextcloud, deptofdefense, aiven_ltd, ui]
avg_bounty: 3500
max_bounty: 29000
severity_distribution: critical: 10, high: 13, medium: 8, low: 7
---

## Overview
LFI and path traversal bugs break the assumption that user input cannot escape intended directories or reference arbitrary files. Developers frequently mishandle path normalization, trust user-controlled filenames, or fail to sanitize archive contents, especially in import/export, file upload, and plugin systems. Worst-case impact includes arbitrary file read, file overwrite, privilege escalation, and RCE—often unauthenticated.

## Root causes
- Direct concatenation of user input into filesystem paths without canonicalization or sanitization.
- Incomplete or incorrect use of path normalization (e.g., missing checks after resolving symlinks or failing to reject `..` segments).
- Trusting archive contents (tar, zip, etc.) without validating extracted paths or following symlinks.
- Failing to validate or sanitize filenames/paths parsed from metadata (e.g., XML, JSON, or package manifests).
- Overridable or monkey-patchable path utilities in dynamic languages (e.g., Node.js `require('path')` or Buffer internals).
- Inadequate filtering of dangerous characters or encodings (e.g., URL-encoded traversal, double encoding, backslashes on Windows).

## Attack surface
- HTTP parameters or body fields controlling file paths: `{filename}`, `{path}`, `{file}`, `{resource}`, `{template}`, `{config}`
- Archive extraction endpoints: file import, backup/restore, package upload, plugin/theme install
- File upload/download handlers, especially those that process user-supplied filenames or metadata
- API endpoints accepting user-controlled paths, keys, or IDs for file operations
- Features: project/group import/export, CI/CD cache, plugin/theme management, file preview/download, markdown/image embedding, document editors
- Tech stacks: Node.js (fs, path, Buffer), Ruby (File, Tempfile, Dir), Java (File, FileOutputStream), PHP (file_get_contents, include), Python (os.path, open)
- Client-side: mobile/desktop sync clients that trust server-supplied paths or metadata

## Recon checklist
1. Enumerate all endpoints accepting file or path parameters (including hidden or undocumented APIs).
2. Identify features that process uploaded archives (tar, zip, nupkg, gem, etc.) or import/export data.
3. Review client-side code (JS, mobile, desktop) for file sync, upload, or download logic.
4. Map all parameters that influence filenames, directories, or resource references (including those parsed from metadata).
5. Analyze server-side code for use of path utilities, normalization, and symlink handling.
6. Check for dynamic language features that allow monkey-patching or overriding of path/file functions.
7. Inspect for incomplete filtering of traversal sequences (`../`, `..\\`, URL-encoded, Unicode, etc.).
8. Identify any logic that copies, moves, or rewrites files based on user input or content references.

## Hunt methodology
1. Send requests with `{param}=../../../../../../../../etc/passwd` and `{param}=..\\..\\..\\..\\..\\..\\windows\\win.ini` to all file/path parameters.
2. Test double URL encoding: `{param}=..%252f..%252f..%252fetc%252fpasswd` and mixed encoding/case.
3. Upload archives (tar/zip) containing files or symlinks with traversal paths (`../../{value}` or symlinks to `/etc/passwd`).
4. Manipulate metadata in package formats (e.g., XML/JSON fields in uploaded packages) to inject traversal sequences.
5. Attempt to overwrite or create files by supplying traversal in upload or cache key parameters.
6. For dynamic languages, attempt to override or monkey-patch path utilities if possible (e.g., via pre-auth code execution or plugin upload).
7. Probe for off-by-slash or alias misconfigurations in web server configs by requesting `/alias../{file}` or similar.
8. Observe responses for file content, error messages, or side effects (file creation, overwrite, or deletion).

## Payload library

### Classic directory traversal
**Technique**: Exploits lack of path sanitization to escape intended directories and access arbitrary files.
**How to apply**: Supply `../../../../../../../../{sensitive_file}` or `..\\..\\..\\..\\..\\..\\{sensitive_file}` in any file/path parameter or upload metadata.
**Payload**:  
```
{param}=../../../../../../../../etc/passwd
{param}=..\\..\\..\\..\\..\\..\\windows\\win.ini
```
**Observe**: Response contains file content, error, or file is created/overwritten outside intended directory.
**Seen in**: File preview/download endpoints, markdown/image embedding, file upload handlers.

### Double encoding and alternate separators
**Technique**: Bypasses naive filtering by encoding traversal sequences or using alternate path separators.
**How to apply**: Encode `../` as `%2e%2e%2f`, double-encode as `%252e%252e%252f`, or use backslashes on Windows.
**Payload**:  
```
{param}=..%2f..%2f..%2fetc%2fpasswd
{param}=..%252f..%252f..%252fetc%252fpasswd
{param}=..\\..\\..\\..\\windows\\win.ini
```
**Observe**: File content is returned or file operation occurs outside intended directory.
**Seen in**: Web servers, plugin/theme handlers, API endpoints.

### Archive extraction with traversal or symlinks
**Technique**: Places files or symlinks with traversal paths inside uploaded archives to escape extraction directory.
**How to apply**: Upload a tar/zip archive containing files named `../../{value}` or symlinks pointing to sensitive files.
**Payload**:  
Create archive with:
```
mkdir {random}
ln -s /etc/passwd {random}/passwd
tar czf archive.tar.gz {random}/../../../../../../etc/passwd
```
**Observe**: Sensitive file is extracted, read, or copied; symlink is followed.
**Seen in**: Import/export features, package upload, backup/restore.

### Metadata injection in package formats
**Technique**: Injects traversal sequences into metadata fields parsed as filenames or paths.
**How to apply**: Supply `../../{value}` in XML/JSON fields (e.g., `name`, `version`, `id`) in uploaded packages.
**Payload**:  
```
<id>../../../../target</id>
<version>../../../../target</version>
```
**Observe**: File is created or overwritten outside intended directory.
**Seen in**: Package registries, plugin/theme upload, gem/npm/nuget installers.

### Overriding or monkey-patching path utilities
**Technique**: In dynamic languages, override path normalization or Buffer internals to bypass traversal checks.
**How to apply**: Inject code to override `path.resolve`, `Buffer.prototype.utf8Write`, or similar before file operations.
**Payload**:  
```js
path.resolve = (s) => s;
Buffer.prototype.utf8Write = ((w) => function (str, ...args) {
  return w.apply(this, [str.replace(/^\/exploit/, '/tmp/..'), ...args]);
})(Buffer.prototype.utf8Write);
```
**Observe**: Path traversal succeeds despite apparent normalization.
**Seen in**: Node.js permission model, serverless functions, plugin systems.

### Off-by-slash and alias misconfiguration
**Technique**: Exploits web server alias or location misconfigurations to escape intended directories.
**How to apply**: Request `/alias../{file}` or similar, exploiting mismatched trailing slashes.
**Payload**:  
```
GET /alias../.bashrc HTTP/1.1
```
**Observe**: File outside intended directory is returned.
**Seen in**: Nginx/Apache alias/location blocks, static file handlers.

### Parameter pollution and path smuggling
**Technique**: Uses multiple parameters or encoded separators to bypass path validation.
**How to apply**: Supply multiple path parameters or separators (`%00`, `%2f`, `%5c`) to confuse backend logic.
**Payload**:  
```
{param}=file.txt%00../../../../etc/passwd
{param}=..%2f..%5c..%2fetc%2fpasswd
```
**Observe**: File operation occurs on unintended file.
**Seen in**: PHP, Java, legacy frameworks.

## Filter & WAF bypass
- Double and mixed encoding: `%252e%252e%252f`, `%c0%ae%c0%ae%c0%af`
- Unicode homoglyphs: `U+2215` (∕), `U+2044` (⁄) as alternate slashes
- Backslash vs. forward slash: `..\\..\\` on Windows, mixed separators
- Null byte injection: `%00` to truncate extensions or bypass suffixes
- Overlong UTF-8: `%c0%ae%c0%ae%c0%af`
- Appending dots or slashes: `file.txt.`, `file.txt/`
- Path parameter smuggling: multiple parameters or separators in one request

## Verification & impact
- **Confirmed vulnerable**: Sensitive file content returned, file created/overwritten outside intended directory, or RCE achieved via file write.
- **False positive signals**: Error messages without file content, 404/403 responses, or file content matching only allowed files.
- **Impact escalation**: Chain to RCE by overwriting config, plugin, or template files; escalate to privilege escalation by reading secrets or tokens; achieve DoS by overwriting critical files.

## Triage & severity
- Typical CVSS: High to Critical (7.5–10.0) for arbitrary file read/write or RCE; Medium for limited file access or authenticated-only bugs; Low for DoS or info leak.
- Severity up: Unauthenticated exploitation, access to secrets/configs, file write/overwrite, RCE, privilege escalation, cross-tenant impact.
- Severity down: Requires authentication, limited to non-sensitive files, sandboxed extraction, mitigations like chroot/jail, or only DoS possible.

## Reporting tips
- Strong PoC: Minimal reproducible request (with payload), clear evidence of file read/write or code execution, and impact statement (what file, what data, what attacker can do).
- Avoid: Reports with only error messages, no evidence of sensitive file access, or limited to non-exploitable files.
- Evidence checklist: Full request/response, file content or side effect, screenshots/logs, description of affected feature, and impact analysis.

## Real examples
- 1439593 — gitlab: Arbitrary file read via symlink in archive extraction during group import (critical, $29000)
- 827052 — gitlab: Arbitrary file read via path traversal in markdown attachment reference during issue move (critical, $20000)
- 1132378 — gitlab: Arbitrary file read via SSRF/path traversal in project import (critical, $16000)
- 822262 — gitlab: Path traversal in Nuget package registry via metadata injection (high, $12000)
- 2995025 — mozilla: RCE via file write and path traversal in VPN client live_reload command (high, $6000)
- 1394916 — ibb: Path traversal and file disclosure in Apache HTTP Server 2.4.49 (critical, $4000)
- 2256167 — ibb: Path traversal via Uint8Array in Node.js permission model (high, $3495)
- 2434811 — ibb: Path traversal by monkey-patching Buffer internals in Node.js (high, $2430)
- 2225660 — ibb: Path traversal via overridable path.resolve in Node.js (high, $2330)
- 301432 — gitlab: CI runner cache poisoning via path traversal in cache key (critical, $2000)
- 682774 — valve: Arbitrary file creation via registry path traversal in Steam Windows client (medium, $1250)
- 1650273 — ibb: Off-by-slash path traversal in Nginx alias config (medium, $1200)
- 243156 — rubygems: Arbitrary file write via crafted gem metadata (high, $1000)
- 519220 — rails: File write and RCE via path traversal in page caching (high, $1000)
- 1400238 — ibb: Path traversal and RCE in Apache HTTP Server 2.4.50 (critical, $1000)
- 1415820 — aiven_ltd: Zero-day unauthenticated LFI in Grafana plugin handler (high, $1000)

## Bounty intelligence
Critical LFI/path traversal with unauthenticated file read or write, especially in import/export or plugin/package management, can reach $10k–$30k on mature SaaS, CI/CD, or infrastructure programs. High-impact bugs in open source or client software (Node.js, Apache, package managers) typically pay $1k–$5k. Reports with clear RCE or cross-tenant impact are most valued; authenticated-only or DoS bugs trend lower. Programs with broad attack surface (DevOps, cloud, developer tools) pay the most for this category.