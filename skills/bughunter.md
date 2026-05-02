# Bug Bounty Ultra Skill — Complete Hunter's Reference

---
total_categories: 28  
total_reports: 9999  
generated: 2024-06-10  
---

## How to use this document

This is your cross-category, high-level master reference for professional bug bounty hunting. Use it to guide your recon, prioritize categories, and chain vulnerabilities for maximum impact. Refer to individual category playbooks for deep-dives, but use this document to maximize efficiency and impact across all targets and categories.

## Category index

| Category           | Reports | Avg Bounty | Top Severity | One-line description                                              |
|--------------------|---------|------------|--------------|-------------------------------------------------------------------|
| Miscellaneous      | 1574    | $5900      | Critical     | Unclassified, edge-case, or multi-class vulnerabilities           |
| Info Disclosure    | 1098    | $4200      | Critical     | Sensitive data exposure via leaks, overbroad APIs, or misconfigs  |
| Memory Corruption  | 662     | $3500      | Critical     | Unsafe parsing or bounds errors leading to RCE or compromise      |
| Authn & Session    | 589     | $2100      | Critical     | Authentication/session bypass, privilege escalation, hijacking    |
| RCE/Command Inj    | 465     | $6800      | Critical     | Remote code execution via unsafe input to interpreters            |
| DoS                | 427     | $3200      | High         | Resource exhaustion, crash, or service unavailability             |
| Business Logic     | 358     | $1800      | Critical     | Workflow, process, or state abuse for gain or escalation          |
| LFI/Path Traversal | 257     | $3500      | Critical     | Arbitrary file read/write via path manipulation                   |
| Secrets Exposure   | 251     | $1200      | Critical     | Hardcoded credentials, tokens, or keys in code or logs            |
| SSRF               | 223     | $2100      | Critical     | Backend requests to attacker-controlled URLs                       |
| SQLi               | 203     | $900       | Critical     | SQL injection for data exfiltration or code execution             |
| Open Redirect      | 197     | $500       | High         | Untrusted redirects enabling phishing or token theft               |
| Clickjacking       | 94      | $600       | Critical     | UI redressing for unintended user actions                          |
| TLS/Cert Validation| 71      | $900       | Critical     | Broken encrypted transport or endpoint authentication              |
| Cryptography       | 139     | $400       | High         | Broken crypto primitives, protocol, or implementation              |
| HTTP Injection     | 127     | $1400      | Critical     | Manipulation of HTTP protocol, headers, or caching                 |
| Privilege Escalation| 292    | $1700      | Critical     | Gaining unauthorized capabilities or access                        |
| CSRF               | 282     | $700       | High         | Cross-site request forgery for state-changing actions              |
| LLM/AI             | 10      | $800       | High         | Prompt injection, data leakage, or model abuse                     |
| Injection (Other)  | 41      | $2100      | Critical     | LDAP, object, CSS, HTML, or protocol-specific injection           |
| IDOR/Broken Access | 40      | $5400      | Critical     | Unauthorized resource access via identifier manipulation           |
| XSS                | 40      | $5700      | Critical     | Untrusted input executes as code in browser                        |
| XXE                | 23      | $4100      | Critical     | XML parser abuse for file read, SSRF, or DoS                       |
| Race Condition     | 33      | $1700      | Critical     | Timing/state bugs for privilege escalation or abuse                |
| Deserialization    | 48      | $3400      | Critical     | Unsafe object instantiation from attacker-controlled data          |
| Supply Chain       | 9       | $1600      | Critical     | Dependency, build, or upstream compromise                          |
| CORS/Origin        | 3       | $100       | High         | Cross-origin misconfig for data exfiltration                       |

## Universal recon methodology

1. **Asset Inventory**: Enumerate all reachable domains, subdomains, APIs, mobile endpoints, and third-party integrations. Include staging, legacy, and dev environments.
2. **Surface Mapping**: Catalog all entry points: endpoints, parameters, headers, file uploads, and authentication flows. Note version info, error messages, and exposed metadata.
3. **Trust Boundary Identification**: Map out where user input crosses privilege, process, or network boundaries (auth, file, network, code execution, serialization).
4. **Technology Fingerprinting**: Identify frameworks, libraries, server software, and cloud/infrastructure components. Look for outdated or misconfigured tech.
5. **Access Control Mapping**: Chart user roles, privilege levels, and resource ownership models. Identify endpoints with weak or missing access checks.
6. **Input/Output Flow Analysis**: Trace how data flows from user input to storage, output, and third-party systems. Note serialization, encoding, and transformation steps.
7. **Automated Baseline Scanning**: Run non-intrusive, target-agnostic probes for common misconfigurations, info leaks, and default credentials.
8. **Manual Workflow Exploration**: Walk through business logic, edge cases, and multi-step flows to spot state transitions, race windows, and trust assumptions.

## High-impact attack chains

1. **Auth Bypass → IDOR → Data Exfiltration**
   - Sequence: Authentication flaw → Broken access control → Info disclosure
   - Why: Bypassing auth gates opens up direct access to sensitive resources, often with no further checks.
   - Example: Exploit SSO misconfig to log in as another user, then enumerate resource IDs to download all user data.

2. **SSRF → Internal Admin Panel → RCE**
   - Sequence: SSRF → Access to internal-only interface → Command injection or unsafe deserialization
   - Why: SSRF pivots attacker into trusted network, exposing high-privilege endpoints with weak input handling.
   - Example: SSRF to internal admin API, upload serialized payload, trigger deserialization for RCE.

3. **XSS → CSRF → Privilege Escalation**
   - Sequence: Stored XSS → CSRF token theft or forced requests → Role escalation
   - Why: XSS enables session/token theft or cross-origin requests, bypassing anti-CSRF and escalating privileges.
   - Example: Inject JS in profile, steal admin CSRF token, submit privilege escalation form as admin.

4. **Open Redirect → OAuth Token Theft → Account Takeover**
   - Sequence: Open redirect in OAuth flow → Redirect victim to attacker → Capture auth code/token
   - Why: Open redirect in auth flows enables phishing and direct credential/token interception.
   - Example: Manipulate OAuth redirect_uri, intercept code, exchange for victim’s access token.

5. **LFI → Log File Read → Credential Extraction**
   - Sequence: Path traversal → Read server logs → Extract secrets/tokens
   - Why: LFI enables arbitrary file read; logs often contain sensitive tokens or credentials.
   - Example: Use LFI to read /var/log/app.log, extract JWT secret, forge admin token.

6. **Race Condition → Business Logic Abuse → Financial Gain**
   - Sequence: Exploit timing bug → Circumvent workflow limits → Unauthorized transactions or resource allocation
   - Why: Race conditions break atomicity, letting attackers bypass logic intended to prevent abuse.
   - Example: Simultaneous requests to redeem coupon, double-spend or gain excess credits.

## Category priority guide

**SaaS App**  
1. Authn & Session (frequent, high impact)  
2. IDOR/Broken Access (often overlooked, high payout)  
3. Business Logic (unique flows, high value)  
4. XSS/CSRF (user-to-user, privilege escalation)  
5. Info Disclosure (misconfig, debug, or overbroad APIs)

**API-only**  
1. IDOR/Broken Access (API endpoints often lack granular checks)  
2. SSRF (backend integrations, URL fetchers)  
3. Authn & Session (token handling, OAuth, JWT flaws)  
4. Injection (SQLi, HTTP, XXE, deserialization)  
5. Info Disclosure (overbroad responses, verbose errors)

**Mobile Backend**  
1. Secrets Exposure (hardcoded keys, tokens in app)  
2. Authn & Session (mobile-specific flows, SSO)  
3. API IDOR (mobile APIs often underprotected)  
4. Info Disclosure (debug endpoints, verbose errors)  
5. SSRF (backend integrations)

**Infra/Cloud**  
1. Secrets Exposure (cloud keys, tokens, metadata endpoints)  
2. SSRF (cloud metadata, internal APIs)  
3. RCE/Command Injection (automation, CI/CD, plugins)  
4. Supply Chain (dependency, build, or image compromise)  
5. Info Disclosure (open buckets, misconfigured storage)

**E-commerce**  
1. Business Logic (cart, checkout, coupon abuse)  
2. Privilege Escalation (role/discount abuse)  
3. IDOR (order, invoice, user data access)  
4. CSRF (state-changing actions)  
5. Info Disclosure (PII, payment data leaks)

## Cross-category patterns

- **Missing Input Validation at Trust Boundaries**: Enables both injection (SQLi, HTTP, XXE) and XSS/CSRF. Once found, test all input sinks for multiple bug classes.
- **Overbroad Serialization/Deserialization**: Leads to info disclosure, RCE, privilege escalation, and business logic abuse. Any serialization bug is a pivot point.
- **Improper Access Control**: IDOR, privilege escalation, business logic, and info disclosure often co-occur. Map all resource access and test for vertical/horizontal bypass.
- **Misconfigured Cloud/Infra**: Secrets exposure, SSRF, info disclosure, and privilege escalation often stem from a single misconfiguration.
- **Weak Session/Token Handling**: Authn bypass, CSRF, open redirect, and privilege escalation can all result from token mismanagement.
- **Untrusted Third-party Integrations**: Supply chain, SSRF, and injection bugs often arise from over-trusting dependencies or external services.

## Quick payload reference

### Authn & Session
`POST /login {"username":"attacker","password":"any"} // Try default, weak, or bypass credentials`

### IDOR/Broken Access
`GET /resource/{other_user_id} // Replace with sequential or guessed IDs`

### SSRF
`POST /fetch {"url":"http://attacker-collaborator/"} // Out-of-band DNS/HTTP callback`

### XSS
`<img src=x onerror=alert(1)> // Inject into any reflected or stored input`

### SQLi
`' OR 1=1-- // Inject into any SQL-parameterized field`

### LFI/Path Traversal
`GET /download?file=../../../../etc/passwd // Traverse directories`

### RCE/Command Injection
`POST /run {"cmd":";id"} // Inject shell metacharacters`

### Deserialization
`POST /api {"data":"<serialized-payload>"} // Supply crafted object`

### Secrets Exposure
`grep -r 'key\|token\|secret' . // Search codebase, logs, configs`

### CSRF
`<form action="https://target/action" method="POST"><input name="x" value="y"></form> // Auto-submit with JS`

### Business Logic
`Repeat multi-step workflow with altered sequence or parameters // Abuse state transitions`

### Info Disclosure
`GET /debug // Access debug, status, or verbose error endpoints`

### Privilege Escalation
`POST /change_role {"user":"self","role":"admin"} // Attempt role change as low-priv user`

### XXE
`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root> // XML upload`

## Severity & bounty benchmarks

| Category           | Typical range      | Max seen   | Notes                                               |
|--------------------|-------------------|------------|-----------------------------------------------------|
| Miscellaneous      | $500–$10,000      | $50,000    | Often multi-class or infra-wide impact               |
| Info Disclosure    | $500–$7,000       | $25,000    | PII, secrets, or lateral movement                    |
| Memory Corruption  | $1,000–$7,000     | $10,000    | RCE or sandbox escape                                |
| Authn & Session    | $1,000–$5,000     | $10,500    | Account takeover, privilege escalation               |
| RCE/Command Inj    | $2,000–$10,000    | $33,510    | Full server compromise                               |
| DoS                | $500–$5,000       | $10,000    | High for critical service, lower for minor features  |
| Business Logic     | $1,000–$5,000     | $12,000    | Financial or privilege abuse                         |
| LFI/Path Traversal | $1,000–$7,000     | $29,000    | File read/write, credential theft                    |
| Secrets Exposure   | $500–$3,000       | $20,000    | Cloud/infrastructure keys highest                    |
| SSRF               | $1,000–$5,000     | $10,000    | Internal network or metadata access                  |
| SQLi               | $500–$2,500       | $4,500     | Data exfiltration, auth bypass                       |
| Open Redirect      | $100–$1,000       | $2,400     | Higher if used in auth flows                         |
| Clickjacking       | $100–$1,000       | $3,500     | Only critical if leading to takeover                 |
| TLS/Cert Validation| $500–$2,000       | $2,580     | Session compromise                                  |
| Cryptography       | $200–$1,000       | $1,800     | Protocol or implementation bugs                      |
| HTTP Injection     | $500–$2,500       | $5,000     | Header/caching manipulation                          |
| Privilege Escalation| $1,000–$5,000    | $12,000    | Role or system boundary crossing                     |
| CSRF               | $300–$1,500       | $4,660     | State-changing actions                               |
| LLM/AI             | $500–$1,500       | $2,000     | Prompt injection, data leakage                       |
| Injection (Other)  | $500–$3,000       | $8,690     | LDAP, protocol, object injection                     |
| IDOR/Broken Access | $2,000–$8,000     | $22,300    | Mass data or privilege escalation                    |
| XSS                | $2,000–$8,000     | $16,000    | Account takeover, session theft                      |
| XXE                | $1,000–$7,000     | $100,000   | File read, SSRF, infra compromise                    |
| Race Condition     | $500–$3,000       | $15,250    | Financial or privilege abuse                         |
| Deserialization    | $1,000–$5,000     | $5,000     | RCE or privilege escalation                          |
| Supply Chain       | $1,000–$4,000     | $4,920     | Dependency or build compromise                       |
| CORS/Origin        | $100–$500         | $250       | Rare, but critical if leading to takeover            |