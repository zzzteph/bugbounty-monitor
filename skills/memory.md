---
category: memory
label: Memory Corruption
report_count: 662
programs: [valve, shopify-scripts, playstation, ibb, putty_h1c, brave, vlc_h1c]
avg_bounty: 3500
max_bounty: 10000
severity_distribution: critical: 7, high: 13, medium: 6, low: 1
---

## Overview

Memory corruption vulnerabilities break the core invariants of memory safety, allowing attackers to read, write, or execute arbitrary memory. These bugs persist due to unsafe parsing, missing bounds checks, and complex legacy codebases. The worst-case impact is remote code execution, privilege escalation, or full system compromise, often from a single malformed input.

## Root causes

- Lack of or incorrect bounds checking on buffer reads/writes, especially in legacy C/C++ code.
- Trusting user-controlled or file-supplied data structures without validation.
- Use-after-free due to incorrect object lifecycle management or race conditions.
- Double free or uninitialized memory access from improper error handling or cleanup logic.
- Integer overflows/underflows leading to miscalculated buffer sizes.
- Recursion or stack usage not properly limited, leading to stack exhaustion.
- Type confusion or improper casting in dynamic language runtimes or JITs.

## Attack surface

- File parsers for custom, legacy, or complex formats (e.g., images, audio, navigation meshes, compiled scripts).
- Network protocol handlers, especially those parsing variable-length fields or user-supplied indices.
- IPC/RPC endpoints accepting serialized or binary data.
- Scripting language sandboxes or embedded interpreters (Ruby, Python, JS engines).
- Features exposing direct memory manipulation (e.g., decompress, decode, or cryptographic APIs).
- Plugin or extension APIs that cross trust boundaries.
- HTTP request handlers with custom parsing logic, especially in modules or experimental features.
- Race conditions in multi-threaded or async code paths.

## Recon checklist

1. Enumerate all file upload, import, or parsing features (docs, media, configs, scripts).
2. Map all endpoints accepting binary or serialized input (API, network, IPC).
3. Identify protocol handlers and message dispatchers, especially those with variable-length fields or indices.
4. Review exposed scripting runtimes and their extension APIs.
5. Analyze client/server communication for custom message types or untrusted data flows.
6. Inspect for legacy code, C/C++ modules, or third-party libraries with known unsafe patterns.
7. Check for experimental or optional modules enabled in server configs.
8. Review open-source code or debug symbols for unchecked memcpy, strcpy, malloc, free, or pointer arithmetic.

## Hunt methodology

1. Upload or send malformed files with oversized, undersized, or negative length fields to file parsers.
2. Fuzz network message handlers with out-of-bounds indices, large/small/negative values, and unexpected types.
3. Trigger object lifecycle edge cases (e.g., free, release, or delete) and then access the object again.
4. Send serialized payloads with crafted pointers, types, or reference counts to scripting engines.
5. Manipulate recursion depth or stack usage via deeply nested or self-referential input.
6. Test for integer overflows/underflows in size, offset, or count fields.
7. Race object creation and deletion in multi-threaded or async features.
8. Observe for crashes, memory sanitizer/ASAN reports, or abnormal process exits, then minimize the test case.

## Payload library

### Oversized/Undersized Buffer
**Technique**: Exploit missing or incorrect bounds checks by supplying length fields that exceed or underflow buffer sizes.
**How to apply**: Craft a file or network message where a length field ({len}) is set to a value larger or smaller than the actual buffer, or negative if signed.
**Payload**:
```
{header}{len:0xFFFFFFFF}{data}
```
**Observe**: Application crash, heap/stack overflow, or memory sanitizer alert.
**Seen in**: Voice decoder input in media features, SSH protocol key exchange, file importers.

### Out-of-Bounds Indexing
**Technique**: Supply indices that are outside the valid range, causing reads/writes to unintended memory.
**How to apply**: Send a message or file with an index field ({index}) set to a large, negative, or otherwise invalid value.
**Payload**:
```
{header}{index:0x80000000}{payload}
```
**Observe**: Crash, information leak, or code execution via vtable/gadget overwrite.
**Seen in**: Network message entity handlers, weapon/resource tables, array-backed protocol fields.

### Use-After-Free / Double Free
**Technique**: Trigger object deletion (free/release) and then access or free the object again.
**How to apply**: Sequence API calls or script operations to free an object, then invoke a method or property on it.
**Payload**:
```
POST /api/endpoint
{
  "action": "release",
  "object_id": "{id}"
}
# Followed by
POST /api/endpoint
{
  "action": "use",
  "object_id": "{id}"
}
```
**Observe**: Crash, memory corruption, or code execution.
**Seen in**: Scripting engine objects, plugin APIs, Flash/JS/AS3 objects.

### Integer Overflow/Underflow
**Technique**: Supply values that, when used in arithmetic, wrap around and cause buffer misallocation or miscalculation.
**How to apply**: Set size/count/offset fields to values near the integer limits.
**Payload**:
```
{header}{size:0xFFFFFFFF}{data}
```
**Observe**: Crash, heap corruption, or out-of-bounds access.
**Seen in**: PHP iconv, mb_split, file format decoders.

### Recursive/Stack Exhaustion
**Technique**: Cause deep recursion or excessive stack usage to trigger stack overflow or uninitialized memory access.
**How to apply**: Send input that causes recursive function calls or deep nesting.
**Payload**:
```
{ "data": [ { "nested": [ ... repeat N times ... ] } ] }
```
**Observe**: Stack overflow, segfault, or uninitialized memory read.
**Seen in**: Scripting runtimes, AST builders, protocol parsers.

### Type Confusion / Object Overwrite
**Technique**: Overwrite or reassign object types, leading to invalid method dispatch or memory access.
**How to apply**: Supply crafted input or script that reassigns a class/type or manipulates internal pointers.
**Payload**:
```
{ "reassign": { "class": "{builtin_type}", "target": "{object}" } }
```
**Observe**: Crash, memory corruption, or code execution.
**Seen in**: Ruby/JS engine class reassignment, Flash ASnative calls.

## Filter & WAF bypass

- Use alternate encodings for length and index fields (big/little endian, signed/unsigned).
- Insert null bytes or Unicode in payloads to bypass naive string checks.
- Chunked transfer encoding or fragmented packets to evade size-based filters.
- Exploit protocol-specific quirks (e.g., negative numbers interpreted as large unsigned).
- Use valid but unexpected types or structures to bypass type checks.
- For file uploads, embed payloads in metadata or optional sections.

## Verification & impact

- **Confirmed vulnerable**: Application/process crash, memory sanitizer/ASAN/valgrind report, or observable memory corruption (e.g., overwritten SEH, EIP, or vtable pointer).
- **False positive signals**: Graceful error handling, input rejection, or crash without memory corruption (e.g., handled exception, no overwrite).
- **Impact escalation**: Achieve code execution by controlling overwritten pointers (vtable, function table, SEH), chaining with infoleaks or sandbox escapes, or leveraging RCE in client/server context for privilege escalation.

## Triage & severity

- Typical CVSS: 7.5–10.0 for RCE, 5.0–7.5 for DoS or infoleak, lower for sandboxed or limited-scope issues.
- Severity increases with unauthenticated attack surface, remote exploitability, or ability to chain to full compromise.
- Severity decreases if only DoS is possible, exploit requires rare configuration, or strong mitigations (ASLR, sandboxing) are in place.

## Reporting tips

- Strong PoC: Minimal input (file, network message, or API call) that triggers the bug, with debugger/ASAN output showing the exact memory corruption.
- Avoid: Reports with only a crash and no evidence of memory corruption, or bugs requiring unrealistic attacker control.
- Evidence checklist: Input payload, reproduction steps, crash logs (with stack trace), memory sanitizer output, and a clear impact statement (e.g., "EIP control", "heap overflow", "kernel R/W primitive").

## Real examples

- 542180 — valve: Malformed navigation mesh file triggers buffer overflow and EIP control in game AI parser (critical, $10000)
- 186723 — shopify-scripts: Overwriting exception class in Ruby engine leads to memory corruption and crash (high, $10000)
- 189633 — shopify-scripts: Crafted Ruby input causes C-level stack overflow and segfault (high, $10000)
- 826026 — playstation: Race in IPv6 socket options leads to kernel use-after-free and arbitrary R/W (high, $10000)
- 1180252 — valve: Buffer overrun in voice decoder allows stack overwrite via crafted audio payload (critical, $7500)
- 807772 — valve: OOB reads in network message handlers enable RCE via entity index manipulation (critical, $7500)
- 56385 — ibb: Double free in Flash Player Settings Manager leads to code execution (high, $5000)
- 119652 — ibb: Flash Player ASnative call with crafted object triggers memory corruption and EIP hijack (high, $5000)
- 139879 — ibb: Flash Player regex engine use-after-free enables remote code execution (high, $5000)
- 151039 — ibb: Uninitialized memory in Flash Player TimedEvent.parent allows type confusion and code execution (high, $5000)
- 1549636 — ibb: Double free in Ruby Regexp compilation with crafted pattern (high, $4000)
- 630462 — putty_h1c: Heap overflow in SSH protocol 1 key handling enables remote code execution (high, $3645.9)
- 513154 — valve: Weapon ID underflow in message parser allows function table overwrite and RCE (critical, $3000)
- 1977252 — brave: Use-after-free in Ethereum wallet renderer enables code execution in browser process (critical, $3000)
- 489102 — vlc_h1c: Stack buffer overflow in RTSP handler enables SEH overwrite (high, $2817.28)
- 2585375 — ibb: Null pointer dereference in Apache mod_proxy allows remote DoS (high, $4920)
- 2526041 — ibb: NGINX HTTP/3 QUIC module null dereference enables remote DoS (medium, $2600)
- 2658447 — ibb: Buffer overread in NGINX MP4 module allows worker memory disclosure and crash (medium, $2142)
- 746766 — ibb: OOB reads in Python AST builder enable remote DoS via crafted code (medium, $2000)

## Bounty intelligence

Memory corruption bugs with proven code execution or kernel impact command the highest bounties ($5k–$10k+), especially in gaming, browser, or OS-level targets. DoS-only or infoleak bugs typically see $1k–$3k. Programs with complex C/C++ codebases, legacy file formats, or exposed scripting runtimes pay most, and bounties increase significantly for unauthenticated, remote, or cross-sandbox exploits. Reports with minimal PoCs or unclear impact are often marked as low severity or informational.