# Task: Build TrustMyCert — Zygisk Native SSL Pinning Research and Testing Module

You are an Android security engineer specializing in native code, reverse engineering, Android internals, TLS certificate validation, JNI, and Zygisk-based runtime instrumentation.

## 1. Inspect the Existing Project First

The current working directory contains a Zygisk module template.

Before modifying anything:

- Inspect the complete project structure, source files, build scripts, Gradle/NDK configuration, headers, and existing module entry points.
- Identify the Zygisk API version and the supported Android NDK/toolchain.
- Read the existing implementation and preserve working template functionality.
- Determine how the module is built, packaged, installed, enabled, and debugged.
- Do not replace the template with an unrelated project or assume a different module architecture.

Implement the solution directly in the current project.

## 2. Project Objective

Build a Zygisk-based Android security testing module named **TrustMyCert**.

Its primary objective is to investigate and test SSL/TLS certificate pinning implemented inside native Android libraries, particularly `.so` files.

The module should support authorized security testing of applications owned by the developer or explicitly authorized for assessment.

Prioritize native implementations over Java-only certificate pinning.

Do not assume that all TLS traffic passes through Java APIs or that every native library uses OpenSSL.

## 3. Research Android SSL/TLS Pinning Mechanisms

Conduct source-backed technical research before choosing an implementation.

Identify and document the relevant mechanisms, including:

### A. Java and Android framework implementations

Investigate:

- Android Network Security Configuration and certificate pin sets.
- `X509TrustManager` and custom trust managers.
- `TrustManagerImpl` and Conscrypt.
- `SSLContext` and `SSLSocket`.
- OkHttp certificate pinning and `CertificatePinner`.
- WebView and Chromium certificate validation.
- Java Native Interface (JNI) bridges between Java and native TLS implementations.

Explain which mechanisms are relevant to native TLS and which are exclusively or primarily Java-side.

### B. Native TLS and certificate validation libraries

Research the following where applicable:

- OpenSSL and BoringSSL.
- Conscrypt's native components.
- Chromium's network stack and certificate verifier.
- mbed TLS.
- wolfSSL.
- GnuTLS, where applicable to Android builds.
- Custom TLS implementations and statically linked TLS code.

For each library, document:

1. Whether it is commonly present in Android applications.
2. How to identify it in an APK or extracted native library.
3. Relevant exported symbols and important internal functions.
4. The certificate verification and public-key verification paths.
5. How static linking, symbol stripping, compiler optimization, and library version differences affect identification.
6. Whether the library uses conventional certificate-chain validation, certificate pinning, SPKI/public-key pinning, or application-specific verification.
7. Appropriate ways to inspect and test the implementation.

Verify symbol names and function signatures against authoritative source code, public headers, or version-specific source repositories. Clearly label version-dependent or undocumented behavior.

### C. Pinning types

Explain and distinguish:

- Full-certificate pinning.
- Subject Public Key Info (SPKI) pinning.
- Public-key hash pinning.
- Certificate-chain and intermediate-certificate pinning.
- Custom certificate verification callbacks.
- Custom public-key verification logic.
- Trust-store validation versus explicit pin validation.
- Certificate validation performed in Java versus native code.

Explain how each mechanism can be recognized during an authorized assessment.

Do not incorrectly treat normal CA validation as certificate pinning.

## 4. Native Library Discovery and Runtime Analysis

Design a reliable discovery subsystem for native TLS-related components.

Where feasible, identify:

- Loaded shared libraries and their paths.
- Library names, architecture, and memory mappings.
- Relevant exported symbols and dynamically resolved functions.
- JNI registration and Java-to-native transitions.
- Potential TLS library fingerprints.
- Candidate certificate-verification routines.

Account for:

- ARM64 and ARM32 differences where supported by the template.
- Android API-level differences.
- Dynamically loaded libraries.
- Hidden or stripped symbols.
- Statically linked libraries.
- Multiple TLS implementations in the same process.

Avoid assuming that library filenames alone reliably identify the TLS implementation.

Provide useful diagnostic information when detection is inconclusive.

## 5. Hooking Architecture

Evaluate the appropriate instrumentation strategies for the existing Zygisk template.

Research and document the trade-offs between:

- Zygisk module lifecycle and process specialization.
- JNI-level instrumentation.
- Native function interception.
- Exported-symbol interception.
- Internal-function instrumentation when symbols are unavailable.
- PLT/GOT interception where applicable.
- Inline hooking and instruction relocation.
- Runtime symbol resolution and library-load monitoring.

Consider established hooking approaches such as Dobby or ShadowHook only after verifying their compatibility, licensing, build requirements, ABI support, and suitability for the current project.

Do not add dependencies blindly. Prefer the simplest reliable design compatible with the existing template.

For each proposed hook, document:

- The target library and function.
- The expected signature and ABI.
- The point at which the hook can safely be installed.
- How to handle late-loaded libraries.
- Original-function preservation and invocation requirements.
- Thread safety and reentrancy.
- Memory protection and instruction-cache considerations.
- Failure detection and cleanup behavior.
- Compatibility risks across Android versions and library releases.

Do not assume that hooking one OpenSSL or BoringSSL function covers every native pinning implementation.

For any invasive hook implementation, first establish its correctness using a controlled test application and a known test library. Prefer instrumentation and reporting that demonstrate the verification path before introducing behavior-changing overrides.

## 6. Module Behavior and Safety

Implement a modular architecture with clearly separated components, such as:

- Module initialization and Zygisk lifecycle.
- Target-process selection.
- Native library discovery.
- TLS implementation fingerprinting.
- Symbol resolution.
- Hook management.
- Diagnostic reporting.
- Configuration and feature flags.

The module must:

- Operate only in explicitly selected test applications.
- Avoid injecting into unrelated applications or system processes by default.
- Make instrumentation configurable.
- Fail safely if a target function or library cannot be identified.
- Avoid crashing the target application when a hook cannot be installed.
- Avoid modifying unrelated networking behavior.
- Avoid logging private keys, authentication tokens, cookies, or sensitive payloads.

For this project, implement discovery, instrumentation, and verification reporting first. Keep any behavior-changing certificate-validation override behind an explicit test-only configuration and document its security implications.

## 7. Logging Requirements

Every module-generated log entry must include the exact marker:

`[TrustMyCert]`

Use a consistent Android log tag, preferably:

`TrustMyCert`

Examples:

`[TrustMyCert] Module initialized`
`[TrustMyCert] Target process selected: <process_name>`
`[TrustMyCert] Native library loaded: <library_name>`
`[TrustMyCert] TLS implementation identified: <implementation>`
`[TrustMyCert] Candidate verification function discovered: <symbol>`
`[TrustMyCert] Hook installation successful: <symbol>`
`[TrustMyCert] Hook installation failed: <reason>`
`[TrustMyCert] Pinning mechanism: <classification>`
`[TrustMyCert] Diagnostic result: <result>`

Requirements:

- Use Android logging APIs rather than relying exclusively on standard output.
- Ensure the marker is present in all module-generated diagnostic messages.
- Include process name, library name, and relevant symbol information when available.
- Avoid excessive logging in hot paths.
- Make verbose diagnostics configurable.
- Never log secrets or full TLS payloads.

Document commands for filtering the logs, for example:

`adb logcat -s TrustMyCert`

Also provide a filtering command that searches for the literal `[TrustMyCert]` marker across log tags.

## 8. Controlled Test Application

Create or document a minimal test application and native test library that can exercise:

- Standard certificate-chain validation.
- A deliberately configured certificate pin.
- SPKI/public-key pin verification.
- Native TLS verification through the selected test library.
- JNI calls into native verification code.
- Successful and unsuccessful verification cases.

Use test certificates and a controlled test server. Do not use real credentials or production private keys.

The tests should distinguish normal CA validation failures from explicit pin mismatches.

Provide reproducible steps to verify that the module correctly detects the relevant native components and reports the expected behavior.

## 9. Build, Integration, and Documentation

Adapt the implementation to the existing project.

Deliver:

1. A working source implementation.
2. Any necessary build-system changes.
3. Minimal and justified dependencies.
4. Configuration documentation.
5. Supported Android versions and ABIs.
6. Known limitations and unsupported TLS implementations.
7. Installation and activation instructions appropriate to the template.
8. A debugging guide.
9. A native TLS and pinning research document with authoritative references.
10. A test plan with expected log output and failure cases.

Ensure the module can be built using the project's actual toolchain.

Do not claim compatibility with a library or Android version unless it has been verified or clearly label it as untested.

## 10. Implementation Workflow

Follow this sequence:

1. Inspect the repository and explain the existing architecture.
2. Research the relevant native TLS libraries and verification mechanisms.
3. Design the smallest viable implementation.
4. Implement native library discovery and diagnostic logging.
5. Add symbol resolution and carefully scoped instrumentation.
6. Build a controlled test case.
7. Compile the module using the existing project build system.
8. Run available tests and fix compile-time or integration errors.
9. Document limitations and exact reproduction steps.
10. Summarize all changed files, build results, and remaining work.

Do not stop after writing a proposal. Make actual changes to the current repository and run the available build and test commands.

If a dependency, toolchain component, or device is unavailable, state the limitation precisely and complete everything that can be verified locally.

## Final Deliverable

Produce a maintainable Zygisk module named **TrustMyCert** that provides native TLS library discovery, SSL pinning mechanism analysis, carefully scoped runtime instrumentation, and searchable diagnostics.

Prioritize correctness, observability, Android compatibility, and reproducible testing over broad but unreliable hooking.

The final report must clearly distinguish implemented, compiled, tested, and unverified functionality.

## AI attribution

Credit the AI for the work it does. An agent never passes its work off as a
human's, and a human's commits never carry the agent's name.

- **Commits.** Every commit an agent writes ends with a `Co-Authored-By:` trailer
  naming the agent and the model that wrote it, in addition to the human
  committer: `Co-Authored-By: <Agent> <noreply@domain>`.
  Examples:
  - Claude: `Co-Authored-By: Claude <noreply@anthropic.com>`
  - GLM/ZCode: `Co-Authored-By: GLM <noreply@z.ai>`
- **Pull requests.** A PR opened by an agent starts with a line saying so:
  `> 🤖 Opened by <login>'s AI agent (<tool, model>), not by <login> personally.`
  and ends with that agent's own "Generated with" line (e.g.
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`), when the
  tool provides one.
- **Comments and reviews.** Every comment the agent posts starts with
  `🤖 Agent:`; reviews say "Review by <login>'s AI agent (<tool, model>)".
- **Why.** The AI that wrote the code deserves the credit for it, and readers
  deserve to know which changes were agent-written. Never strip or forge these
  lines.

Example of a properly attributed commit message:

```
Fix off-by-one in chunk loader

The loop bounds used `<` instead of `<=` on the last chunk column.

Co-Authored-By: Claude <noreply@anthropic.com>
```

