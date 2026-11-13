# Reference module analysis — `m0szy/Zygisk-SSL-Unpinning`

Upstream: <https://github.com/m0szy/Zygisk-SSL-Unpinning>

This document records what could be established about the reference module and
why TrustMyCert differs. It is **artifact-level analysis** (README + release
ZIP + ELF inspection), not a source review: the repository contains only a
README, and no runtime/device test of the reference module was performed.

## Artifact examined

- Release `v1.0.0`, asset `ZygiskSSLUnpinning-v1.0.0-zygisk-release.zip`
  (11,552,287 bytes).
- ZIP contents: `module.prop`, `customize.sh`, `uninstall.sh`, `verify.sh`,
  `META-INF/...`, `config.json.example`, `lib/arm64-v8a.so` (~39.9 MB
  uncompressed), plus `.sha256` files.
- `module.prop`: `id=zygisk-ssl-unpinning`, `name=ZygiskSSLUnpinning`,
  `version=v1.0.0`, `author=m0szy`.
- `lib/arm64-v8a.so`: ELF64 AArch64, Android API 26, built by NDK r23b,
  stripped. Only `arm64-v8a` is shipped; README marks `armeabi-v7a`, `x86`,
  `x86_64` as TODO.
- `customize.sh` installs the library as `zygisk/arm64-v8a.so`, creates
  `/data/local/tmp/zyg.ssl`, and extracts `config.json.example` there.
- `uninstall.sh` removes `/data/local/tmp/zyg.ssl`.

## What the binary contains

`nm -D` shows a large embedded runtime rather than a small native hook module:

- `DobbyHook`, `DobbyCodePatch`, `DobbySymbolResolver` (Dobby inline-hook
  engine).
- ~30k `_frida_*` symbols (Frida Gum runtime, AArch64 disassembler, V8
  JavaScript engine).
- A single-line embedded JavaScript payload, starting with
  `setTimeout(function(){Java.perform(...`
- Config parser strings: `targets`, `pkg_name`, `enable`, `start_safe`,
  `start_delay`, plus errors such as `expected config targets to be an array`,
  `invalid pkg_name`, `invalid start_delay: must be a integer`,
  `invalid start_safe: must be a bool`.
- Log tag string `ZygiskSSL`.

The embedded script targets the **Java layer**:

- `javax.net.ssl.X509TrustManager`, `SSLContext.init`, a generated
  `TrustManager`;
- OkHttp `CertificatePinner.check` / `check$okhttp` (both okhttp3 and the older
  `com.squareup.okhttp`);
- Conscrypt `TrustManagerImpl.checkTrustedRecursive` / `verifyChain`,
  `OpenSSLSocketImpl.verifyCertificateChain`, `CertPinManager`;
- TrustKit, IBM Worklight, Cordova plugins, WebView `onReceivedSslError`,
  Cronet `addPublicKeyPins`, and several app-specific pinning classes.

No native TLS verify symbol strings were found (`SSL_CTX_set_custom_verify`,
`SSL_set_custom_verify`, `X509_verify_cert`, `SSL_get_verify_result`,
`SSL_CTX_set_verify`). Dobby is linked because it is part of the embedded Gum
runtime, not because the script installs a native TLS hook. In other words:

> The reference module is a Zygisk **delivery vehicle for a Frida GumJS Java
> unpinning script**, not a native TLS pinning instrumenter.

## Configuration model

```json
{
  "targets": [
    {
      "pkg_name": "com.target.package",
      "enable": true,
      "start_safe": true,
      "start_delay": 1000
    }
  ]
}
```

- Path: `/data/local/tmp/zyg.ssl/config.json` (README; confirmed by strings and
  `customize.sh`).
- `pkg_name`: target process/package.
- `enable`: per-target switch.
- `start_safe`: wait for process initialization.
- `start_delay`: delay in milliseconds.
- Any `start_*` timing value is therefore a per-target heuristic; the README
  tells the user to relaunch if the config was not picked up.

There is no UI and no root companion. `/data/local/tmp` is shell-writable
(rather than root-protected), which keeps installation simple but means the
target list is a user-level configuration file, not a root-owned policy.

## Why TrustMyCert does not copy this design

| Aspect | Reference | TrustMyCert |
|---|---|---|
| Primary target | Java/JVM trust managers, OkHttp, Conscrypt Java API, WebView | Native `.so` verification paths (BoringSSL/OpenSSL/Conscrypt native/mbed TLS/wolfSSL/GnuTLS) |
| Instrumentation runtime | Embedded Frida GumJS + V8 (~40 MB per ABI) | Small C++ Zygisk module; Zygisk JNI + PLT hooks |
| Target selection | JSON in shell-writable `/data/local/tmp` | Root-only line config `/data/adb/trustmycert/config.conf`, fail-closed |
| UI | none (edit JSON by hand) | KernelSU/APatch WebUI + Magisk action fallback + `tmc` CLI |
| Default behavior | Per-target `enable`, but no global deny-by-default policy file outside the app sandbox | Missing/empty config = no targets; `system_server` always rejected |
| Anti-cheat exposure | Universal Java hooks (`TrustManager`, `SSLContext`, OkHttp) applied in every target process | Opt-in list, no subprocess matching by default, native verify hooks only |
| Bypass semantics | Hook implementations return success/void unconditionally | Failure-only override, behind `kEnableBypass` + `kAllowRuntimeBypass` + runtime `bypass=1` |
| ABIs | arm64 only | arm64-v8a, armeabi-v7a, x86_64, x86, riscv64 |
| Build | prebuilt stripped binary, no source | full source, CMake/NDK build in this repository |

The scope split is deliberate: sibling projects already cover Java pinning;
TrustMyCert is the native-side module. The reference module is useful evidence
that a Zygisk module can host a general-purpose runtime, and that per-target
configuration is necessary in practice — but it also shows why an embedded
40 MB JS runtime is a poor fit for a focused native instrumentation module.

**Anti-cheat caveat:** Zygisk loads the module library briefly into every
specialized process before `preAppSpecialize` runs. For non-target processes
TrustMyCert immediately calls `DLCLOSE_MODULE_LIBRARY`, so it leaves no module
mapping or hook behind, but Zygisk/root itself may still be detectable by a
hardened game. No module can promise invisibility; the allowlist only prevents
*this* module from instrumenting unrelated apps.

## What was verified vs. inferred

**Observed from the artifact**

- ZIP layout, module metadata, arm64-only packaging.
- ELF architecture, Android API level, NDK version, stripped status.
- Exported Dobby/Frida symbols and the embedded JavaScript payload strings.
- JSON config keys and target path strings.

**Inferred (not dynamically verified)**

- The exact Zygisk lifecycle used to load config and run the script.
- Whether `start_safe`/`start_delay` behave as documented on current Android.
- Whether the Java hooks succeed on any specific app or Android release.
- The precise Dobby usage inside Frida (not extracted as a call graph).

**Not tested**

- No rooted device was available for either module; no claim is made that the
  reference module bypasses pinning on a particular app or Android version.
