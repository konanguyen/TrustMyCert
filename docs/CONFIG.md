# TrustMyCert — Configuration

All configuration is compile-time in `native/config.h` (rebuilt into the
module; no root companion or config-file IPC is needed).

## Options

| Flag | Default | Effect |
|---|---|---|
| `kEnableDiscovery` | `true` | Enumerate `/proc/self/maps`, probe TLS symbols, log fingerprint report |
| `kEnableJniHooks` | `true` | Hook `Runtime.nativeLoad` as a library-load monitor |
| `kEnableNativeHooks` | `true` | PLT-hook `SSL_get_verify_result`, `X509_verify_cert`, `SSL_CTX_set_verify` (observe-only) |
| `kVerbose` | `false` | Extra per-library / per-symbol lines |
| `kMaxHotPathLogs` | `16` | Cap on log lines from hot-path wrappers per process |
| **`kEnableBypass`** | **`false`** | **TEST-ONLY: force verification success. Weakens TLS process-wide. Never ship enabled.** |

## Selecting target apps

Edit `kTargetApps` in `native/config.h` — the module instruments **only**
processes whose `nice_name` matches. `kTestAppPrefix` additionally covers
sibling harnesses. Everything else (including `system_server`, which is
explicitly opted out in `preServerSpecialize`) gets `DLCLOSE_MODULE_LIBRARY`
and zero instrumentation.

```cpp
inline constexpr const char *kTargetApps[] = {
    "com.example.trustmycert.test",   // <-- your authorized test app
};
```

Rebuild after editing: `python3 build.py zip`.

## Enabling the test-only bypass (controlled tests only)

1. Use only against apps you own or are explicitly authorized to assess.
2. Use only with test certificates + controlled test server (`test/`).
3. Set `kEnableBypass = true`, rebuild, install, run the test plan, then
   revert. The module logs `TEST-ONLY bypass is ENABLED` at startup so a
   bypass build is always identifiable in logcat.

## Supported matrix

- Zygisk API v4 (`native/zygisk.hpp`, do not modify).
- NDK `29.0.14206865`, `platform android-26` (min; `project-config.json`).
- ABIs built: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`, `riscv64`.
- Android 8.0+ expected (minSdk = platform level); API-level differences in
  JNI signatures are handled by trying known variants and skipping on
  mismatch — check logcat `Hook installation ...` lines on each new device.

## Known limitations

- Java-layer pinning (OkHttp `CertificatePinner`, `TrustManager` policy,
  Network Security Config) is out of scope — sibling modules own it.
- Stripped / statically linked / custom TLS: detected only if characteristic
  exports remain; otherwise reported inconclusive — confirm with the test app.
- Cronet/Chromium verifier: detection only, no hook.
- Libraries loaded after specialization: reported, not PLT-hooked (commit
  window closed — Zygisk API limitation).
- Several TLS builds in one process: forwarding falls back to `RTLD_DEFAULT`
  with a warning (see `docs/RESEARCH.md` §4).
