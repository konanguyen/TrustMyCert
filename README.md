# TrustMyCert

Zygisk-based Android security testing module for researching and testing
SSL/TLS certificate pinning inside **native** libraries. For authorized
testing of apps you own or are explicitly permitted to assess — nothing here
weakens TLS unless you deliberately enable the test-only bypass.

## What it does

- **Discovery:** enumerates loaded `.so` files from `/proc/self/maps`,
  probes TLS exported symbols (`dlopen(RTLD_NOLOAD)` — never loads new code),
  fingerprints the TLS implementation (BoringSSL / OpenSSL-compatible /
  Conscrypt-native / Cronet / mbed TLS / wolfSSL / GnuTLS / custom-static).
- **Scoped instrumentation (observe-only by default):** JNI hook on
  `Runtime.nativeLoad` (load monitor) + PLT hooks on `SSL_get_verify_result`,
  `X509_verify_cert`, `SSL_CTX_set_verify` with rate-limited logging and
  exact-orig forwarding.
- **Diagnostics:** every line carries the `[TrustMyCert]` marker on tag
  `TrustMyCert`. Bypass builds identify themselves in logcat.
- **Safety:** allowlisted target apps only, `system_server` never touched,
  fail-safe hook installation, no secrets in logs, bypass behind
  `kEnableBypass=false` default.

## Build

```bash
export ANDROID_HOME=$HOME/Android/Sdk   # NDK 29.0.14206865, platform android-26
python3 build.py config [-a abi]        # generate compile_commands.json
python3 build.py zip                    # module zip -> release/
python3 build.py flash [--reboot]       # build + install via root (Magisk/KSU/APatch)
```

Requires: Android SDK + NDK `29.0.14206865`, `cmake`, `ninja`, `python3`,
`adb`. Zygisk API v4, ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`,
`riscv64`.

## Docs

- `docs/RESEARCH.md` — native TLS/pinning research + symbol reference + hooking trade-offs
- `docs/CONFIG.md` — target selection, flags, bypass policy, support matrix
- `docs/TEST_PLAN.md` — host tests, on-device procedure, expected logs, status ledger
- `docs/DEBUG.md` — log filtering, failure table
- `test/` — native test lib (chain/pin/SPKI, JNI bridge), test TLS server, cert scripts, APK stub

## Logs

```bash
adb logcat -s TrustMyCert
adb logcat | grep -F '[TrustMyCert]'
```

## Status

Implemented + NDK-built (all ABIs) + host-tested (parser, SHA-256/pin
taxonomy). On-device hook/bypass verification pending a rooted test device —
see `docs/TEST_PLAN.md` section D.

## See also

- Template origin: https://github.com/topjohnwu/zygisk-module-sample (Zygisk API v4 header kept unmodified in `native/zygisk.hpp`)
- Development: LLVM clangd, VSCode + Clangd plugin, Android NDK, CMake
