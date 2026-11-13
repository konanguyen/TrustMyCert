# TrustMyCert

Zygisk module for researching and testing SSL/TLS certificate pinning
implemented inside **native** Android libraries (`.so` files).

For authorized security testing only — apps you own or are explicitly
permitted to assess. The module is observe-only by default and weakens
nothing unless you deliberately enable the test-only bypass.

## Features

- **Native library discovery** — enumerates loaded `.so` files from
  `/proc/self/maps` (name, arch, mappings) without trusting filenames alone.
- **TLS fingerprinting** — probes exported symbols with
  `dlopen(path, RTLD_NOLOAD)` (never loads new code) and identifies
  BoringSSL, OpenSSL-compatible, Conscrypt-native, Cronet, mbed TLS,
  wolfSSL, GnuTLS, or custom/statically-linked stacks. Inconclusive results
  are reported as such, never guessed.
- **Runtime target allowlist (no global hooking)** — targets are chosen at
  runtime from `/data/adb/trustmycert/config.conf` through a root companion.
  Missing/empty config instruments nothing. This keeps instrumentation out of
  unrelated apps, games with anti-cheat, banking RASP and `system_server`.
- **WebUI + CLI** — KernelSU/APatch WebUI (`webroot/`), a Magisk action-button
  HTTP fallback, and a POSIX `bin/tmc` CLI for the same config. Add/remove
  target apps, toggle subprocess matching and verbose diagnostics.
- **Scoped instrumentation** — JNI hook on `Runtime.nativeLoad` (library-load
  monitor) plus PLT hooks on `SSL_get_verify_result`, `X509_verify_cert` and
  `SSL_CTX_set_verify`. Wrappers log (rate-limited) and forward to the exact
  original function.
- **Searchable diagnostics** — every log line carries the `[TrustMyCert]`
  marker on the `TrustMyCert` tag, with process name, library and symbol
  context. No private keys, tokens, cookies or payloads are ever logged.
- **Safety first** — only explicitly allowlisted test apps are instrumented;
  `system_server` and all other processes are skipped and the library is
  `dlclose`d there. Hook failures never crash the target app. Any
  behavior-changing certificate override stays behind three gates:
  `kEnableBypass`, `kAllowRuntimeBypass`, and the runtime `bypass=1` switch
  (all default off).

## Requirements

| Tool | Version / note |
|---|---|
| Android SDK + NDK | NDK `29.0.14206865`, platform `android-26` (Android 8.0+) |
| `ANDROID_HOME` (or `ANDROID_SDK_ROOT`) | must point at the SDK |
| `cmake`, `ninja`, `python3`, `git`, `adb` | build + deploy |
| Rooted device/emulator + Zygisk | Magisk, KernelSU/ZygiskNext or APatch; module install only |

Setup example (Ubuntu):

```bash
sudo apt install ninja-build
# install Android cmdline-tools, then:
sdkmanager "platforms;android-26" "ndk;29.0.14206865"
export ANDROID_HOME=$HOME/Android/Sdk
```

## Build, install, run

```bash
python3 build.py config [-a abi]   # compile_commands.json for clangd
python3 build.py build [-a abi]    # build .so for one ABI
python3 build.py zip               # full module zip (all ABIs) -> release/
python3 build.py flash [--reboot]  # build + install onto device via root
```

Then:

1. Enable the module (and Zygisk) in the Magisk/KernelSU/APatch app, reboot.
2. Open the module WebUI (KernelSU/APatch) or tap the module Action button
   (Magisk) and add your authorized test app, e.g. `com.example.myapp`.
   Equivalent CLI:

   ```bash
   adb shell su -c '/data/adb/modules/trustmycert/bin/tmc add com.example.myapp'
   ```

3. Force-stop and launch the test app, then watch logcat:

```bash
adb logcat -s TrustMyCert
adb logcat | grep -F '[TrustMyCert]'
```

Expected sequence: `Runtime config: loaded ...` → `Target process selected` →
`TLS implementation identified` → `Pinning mechanism: ...` → hook commit
results. See `docs/WEBUI.md` for target management, `docs/DEBUG.md` for the
full log reference and failure table.

## Project structure

```
native/               module source (trustmycert.cpp, discovery.*, hooks.*, runtime_config.*)
  zygisk.hpp          Zygisk API v4 header (do not modify)
template/             Magisk module packaging (module.prop, customize.sh, ...)
  bin/tmc             root CLI for the runtime target allowlist
  webroot/            KernelSU/APatch WebUI + CGI fallback for Magisk
  action.sh           Magisk action button: local WebUI server
docs/
  RESEARCH.md         native TLS/pinning research, symbol reference, hook trade-offs
  CONFIG.md           build flags, runtime config, bypass policy, support matrix
  WEBUI.md            WebUI, CLI, config format, companion IPC, troubleshooting
  REFERENCE-MODULES.md analysis of m0szy/Zygisk-SSL-Unpinning and design delta
  TEST_PLAN.md        host tests, on-device procedure, expected logs
  DEBUG.md            debugging guide
test/
  native_testlib/     controlled JNI test lib (chain / cert-pin / SPKI-pin)
  app_stub/           minimal test APK harness source
  server.py           controlled TLS test server (test certs only)
  gen_certs.sh        test-only certificate generator
  runtime_config_host_test.cpp  parser/matching/companion protocol tests
build.py              CMake/NDK build, packaging, flash orchestration
```

## Controlled testing

`test/` provides a full ground-truth harness: a native library exercising
standard chain validation, certificate pin and SPKI pin (success + failure
cases), a local TLS server and short-lived test certificates — so CA
validation failures can be told apart from explicit pin mismatches. Follow
`docs/TEST_PLAN.md`.

## Status & limitations

- ✅ Implemented, NDK-built for `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`,
  `riscv64`; host unit tests pass (maps parser, SHA-256/pin taxonomy, runtime
  config parser/matching/companion protocol).
- ✅ Runtime target allowlist + WebUI/CLI implemented; installer packaging is
  covered by a full-zip build.
- ⏳ On-device hook/bypass/WebUI verification pending a rooted test device.
- Java-layer pinning and the Chromium/Cronet verifier are out of scope
  (sibling modules own the Java layer). See `docs/CONFIG.md` and
  `docs/TEST_PLAN.md` §D.

## Origin

Built on the Zygisk module template (Zygisk API v4). The template's
`example.cpp` was replaced; the root companion API is now used narrowly to
serve one fixed config file (no arbitrary root operations). See
`docs/REFERENCE-MODULES.md` for the comparison with
`m0szy/Zygisk-SSL-Unpinning`, and
<https://github.com/topjohnwu/zygisk-module-sample>.
