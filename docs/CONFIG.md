# TrustMyCert — Configuration

Two layers:

1. **Build-time limits and master switches** in `native/config.h` (rebuilt into
   the module).
2. **Runtime target selection and diagnostics switches** in
   `/data/adb/trustmycert/config.conf`, managed by the WebUI or `bin/tmc`.

Runtime configuration is documented in detail in `docs/WEBUI.md`.

## Build-time options

| Flag | Default | Effect |
|---|---|---|
| `kEnableDiscovery` | `true` | Enumerate `/proc/self/maps`, probe TLS symbols, log fingerprint report |
| `kEnableJniHooks` | `true` | Hook `Runtime.nativeLoad` as a library-load monitor |
| `kEnableNativeHooks` | `true` | PLT-hook `SSL_get_verify_result`, `X509_verify_cert`, `SSL_CTX_set_verify` (observe-only unless bypass is active) |
| `kVerbose` | `false` | Force verbose diagnostics regardless of runtime config |
| `kMaxHotPathLogs` | `16` | Cap on log lines from hot-path wrappers per process |
| `kMaxLibsLogged` | `64` | Cap on detailed library/symbol reports |
| **`kEnableBypass`** | **`false`** | **TEST-ONLY: compile the failure-only verification override. Alone it does nothing at runtime.** |
| **`kAllowRuntimeBypass`** | **`false`** | **Second gate: allow `bypass=1` in the runtime config to activate the override. Keep false in distributed builds.** |
| `kMaxTargets` (runtime) | `64` | Maximum allowlisted package names |
| `kMaxConfigBytes` (runtime) | `64 KiB` | Companion read cap |

All three must be true for the bypass to run:

```
kEnableBypass == true && kAllowRuntimeBypass == true && runtime bypass == 1
```

The effective verbose switch is `kVerbose || runtime verbose`.

## Selecting target apps

Do **not** edit a C++ array. Add targets at runtime:

```bash
TMC=/data/adb/modules/trustmycert/bin/tmc
$TMC add com.example.myapp
```

or use the WebUI. The module reads the list through the Zygisk root companion
in `preAppSpecialize` and instruments only matching processes. The default is
deny:

| Situation | Behavior |
|---|---|
| Config file missing | Companion returns zero bytes; no instrumentation |
| `enabled=0` | No instrumentation |
| Empty target list | No instrumentation |
| Process not listed | `DLCLOSE_MODULE_LIBRARY`, no hooks |
| `system_server` | Always rejected; `preServerSpecialize` opts out |
| Target listed | JNI load monitor + discovery + PLT hooks |
| `pkg:suffix` and `match_subprocesses=1` | Instrumented as a subprocess of the target |
| `pkg:suffix` and `match_subprocesses=0` | Skipped (default) |

Matching is exact and case-sensitive against `AppSpecializeArgs.nice_name`.
Package-name lookalikes (`com.example.app2`) never match.

## Enabling the test-only bypass (controlled tests only)

1. Use only against apps you own or are explicitly authorized to assess.
2. Use only with test certificates + a controlled test server (`test/`).
3. Build with both gates:

   ```cpp
   inline constexpr bool kEnableBypass = true;
   inline constexpr bool kAllowRuntimeBypass = true;
   ```

4. Enable it per device, only for the test window:

   ```bash
   $TMC set bypass 1
   ```

5. Run the test plan, then reset and rebuild:

   ```bash
   $TMC set bypass 0
   # revert both compile-time flags and reinstall the release build
   ```

Bypass semantics are failure-only: the wrapper calls the real function first
and replaces its result only when it indicates failure (`SSL_get_verify_result`
non-zero, `X509_verify_cert` != 1). Genuine successes pass through untouched, so
the behavioral delta versus normal validation is minimized. This is still a
TLS-weakening test feature and is never appropriate for real accounts or
production traffic.

The module logs a warning at startup when a bypass-capable build is loaded, and
another warning in each process where the bypass is actually active.

## Supported matrix

- Zygisk API v4 (`native/zygisk.hpp`, do not modify).
- Root companion support required for runtime config (Magisk Zygisk,
  KernelSU/APatch with a Zygisk implementation that implements the companion
  API).
- NDK `29.0.14206865`, `platform android-26` (min; `project-config.json`).
- ABIs built: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`, `riscv64`.
- Android 8.0+ expected (minSdk = platform level); API-level differences in
  JNI signatures are handled by trying known variants and skipping on
  mismatch — check logcat `Hook installation ...` lines on each new device.

## Known limitations

- Java-layer pinning (OkHttp `CertificatePinner`, `TrustManager` policy,
  Network Security Config) is out of scope — sibling modules own it. See
  `docs/REFERENCE-MODULES.md` for why the reference module's universal Java
  hooks are not replicated here.
- Stripped / statically linked / custom TLS: detected only if characteristic
  exports remain; otherwise reported inconclusive — confirm with the test app.
- Cronet/Chromium verifier: detection only, no hook.
- Libraries loaded after specialization: reported, not PLT-hooked (commit
  window closed — Zygisk API limitation).
- Several TLS builds in one process: forwarding falls back to `RTLD_DEFAULT`
  with a warning (see `docs/RESEARCH.md` §4).
- Runtime config is read once per process start; changes require an app
  restart (force-stop).
- Companion failure is fail-closed: if config cannot be fetched, nothing is
  instrumented.
- Zygisk maps the module library briefly in every specialized process before
  target selection; non-targets receive `DLCLOSE_MODULE_LIBRARY`. Zygisk/root
  detection by anti-cheat is outside this module's control.
- `tmc` writes are atomic but not locked; avoid concurrent UI/CLI writers.
