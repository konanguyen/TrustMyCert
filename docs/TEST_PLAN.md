# TrustMyCert — Test plan

## A. Host unit tests (no device needed)

One command runs everything below (native tests, shell/JS syntax, CLI, CGI):

```bash
sh test/run_host_tests.sh   # expected: ALL HOST TESTS PASSED
```

Individual commands:

```bash
# test library: SHA-256 vectors + chain/pin taxonomy
g++ -std=c++17 -Wall -Wextra test/native_testlib/test_main.cpp \
  test/native_testlib/testlib.cpp -o /tmp/opencode/tmc_test && /tmp/opencode/tmc_test
# expected: 12x PASS + ALL TESTS PASSED

# discovery maps-parser (NDK-independent pure logic)
g++ -std=c++17 -Wall -Wextra -Itest/host_stubs -Inative \
  test/discovery_host_test.cpp native/discovery.cpp -o /tmp/opencode/tmc_disc \
  && /tmp/opencode/tmc_disc
# expected: DISCOVERY HOST TESTS PASSED

# runtime config parser, process matching, companion IPC framing
g++ -std=c++17 -Wall -Wextra -Itest/host_stubs -Inative \
  test/runtime_config_host_test.cpp native/runtime_config.cpp \
  -o /tmp/opencode/tmc_runtime && /tmp/opencode/tmc_runtime
# expected: RUNTIME CONFIG HOST TESTS PASSED

# CLI (TMC_CONFIG points at a scratch file)
TMC_CONFIG=/tmp/opencode/tmc_test.conf sh module/bin/tmc add com.example.app
TMC_CONFIG=/tmp/opencode/tmc_test.conf sh module/bin/tmc list
TMC_CONFIG=/tmp/opencode/tmc_test.conf sh module/bin/tmc validate
# expected: added / enabled=1 + target=com.example.app / ok: ... (1 targets)

# module log tail (TMC_LOGCAT is a host test shim)
TMC_LOGCAT=/tmp/opencode/fake-logcat sh module/bin/tmc logs 20
# expected: the last N TrustMyCert lines from logcat

# CGI whitelist (host sh; wrapper runs the CLI with the host shell)
printf 'secret\n' > /tmp/opencode/tmc.token
printf '#!/bin/sh\nexec sh %s/module/bin/tmc "$@"\n' "$PWD" > /tmp/opencode/tmc_wrap
chmod +x /tmp/opencode/tmc_wrap
printf 'list' | REQUEST_METHOD=POST QUERY_STRING='token=secret' \
  TMC_CONFIG=/tmp/opencode/tmc_test.conf TMC_UI_TOKEN_FILE=/tmp/opencode/tmc.token \
  TMC_CGI_ERR_FILE=/tmp/opencode/tmc.cgi.err TMC_BIN=/tmp/opencode/tmc_wrap \
  sh module/webroot/cgi-bin/api
# expected JSON {"errno":0,...}; wrong token -> Status: 403 + invalid token
```

The controlled TLS server:

```bash
# controlled TLS server (needs test/gen_certs.sh first)
bash test/gen_certs.sh
python3 test/server.py &
curl -k https://127.0.0.1:8443/   # expect: trustmycert-test-ok
```

## B. Module build (done locally)

```bash
export ANDROID_HOME=$HOME/Android/Sdk

TMC_VERSION=1.1.0 python3 build.py zip
# packages BOTH channels:
# -> release/TrustMyCert-1.1.0-<hash>.zip
#    product: only error logs compiled in (version=1.1.0)
# -> release/TrustMyCert-1.1.0-debug-<hash>.zip
#    debug: debug/info/warning/error logs compiled in (version=1.1.0-debug)
```

One release ships both channels; the debug zip carries `-debug` in its file
name. The GitHub release workflow (`.github/workflows/release.yml`) is driven
by a plain `vX.Y.Z` tag and publishes both zips in a single release.

Verified 2026-11-14: both channels built locally with all ABIs linked
(`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`, `riscv64`):

- `release/TrustMyCert-1.1.0-674157f.zip` — product (`version=1.1.0`,
  `versionCode=9999`); `strings` contains only the `[TrustMyCert]` error
  lines, no info/warn diagnostics.
- `release/TrustMyCert-1.1.0-debug-674157f.zip` — debug
  (`version=1.1.0-debug`); `strings` contains the info/warn/error
  diagnostics.

Both libraries export `zygisk_module_entry` and `zygisk_companion_entry`
(`nm -D`).

Published release verification (2026-11-14): GitHub Actions run
[43516215096](https://github.com/konanguyen/TrustMyCert/actions/runs/43516215096)
succeeded for tag `v1.1.0` (commit `aa9c3aa`) and published a normal release at
<https://github.com/konanguyen/TrustMyCert/releases/tag/v1.1.0> with both
module zips plus both symbols zips. The two module zips were downloaded and
inspected:

- `TrustMyCert-1.1.0-aa9c3aa.zip` — `version=1.1.0`, `versionCode=10999`,
  five ABIs, both Zygisk exports, no info/warn strings.
- `TrustMyCert-1.1.0-debug-aa9c3aa.zip` — `version=1.1.0-debug`,
  `versionCode=10000`, five ABIs, both Zygisk exports, info/warn strings
  present.

The local artifacts above were built from commit `674157f`; the release
assets were built by CI from the tagged commit `aa9c3aa`. See the status
ledger below.

## C. On-device test (requires rooted device + Zygisk)

1. Flash: `python3 build.py flash --reboot` (or install the zip from the
   Magisk/KernelSU app). Enable the module + Zygisk, reboot.
2. Add the stub package to the runtime allowlist (WebUI or CLI):

   ```bash
   adb shell su -c '/data/adb/modules/trustmycert/bin/tmc add com.example.trustmycert.test'
   adb shell su -c '/data/adb/modules/trustmycert/bin/tmc list'
   ```

3. Build the stub APK: open `test/app_stub` in Android Studio (package
   `com.example.trustmycert.test`), build its `libtestverify.so` from
   `test/native_testlib` via the stub's CMake, install with `adb install`.
   The stub has four buttons: Chain-OK, Chain-bad-CA, CertPin-match,
   CertPin-mismatch, SPKI-match, SPKI-mismatch (each calls the JNI bridge).
4. `adb logcat -c`, force-stop and launch the test app, tap each case.
5. Filter: `adb logcat -s TrustMyCert`.

### Target-selection tests (must pass before hook tests)

| Test | Action | Expected |
|---|---|---|
| Default deny | Do not add any target; launch the stub | `enabled=1 targets=0`; no `Target process selected` for the stub |
| Allowlist | `tmc add <pkg>`; force-stop + relaunch | `Target process selected: <pkg>` |
| Non-target | Launch any other app | No instrumentation; skipped line at debug priority |
| `system_server` | Reboot | `Target process skipped: system_server (never instrumented)` |
| Disable | `tmc set enabled 0`; force-stop + relaunch target | `Target process skipped: ... (module disabled by runtime config)` |
| Subprocess off | Target has `:remote` process; leave `match_subprocesses=0` | `:remote` is not instrumented |
| Subprocess on | `tmc set match_subprocesses 1`; relaunch | `:remote` is instrumented |
| Config persistence | Reboot | Target list and switches preserved |

### Expected log output

Launch (before any TLS):

```
[TrustMyCert] Module initialized (Zygisk API 4)
[TrustMyCert] Target process selected: com.example.trustmycert.test
[TrustMyCert] Hook installation successful: java/lang/Runtime.nativeLoad/*
[TrustMyCert] Target process specialized: com.example.trustmycert.test
[TrustMyCert] Diagnostic result: N mapped files enumerated
[TrustMyCert] TLS implementation identified: Conscrypt-native (...)
[TrustMyCert] Pinning mechanism: impl=...; chain-validation=present; ...
[TrustMyCert] Hook commit: registered=R committed=yes
[TrustMyCert] Hook installation successful: X509_verify_cert origs>=1
```

Per network handshake (observe-only, capped at 16 lines):

```
[TrustMyCert] Hook X509_verify_cert -> 1        (test server, trusted)
[TrustMyCert] Hook SSL_get_verify_result -> 0
```

### Ground-truth matrix (test app)

| Case | Chain | Pin | Expected app result | Expected module log |
|---|---|---|---|---|
| Chain-OK, no pin | ok | n/a | success | verify -> 1 / 0 |
| Chain bad CA | unknown-CA | n/a | TLS fail (CA) | verify -> 0 / error != 0 |
| CertPin match | ok | match | success | + certpin match (app log) |
| CertPin mismatch | ok | mismatch | app rejects (PIN) | native verify still 1/0 — proves pin ≠ CA failure |
| SPKI match/mismatch | ok | match/mismatch | success / app rejects | same as above |

The key assertion: **pin-mismatch cases fail in the app while native
`X509_verify_cert` still reports success** — demonstrating that pin policy
lives above chain validation (AGENTS.md §3C).

### Failure cases

- `no known TLS symbols resolved` on the test app → methodology broken,
  investigate before any bypass test.
- Bypass test (explicit opt-in): set BOTH `kEnableBypass=true` and
  `kAllowRuntimeBypass=true`, rebuild, reflash, then
  `tmc set bypass 1`; repeat the bad-CA case → handshake now succeeds; log
  shows `TEST-ONLY bypass compiled in` + `BYPASS active` lines. **Set
  `bypass=0` and rebuild with both flags false afterwards.**
- With the default build, `tmc set bypass 1` must leave behavior unchanged and
  log `Runtime bypass requested but build disallows it`.

## D. Status ledger

| Item | Status |
|---|---|
| Discovery + fingerprint + reporting | implemented, NDK-built (all ABIs), host-tested (parser) |
| JNI `nativeLoad` monitor | implemented, NDK-built, **unverified on device** |
| PLT observe-only wrappers | implemented, NDK-built, **unverified on device** |
| Test-only bypass | implemented (failure-only override), default OFF, **unverified on device** |
| Flutter stripped-carrier reporting | implemented, NDK-built, host-tested (basename rules) |
| Proxygen 3rd mangling variant + Liger | implemented, NDK-built, host-tested |
| Runtime target config (parser/matching/IPC framing) | implemented, NDK-built, host-tested |
| Root companion config fetch | implemented, NDK-built, **unverified on device** |
| WebUI (`webroot/`) | implemented, shell/JS syntax-checked, HTTP fallback host-tested, **unverified in a real root manager** |
| WebUI **Debug info** log panel | implemented, JS syntax-checked and `logs` CGI path host-tested, **unverified in a real root manager** |
| `tmc` CLI | implemented, host-tested (add/remove/set/list/validate/logs), **unverified on device** |
| Debug/product build channels (`DEBUG=0/1`, naming, `versionCode`) | implemented; both zips built and inspected locally and from the `v1.1.0` release assets |
| Tag-driven GitHub release workflow | implemented; run 43516215096 succeeded and published `v1.1.0` (both channels + symbols) |
| Installer packaging (`customize.sh`, perms, config seed) | implemented, full-zip build, **unverified on device** |
| Test lib + server + APK stub | implemented, host-verified (lib+server); APK assembly needs Android Studio + device |
| On-device log confirmation | **not done** — no rooted device available |
