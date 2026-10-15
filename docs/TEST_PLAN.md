# TrustMyCert — Test plan

## A. Host unit tests (no device needed)

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

```bash
# controlled TLS server (needs test/gen_certs.sh first)
bash test/gen_certs.sh
python3 test/server.py &
curl -k https://127.0.0.1:8443/   # expect: trustmycert-test-ok
```

## B. Module build (done locally)

```bash
export ANDROID_HOME=$HOME/Android/Sdk
python3 build.py zip   # -> release/TrustMyCert-1.0-*-debug.zip (all 5 ABIs)
```

Verified 2026-10-16: `release/TrustMyCert-1.0-1-cf5be86-debug.zip`, all ABIs
linked (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`, `riscv64`).

## C. On-device test (requires rooted device + Zygisk)

1. Flash: `python3 build.py flash --reboot` (or install the zip from the
   Magisk/KernelSU app). Enable the module + Zygisk, reboot.
2. Build the stub APK: open `test/app_stub` in Android Studio (package
   `com.example.trustmycert.test`), build its `libtestverify.so` from
   `test/native_testlib` via the stub's CMake, install with `adb install`.
   The stub has four buttons: Chain-OK, Chain-bad-CA, CertPin-match,
   CertPin-mismatch, SPKI-match, SPKI-mismatch (each calls the JNI bridge).
3. `adb logcat -c`, launch the test app, tap each case.
4. Filter: `adb logcat -s TrustMyCert`.

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
- Bypass test (explicit opt-in): set `kEnableBypass=true`, rebuild, reflash,
  repeat bad-CA case → handshake now succeeds; log shows
  `TEST-ONLY bypass is ENABLED` + `BYPASS active` lines. **Revert afterwards.**

## D. Status ledger

| Item | Status |
|---|---|
| Discovery + fingerprint + reporting | implemented, NDK-built (all ABIs), host-tested (parser) |
| JNI `nativeLoad` monitor | implemented, NDK-built, **unverified on device** |
| PLT observe-only wrappers | implemented, NDK-built, **unverified on device** |
| Test-only bypass | implemented, default OFF, **unverified on device** |
| Test lib + server + APK stub | implemented, host-verified (lib+server); APK assembly needs Android Studio + device |
| On-device log confirmation | **not done** — no rooted device available |
