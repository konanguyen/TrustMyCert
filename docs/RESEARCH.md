# TrustMyCert — Native TLS & Pinning Research

Source-backed reference for the TrustMyCert Zygisk module. All symbol names
below were checked against the cited public sources. Anything marked
**version-dependent** must be re-confirmed on the target device before a hook
is written against it (procedure in §7).

Scope rule (AGENTS.md §3C): normal CA chain validation is **not** pinning.
A finding is reported as *pinning* only when an explicit expected-credential
comparison (certificate, SPKI hash, or public-key equality) is observed, e.g.
via the controlled test app. Symbol presence alone yields the classification
`pinning=undetermined-from-symbols`.

## 1. Java / framework mechanisms

| Mechanism | Where | Relevance to native TLS |
|---|---|---|
| Network Security Config (+ `<pin-set>`) | `android:networkSecurityConfig`, enforced by `TrustManagerImpl` | Java-side policy; native libs bypass it entirely unless they call back into the framework verifier |
| `X509TrustManager` / custom TrustManagers | App code, `javax.net.ssl` | Java-only, overridable per-app |
| `TrustManagerImpl` + Conscrypt | AOSP `external/conscrypt` (`TrustManagerImpl.java` → `NativeCrypto` JNI) | Bridge: Java policy, native crypto. `checkTrustedRecursive` calls native verify; observable at the native verify boundary |
| `SSLContext` / `SSLSocket` (JSSE) | `com.android.org.conscrypt` | Java API; native work happens in Conscrypt native code |
| OkHttp `CertificatePinner` | `okhttp3.CertificatePinner.check()` (pure Java, SPKI `sha256/` pins) | Java-only. Zygisk API v4 **cannot** hook pure-Java methods — no ART instrumentation. Observed indirectly via the native verify calls it triggers (or doesn't) |
| WebView / Chromium cert validation | `net/cert` (`CertVerifyProc`, `CTVerifier`) | Native C++, but inside the WebView/Chromium binary; symbols usually stripped, no stable public entry points for PLT hooking |
| JNI bridges | `org.conscrypt.NativeCrypto` / `com.android.org.conscrypt.NativeCrypto` native methods | The Java→native transition point. Native-method hooks via `hookJniNativeMethods` work **only** here (registered natives), never on plain Java methods |

References: [Conscrypt repo](https://github.com/google/conscrypt) (`common/src/main/java/org/conscrypt/TrustManagerImpl.java`,
`.../NativeCrypto.java`); [OkHttp CertificatePinner](https://github.com/square/okhttp/blob/master/okhttp/src/main/kotlin/okhttp3/CertificatePinner.kt);
[Android Network Security Config](https://developer.android.com/training/articles/security-config).

## 2. Native TLS libraries

### 2.1 OpenSSL (1.1.x / 3.x)
- **Presence:** common in apps bundling their own TLS (games, fintech SDKs, IoT apps); also the ancestor API that BoringSSL mirrors.
- **Identification:** `libssl.so` / `libcrypto.so` in the APK (`lib/<abi>/`), or `libssl*.so` mappings; exported `SSL_*` / `X509_*` symbols.
- **Key symbols (stable C ABI, public headers `openssl/ssl.h`, `openssl/x509_vfy.h`):**
  `SSL_CTX_set_verify(ctx, mode, callback)`, `SSL_set_verify`,
  `SSL_CTX_set_cert_verify_callback` (app-supplied chain validator),
  `X509_verify_cert(ctx)` → `1` success / `0` fail / `<0` internal error,
  `SSL_get_verify_result(ssl)` → `long` (`X509_V_OK == 0` on success),
  `X509_STORE_CTX_get_error`.
- **Pinning shape:** usually *custom* — an app sets a verify callback or post-handshake compares the peer cert/SPKI against an embedded value. Stock `X509_verify_cert` alone is CA validation, not pinning.

References: [openssl docs — SSL_CTX_set_verify](https://www.openssl.org/docs/man3.2/man3/SSL_CTX_set_verify.html),
[X509_verify_cert](https://www.openssl.org/docs/man3.2/man3/X509_verify_cert.html),
[source](https://github.com/openssl/openssl).

### 2.2 BoringSSL (system TLS on Android)
- **Presence:** Android platform TLS (`/system/lib64/libssl.so`, `libcrypto.so`); many apps link it statically.
- **Identification:** same `libssl/libcrypto` basenames as OpenSSL — **filenames do not distinguish them**. Distinguisher: BoringSSL-only exports
  `SSL_CTX_set_custom_verify` / `SSL_set_custom_verify` (custom verify callback with async support), declared in BoringSSL's `ssl.h`. TrustMyCert fingerprints on exactly this.
- **Key symbols:** `SSL_get_verify_result`, `X509_verify_cert` (same semantics as OpenSSL), plus the `*_custom_verify` pair.
- **Caveats:** version skew between AOSP releases; static linking + stripping removes the distinguisher → reported as `OpenSSL-compatible` or `custom-or-static`, never asserted.

References: [BoringSSL ssl.h](https://github.com/google/boringssl/blob/master/include/openssl/ssl.h),
[`SSL_CTX_set_custom_verify`](https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers/ssl.h.html).

### 2.3 Conscrypt native components
- **Presence:** every app using framework TLS (`HttpsURLConnection`, `SSLSocket`) loads platform Conscrypt (`libconscrypt_jni`).
- **Identification:** `libconscrypt_*` mappings; JNI natives under `NativeCrypto_*` symbol prefixes.
- **Hook surface:** Java policy (`TrustManagerImpl`) + native crypto. TrustMyCert observes the shared native verify boundary (`X509_verify_cert`) rather than chasing versioned `NativeCrypto` JNI signatures.
- **No companion needed:** Conscrypt runs in-app; observing it needs no superuser IPC, which is why TrustMyCert registers no root companion.

References: [Conscrypt](https://github.com/google/conscrypt) (`platform/src/main/native`).

### 2.4 Chromium network stack / Cronet
- **Presence:** apps embedding Cronet (`org.chromium.net`) ship `libcronet.*.so`.
- **Identification:** `libc dekronet` basename + `Cronet_Engine_Create` / `Cronet_UrlRequest_Create` exports. The cert verifier (`CertVerifyProc`, `CTVerifier` in Chromium `src/net/cert`) is internal, stripped, no stable PLT target.
- **Verdict:** detection supported, generic hook **unsupported** — documented limitation, needs per-build reverse engineering.

References: [Cronet](https://developer.android.com/guide/topics/connectivity/cronet),
[Chromium net/cert](https://chromium.googlesource.com/chromium/src/+/main/net/cert/).

### 2.5 mbed TLS
- **Presence:** IoT/VPN/media SDKs; small footprint, often statically linked.
- **Identification:** `libmbedtls*` / `libmbedcrypto*` basenames; `mbedtls_*` symbol prefix (rarely stripped because apps call the public API dynamically).
- **Key symbols (`ssl.h`, `x509_crt.h`):** `mbedtls_ssl_set_hostname` (SNI — needed before verification),
  `mbedtls_x509_crt_verify(crt, trust_ca, crl, cn, &flags, f_vrfy, p_vrfy)` → `0` success,
  `mbedtls_ssl_get_verify_result` → bitmask flags (note: **not** a single OK constant, unlike `X509_V_OK`).
- **Pinning shape:** callback `f_vrfy` or manual post-verify SPKI compare.

References: [mbed TLS](https://github.com/Mbed-TLS/mbedtls) (`include/mbedtls/ssl.h`, `x509_crt.h`).

### 2.6 wolfSSL
- **Presence:** embedded/automotive SDKs, some VPN clients.
- **Identification:** `libwolfssl*` basename; `wolfSSL_*` prefix (older builds: `CyaSSL_*` — **version-dependent**).
- **Key symbols (`wolfssl/ssl.h`):** `wolfSSL_CTX_set_verify`, `wolfSSL_get_verify_result`, `wolfSSL_X509_verify_cert`.

References: [wolfSSL](https://github.com/wolfSSL/wolfssl) (`wolfssl/ssl.h`).

### 2.7 GnuTLS / custom stacks
- **Presence:** rare on Android (license + size); listed for completeness.
- **Key symbols:** `gnutls_certificate_verify_peers2`, `gnutls_x509_crt_verify`.
- **Custom/statically-linked TLS:** no exports; identification requires string/TLS-constant fingerprinting and per-build RE — out of scope for the MVP; the controlled test app covers the methodology instead.

References: [GnuTLS](https://www.gnutls.org/manual/).

## 3. Pinning types (recognition guide)

| Type | What is compared | How to recognize in assessment |
|---|---|---|
| Full-certificate pin | DER bytes / hash of leaf cert | Exact-match compare against embedded blob; breaks on every cert rotation |
| SPKI pin | SHA-256 of SubjectPublicKeyInfo (OkHttp `sha256/...`) | Base64 `sha256/` constants; digest-verify helpers (`EVP_DigestVerify`, `mbedtls_pk_verify`, `RSA_verify`) near the verify path |
| Pubkey-hash pin | Hash of public key (variant of SPKI) | Same as SPKI, different hash input |
| Chain / intermediate pin | Issuer/intermediate identity | Custom callback inspecting chain depth > 0 |
| Custom verify callback | App function returning accept/reject | `SSL_CTX_set_verify` / `SSL_CTX_set_custom_verify` / `mbedtls` `f_vrfy` registration with a non-null function pointer |
| Trust-store vs pin | System CA set vs embedded expected value | Failure message/behavior differs: unknown-CA vs known-CA-but-unexpected-key (the test app exercises both separately) |
| Java vs native validation | Stack frames: `TrustManagerImpl/CertificatePinner` vs `.so` verify symbols | `adb logcat -s TrustMyCert` shows which native verify functions fire during a handshake |

## 4. Hooking architecture (trade-offs, decided)

| Strategy | Verdict |
|---|---|
| Zygisk lifecycle (`pre/postAppSpecialize`) | Used. All registration/commit inside the specialize window; `Api` dies after it |
| JNI native-method hooks (`hookJniNativeMethods`) | Used for `Runtime.nativeLoad` (stable, exact signatures, load monitor). **Not** usable on pure-Java pinning (`CertificatePinner.check`, `TrustManagerImpl.checkTrusted`) — ART limitation |
| Exported-symbol PLT hooks (`pltHookRegister/Commit`) | Used for `SSL_get_verify_result`, `X509_verify_cert`, `SSL_CTX_set_verify` (stable C ABI). Per-(lib,symbol) orig slots; single-orig fast path, `RTLD_DEFAULT` fallback with warning when several TLS builds coexist |
| Internal-function / stripped-symbol hooks | Not in MVP: needs per-build offsets, fragile across releases |
| Inline hooking / PLT/GOT by hand | Rejected: Zygisk already provides PLT hooking with correct cache handling; hand-rolled remapping adds crash risk for no MVP benefit |
| Dobby / ShadowHook | Evaluated, **not vendored**: extra license/build/ABI surface; incompatible-without-verification on this template's NDK matrix. Revisit only with a per-ABI compatibility table |
| Late-loaded libraries | Reported (discovery rescan on `nativeLoad`), **not** PLT-hooked: commit window is closed post-specialization (API limitation, logged as diagnostic) |
| Behavior-changing bypass | Implemented **only** behind `config::kEnableBypass=false` default; enabling weakens TLS process-wide — test-only, see `docs/CONFIG.md` |

Per-hook safety contract (`native/hooks.cpp`): exact-signature wrappers only;
null-orig never called; hot-path logging capped at `kMaxHotPathLogs`;
no secrets/payloads logged (results and pointers only); mutex only on
slow paths, atomics on hot paths.

## 5. Companion / IPC

None. The template demoed a root companion (`example.cpp`), but TrustMyCert
performs no superuser operation (config is compiled in, logs go through
logcat), so no companion is registered. If a future feature needs root
(e.g. reading another app's config), add `REGISTER_ZYGISK_COMPANION` then —
with a threat model, not before.

## 6. Symbol reference (what TrustMyCert probes)

| Symbol | Library family | Meaning when present |
|---|---|---|
| `SSL_get_verify_result` | OpenSSL/BoringSSL-compatible | Chain-result query path exists |
| `X509_verify_cert` | OpenSSL/BoringSSL-compatible | Central chain validator present |
| `SSL_CTX_set_verify` | OpenSSL/BoringSSL-compatible | App can install custom verify callbacks |
| `SSL_CTX_set_cert_verify_callback` | OpenSSL ≥1.0.2 style | App-supplied chain validator API |
| `SSL_CTX_set_custom_verify` / `SSL_set_custom_verify` | **BoringSSL only** | BoringSSL distinguisher |
| `EVP_DigestVerify`, `RSA_verify` | OpenSSL/BoringSSL crypto | Primitives usable for SPKI/hash-pin compares |
| `mbedtls_ssl_get_verify_result`, `mbedtls_x509_crt_verify`, `mbedtls_ssl_set_hostname` | mbed TLS | mbed TLS verify path |
| `mbedtls_pk_verify` | mbed TLS crypto | Pubkey-verify helper (SPKI-pin capable) |
| `wolfSSL_CTX_set_verify`, `wolfSSL_get_verify_result`, `wolfSSL_X509_verify_cert` | wolfSSL | wolfSSL verify path |
| `gnutls_certificate_verify_peers2`, `gnutls_x509_crt_verify` | GnuTLS | GnuTLS verify path |
| `Cronet_Engine_Create`, `Cronet_UrlRequest_Create` | Cronet | Chromium stack embedded (detect-only) |

## 7. Confirming a version-dependent signature on-device (procedure)

1. `adb shell pm path <test-app>` → `adb pull` the APK; `unzip -l` for bundled `.so`.
2. `adb shell grep -a -o -E 'SSL_do_handshake|nativeLoad|CertificatePinner' /proc/<pid>/maps`-adjacent mem or `strings` on the pulled `.so`.
3. `javap`/`dexdump` on framework jars for the exact JNI descriptor on that API level.
4. Add the (class, method, sig) triple with a byte-exact wrapper prototype, rebuild, and check logcat for `Hook installation successful` vs `failed`.
5. Never ship a guessed triple: a non-resolving triple is harmless (skipped + logged), a resolving-but-wrong prototype corrupts the stack.
