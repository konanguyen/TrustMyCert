#pragma once

// Carefully scoped runtime instrumentation (AGENTS.md section 5).
//
// What is implemented (observe-only unless config::kEnableBypass):
//   JNI  - java/lang/Runtime.nativeLoad, two known signatures (load monitor).
//          Re-runs discovery reporting when app code loads a new library.
//   PLT  - SSL_get_verify_result / X509_verify_cert / SSL_CTX_set_verify.
//          Wrappers log (rate-limited) then forward to the real function.
//
// Deliberate non-goals, documented in docs/RESEARCH.md:
//   - No ART Java-method hooking (Zygisk API v4 cannot hook pure-Java
//     methods such as OkHttp CertificatePinner.check); those paths are
//     observed indirectly through the native verify functions they call into.
//   - No NativeCrypto.SSL_do_handshake JNI hook: its signature is
//     version-dependent and a mismatched wrapper prototype would corrupt the
//     stack. Added only after confirming the exact signature on the target
//     device (procedure in docs/RESEARCH.md).
//   - No Dobby/ShadowHook vendoring: unverified licensing/ABI/build cost for
//     this template; Zygisk built-in PLT + JNI hooks cover the MVP.
//   - pltHookRegister/pltHookCommit must complete inside
//     pre/postSpecialize (the Api handle dies after that), so libraries
//     loaded *after* specialization are reported by discovery but cannot be
//     PLT-hooked. This is a Zygisk API limitation, not a bug.

#include <jni.h>

namespace zygisk {
struct Api;
}

namespace trustmycert {
namespace hooks {

// Install JNI hooks. Safe to call once in preAppSpecialize (JNIEnv valid).
// Returns number of methods successfully hooked.
int InstallJniHooks(zygisk::Api *api, JNIEnv *env);

// Register PLT hooks for every mapped ELF and commit. Must be called inside
// pre/postSpecialize. Returns committed ok.
bool InstallNativeHooks(zygisk::Api *api);

// Re-run discovery reporting after a new library load (observe-only; no
// PLT commit possible here — see header note).
void ReportNewLibraries();

}  // namespace hooks
}  // namespace trustmycert
