// TrustMyCert runtime instrumentation. See hooks.h for scope + limits.

#include "hooks.h"

#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include "zygisk.hpp"
#include "config.h"
#include "discovery.h"
#include "log.h"

namespace trustmycert {
namespace hooks {

namespace {

// ---------- shared state ----------

std::mutex g_state_mu;
std::vector<std::string> g_known_libs;  // snapshot from Install* time
pid_t g_pid = 0;

// ---------- JNI: Runtime.nativeLoad load monitor ----------

// Known signatures across Android releases (libcore/luni Runtime.java):
//   v2 (newer): nativeLoad(String, ClassLoader, Class) -> String
//   v1 (older): nativeLoad(String, ClassLoader) -> String
// Each wrapper below matches its registered signature exactly; a wrapper is
// only installed when its (class, method, sig) triple resolves (fnPtr set),
// so a version mismatch can never install a wrong-prototype hook.
using NativeLoadV2 = jstring (*)(JNIEnv *, jclass, jstring, jobject, jclass);
using NativeLoadV1 = jstring (*)(JNIEnv *, jclass, jstring, jobject);

NativeLoadV2 g_orig_native_load_v2 = nullptr;
NativeLoadV1 g_orig_native_load_v1 = nullptr;

void AfterLibraryLoad(JNIEnv *env, jstring filename) {
    if (filename == nullptr) return;
    const char *c = env->GetStringUTFChars(filename, nullptr);
    std::string path = c ? c : "";
    if (c) env->ReleaseStringUTFChars(filename, c);
    TMC_LOGI("Native library loaded: %s", path.c_str());
    ReportNewLibraries();
}

jstring HookedNativeLoadV2(JNIEnv *env, jclass clazz, jstring filename, jobject loader,
                           jclass caller) {
    jstring r = g_orig_native_load_v2 ? g_orig_native_load_v2(env, clazz, filename, loader, caller)
                                      : nullptr;
    AfterLibraryLoad(env, filename);
    return r;
}

jstring HookedNativeLoadV1(JNIEnv *env, jclass clazz, jstring filename, jobject loader) {
    jstring r = g_orig_native_load_v1 ? g_orig_native_load_v1(env, clazz, filename, loader) : nullptr;
    AfterLibraryLoad(env, filename);
    return r;
}

// ---------- native PLT wrappers (observe-only) ----------

// C ABI of the hooked symbols — stable across OpenSSL 1.x-3.x and BoringSSL
// (see docs/RESEARCH.md). void* params avoid any OpenSSL header dependency.
using FnGetVerifyResult = long (*)(const void * /*SSL*/);
using FnVerifyCert = int (*)(void * /*X509_STORE_CTX*/);
using FnSetVerify = void (*)(void * /*SSL_CTX*/, int /*mode*/, void * /*callback*/);

std::vector<FnGetVerifyResult> g_orig_get_verify_result;
std::vector<FnVerifyCert> g_orig_verify_cert;
std::vector<FnSetVerify> g_orig_set_verify;

std::atomic<int> g_log_count_verify_result{0};
std::atomic<int> g_log_count_verify_cert{0};
std::atomic<int> g_log_count_set_verify{0};

bool ShouldLog(std::atomic<int> &ctr) {
    int n = ctr.fetch_add(1, std::memory_order_relaxed);
    return n < config::kMaxHotPathLogs;
}

// Forwarding rule: exactly one orig -> call it (the common single-TLS-impl
// case, provably the right target). Multiple origs (several TLS builds in
// one process) -> RTLD_DEFAULT lookup of the real definition + a one-time
// warning. Never calls a null pointer; never fabricates a result unless
// config::kEnableBypass (test-only).
template <typename Fn>
Fn PickOrig(const std::vector<Fn> &v, const char *sym, std::atomic<int> &warned) {
    if (v.size() == 1) return v[0];
    if (!v.empty()) {
        if (warned.fetch_add(1, std::memory_order_relaxed) == 0)
            TMC_LOGW("Hook forwarding ambiguous: %zu origs for %s, using RTLD_DEFAULT", v.size(),
                     sym);
        void *p = ::dlsym(RTLD_DEFAULT, sym);
        return reinterpret_cast<Fn>(p);
    }
    return nullptr;
}

long Hooked_SSL_get_verify_result(const void *ssl) {
    static std::atomic<int> warned{0};
    FnGetVerifyResult orig;
    {
        std::lock_guard<std::mutex> l(g_state_mu);
        orig = PickOrig(g_orig_get_verify_result, "SSL_get_verify_result", warned);
    }
    if (config::kEnableBypass) {
        // TEST-ONLY, failure-only override (field technique: flip failures,
        // preserve successes — minimizes behavioral delta vs blanket allow).
        long real = orig ? orig(ssl) : -1L;
        if (real != 0) {
            if (ShouldLog(g_log_count_verify_result))
                TMC_LOGW("Hook SSL_get_verify_result: BYPASS active, failure %ld forced to X509_V_OK",
                         real);
            return 0;  // X509_V_OK
        }
        if (ShouldLog(g_log_count_verify_result))
            TMC_LOGI("Hook SSL_get_verify_result -> %ld (genuine success, kept)", real);
        return real;
    }
    long r = orig ? orig(ssl) : -1L;
    if (ShouldLog(g_log_count_verify_result))
        TMC_LOGI("Hook SSL_get_verify_result -> %ld", r);
    return r;
}

int Hooked_X509_verify_cert(void *ctx) {
    static std::atomic<int> warned{0};
    FnVerifyCert orig;
    {
        std::lock_guard<std::mutex> l(g_state_mu);
        orig = PickOrig(g_orig_verify_cert, "X509_verify_cert", warned);
    }
    if (config::kEnableBypass) {
        // TEST-ONLY, failure-only override (see above).
        int real = orig ? orig(ctx) : 0;
        if (real != 1) {
            if (ShouldLog(g_log_count_verify_cert))
                TMC_LOGW("Hook X509_verify_cert: BYPASS active, failure %d forced to success", real);
            return 1;
        }
        if (ShouldLog(g_log_count_verify_cert))
            TMC_LOGI("Hook X509_verify_cert -> 1 (genuine success, kept)");
        return real;
    }
    int r = orig ? orig(ctx) : 0;
    if (ShouldLog(g_log_count_verify_cert)) TMC_LOGI("Hook X509_verify_cert -> %d", r);
    return r;
}

void Hooked_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    static std::atomic<int> warned{0};
    FnSetVerify orig;
    {
        std::lock_guard<std::mutex> l(g_state_mu);
        orig = PickOrig(g_orig_set_verify, "SSL_CTX_set_verify", warned);
    }
    if (ShouldLog(g_log_count_set_verify))
        TMC_LOGI("Hook SSL_CTX_set_verify: mode=%d callback=%p", mode, cb);
    if (orig) orig(ctx, mode, cb);
}

void SnapshotLibs(const std::vector<discovery::MappedLib> &libs) {
    std::lock_guard<std::mutex> l(g_state_mu);
    g_known_libs.clear();
    for (const auto &m : libs) g_known_libs.push_back(m.path);
}

}  // namespace

int InstallJniHooks(zygisk::Api *api, JNIEnv *env) {
    if (!config::kEnableJniHooks) {
        TMC_LOGI("JNI hooks disabled by config");
        return 0;
    }
    int hooked = 0;
    // Newer 3-arg form first; each entry only installs on exact match.
    JNINativeMethod v2[] = {
        {"nativeLoad",
         "(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/Class;)Ljava/lang/String;",
         reinterpret_cast<void *>(&HookedNativeLoadV2)}};
    api->hookJniNativeMethods(env, "java/lang/Runtime", v2, 1);
    if (v2[0].fnPtr != nullptr) {
        g_orig_native_load_v2 = reinterpret_cast<NativeLoadV2>(v2[0].fnPtr);
        TMC_LOGI("Hook installation successful: java/lang/Runtime.nativeLoad/3 (load monitor)");
        ++hooked;
    } else {
        TMC_LOGI("Diagnostic result: Runtime.nativeLoad/3 not found, trying /2 variant");
    }
    JNINativeMethod v1[] = {
        {"nativeLoad", "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/String;",
         reinterpret_cast<void *>(&HookedNativeLoadV1)}};
    // Only try /2 if /3 missed (a runtime has exactly one of them).
    if (g_orig_native_load_v2 == nullptr) {
        api->hookJniNativeMethods(env, "java/lang/Runtime", v1, 1);
        if (v1[0].fnPtr != nullptr) {
            g_orig_native_load_v1 = reinterpret_cast<NativeLoadV1>(v1[0].fnPtr);
            TMC_LOGI("Hook installation successful: java/lang/Runtime.nativeLoad/2 (load monitor)");
            ++hooked;
        } else {
            TMC_LOGW("Hook installation failed: Runtime.nativeLoad not found (/2 nor /3)");
        }
    }
    return hooked;
}

bool InstallNativeHooks(zygisk::Api *api) {
    if (!config::kEnableNativeHooks) {
        TMC_LOGI("Native hooks disabled by config");
        return true;
    }
    auto libs = discovery::EnumerateLoadedLibraries();
    SnapshotLibs(libs);
    g_pid = getpid();

    struct Target {
        const char *sym;
        void *hook;
        void **slot;  // per-lib orig storage allocated below
    };
    // One orig slot per (lib, symbol): Zygisk writes each registration's
    // previous PLT target into its own slot, so forwarding stays exact.
    struct Slot {
        std::string lib;
        std::string sym;
        void *orig = nullptr;
    };
    static std::vector<Slot> slots;  // static: outlives commit, read by wrappers via vectors below
    static std::mutex slots_mu;

    int regs = 0;
    {
        std::lock_guard<std::mutex> l(slots_mu);
        for (const auto &m : libs) {
            if (m.path.find(".so") == std::string::npos) continue;
            Slot s1{m.path, "SSL_get_verify_result", nullptr};
            Slot s2{m.path, "X509_verify_cert", nullptr};
            Slot s3{m.path, "SSL_CTX_set_verify", nullptr};
            api->pltHookRegister(m.dev, m.inode, s1.sym.c_str(),
                                 reinterpret_cast<void *>(&Hooked_SSL_get_verify_result),
                                 &s1.orig);
            api->pltHookRegister(m.dev, m.inode, s2.sym.c_str(),
                                 reinterpret_cast<void *>(&Hooked_X509_verify_cert), &s2.orig);
            api->pltHookRegister(m.dev, m.inode, s3.sym.c_str(),
                                 reinterpret_cast<void *>(&Hooked_SSL_CTX_set_verify), &s3.orig);
            slots.push_back(s1);
            slots.push_back(s2);
            slots.push_back(s3);
            regs += 3;
        }
    }
    bool ok = api->pltHookCommit();
    TMC_LOGI("Hook commit: registered=%d committed=%s", regs, ok ? "yes" : "no");
    if (!ok) {
        TMC_LOGE("Hook installation failed: pltHookCommit returned false");
        return false;
    }
    // Collect non-null origs per symbol (a lib whose PLT lacks the symbol
    // yields a null orig — expected, not an error).
    {
        std::lock_guard<std::mutex> l(g_state_mu);
        std::lock_guard<std::mutex> l2(slots_mu);
        for (const auto &s : slots) {
            if (s.orig == nullptr) continue;
            if (s.sym == "SSL_get_verify_result")
                g_orig_get_verify_result.push_back(reinterpret_cast<FnGetVerifyResult>(s.orig));
            else if (s.sym == "X509_verify_cert")
                g_orig_verify_cert.push_back(reinterpret_cast<FnVerifyCert>(s.orig));
            else if (s.sym == "SSL_CTX_set_verify")
                g_orig_set_verify.push_back(reinterpret_cast<FnSetVerify>(s.orig));
        }
    }
    TMC_LOGI("Hook installation successful: SSL_get_verify_result origs=%zu",
             g_orig_get_verify_result.size());
    TMC_LOGI("Hook installation successful: X509_verify_cert origs=%zu", g_orig_verify_cert.size());
    TMC_LOGI("Hook installation successful: SSL_CTX_set_verify origs=%zu", g_orig_set_verify.size());
    return true;
}

void ReportNewLibraries() {
    auto libs = discovery::EnumerateLoadedLibraries();
    std::vector<std::string> fresh;
    {
        std::lock_guard<std::mutex> l(g_state_mu);
        for (const auto &m : libs) {
            bool known = false;
            for (const auto &k : g_known_libs)
                if (k == m.path) {
                    known = true;
                    break;
                }
            if (!known) {
                fresh.push_back(m.path);
                g_known_libs.push_back(m.path);
            }
        }
    }
    for (const auto &p : fresh) TMC_LOGI("Native library loaded (late): %s", p.c_str());
    if (!fresh.empty()) {
        auto probes = discovery::ProbeTlsSymbols(libs);
        for (const auto &pr : probes) {
            bool isFresh = false;
            for (const auto &p : fresh)
                if (p == pr.lib_path) {
                    isFresh = true;
                    break;
                }
            if (!isFresh) continue;
            discovery::MappedLib m;
            m.path = pr.lib_path;
            auto impl = discovery::Fingerprint(m, pr.found);
            TMC_LOGI("TLS implementation identified: %s (%s)", discovery::ToString(impl),
                     pr.lib_path.c_str());
            TMC_LOGI("Pinning mechanism: %s",
                     discovery::ClassifyVerification(impl, pr.found).c_str());
        }
        TMC_LOGI("Diagnostic result: late-loaded libs are reported only (PLT commit window closed)");
    }
}

}  // namespace hooks
}  // namespace trustmycert
