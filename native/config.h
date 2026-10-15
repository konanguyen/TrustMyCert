#pragma once

// TrustMyCert compile-time configuration.
//
// All behavior-changing certificate validation overrides MUST stay behind
// kEnableBypass (default: false). Discovery, fingerprinting and observe-only
// instrumentation run independently of that flag. See AGENTS.md sections 5-6.

#include <cstddef>

namespace trustmycert {
namespace config {

// Verbose diagnostics (extra per-library / per-symbol lines). Gated to avoid
// log spam; hot-path wrappers additionally rate-limit themselves.
inline constexpr bool kVerbose = false;

// Master switches for each subsystem.
inline constexpr bool kEnableDiscovery = true;
inline constexpr bool kEnableJniHooks = true;
inline constexpr bool kEnableNativeHooks = true;

// TEST-ONLY: when true, verification wrappers return success even when the
// real verification failed. This weakens TLS security process-wide in the
// target app. NEVER enable in a release build; only for controlled tests
// against apps you own or are explicitly authorized to assess, using test
// certificates and a controlled test server.
inline constexpr bool kEnableBypass = false;

// Max libraries / symbols reported in detail when verbose.
inline constexpr std::size_t kMaxLibsLogged = 64;
inline constexpr std::size_t kMaxSymbolsLogged = 32;

// Max observe-only log lines emitted from hot-path wrappers per process.
// Prevents log flooding when e.g. SSL_get_verify_result is called in a loop.
inline constexpr int kMaxHotPathLogs = 16;

// Explicit allowlist of test application process names (value of
// AppSpecializeArgs.nice_name). The module refuses to instrument anything
// else, including system_server and unrelated apps. Edit + rebuild to add
// your own authorized test app.
inline constexpr const char *kTargetApps[] = {
    "com.example.trustmycert.test",
};

inline constexpr const char *kTestAppPrefix = "com.example.trustmycert.";

// Returns true only for explicitly selected test processes.
inline bool IsTargetApp(const char *process) {
    if (process == nullptr || process[0] == '\0') return false;
    for (const char *t : kTargetApps) {
        const char *a = process;
        const char *b = t;
        while (*a && *b && *a == *b) {
            ++a;
            ++b;
        }
        if (*a == '\0' && *b == '\0') return true;
    }
    // Allow sibling test harnesses under the same package prefix.
    for (const char *p = process, *q = kTestAppPrefix; *q; ++p, ++q) {
        if (*p != *q) return false;
        if (*p == '\0') return false;
    }
    return true;
}

}  // namespace config
}  // namespace trustmycert
