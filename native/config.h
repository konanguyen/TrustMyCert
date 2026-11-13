#pragma once

// TrustMyCert compile-time configuration.
//
// Target selection and the verbose/bypass switches are runtime configurable
// (see runtime_config.h and docs/WEBUI.md); this header only holds hard
// build-time limits and master switches. All behavior-changing certificate
// validation overrides MUST stay behind kEnableBypass (default: false) AND
// kAllowRuntimeBypass (default: false). Discovery, fingerprinting and
// observe-only instrumentation run independently of those flags.
// See AGENTS.md sections 5-6.

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

// TEST-ONLY: when true, verification wrappers can override failures. This
// weakens TLS security process-wide in the target app. NEVER enable in a
// release build; only for controlled tests against apps you own or are
// explicitly authorized to assess, using test certificates and a controlled
// test server.
inline constexpr bool kEnableBypass = false;

// Second, independent build-time gate for runtime (`bypass=1`) activation.
// Even with kEnableBypass=true, a runtime config cannot enable bypass unless
// this is also true. Keep false for any distributed build.
inline constexpr bool kAllowRuntimeBypass = false;

// Max libraries / symbols reported in detail when verbose.
inline constexpr std::size_t kMaxLibsLogged = 64;
inline constexpr std::size_t kMaxSymbolsLogged = 32;

// Max observe-only log lines emitted from hot-path wrappers per process.
// Prevents log flooding when e.g. SSL_get_verify_result is called in a loop.
inline constexpr int kMaxHotPathLogs = 16;

// Target selection is runtime-only: /data/adb/trustmycert/config.conf lists
// the authorized test apps. Default (missing/empty config) instruments
// nothing, including system_server and unrelated apps.

}  // namespace config
}  // namespace trustmycert
