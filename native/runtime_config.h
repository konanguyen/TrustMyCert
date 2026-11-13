#pragma once

// TrustMyCert runtime configuration (WebUI / CLI managed).
//
// The module is fail-closed: a process is instrumented only when the runtime
// config names it explicitly. Config lives outside the app sandbox at
// /data/adb/trustmycert/config.conf and is read through the Zygisk root
// companion during preAppSpecialize (app processes cannot read /data/adb).
//
// Format (line based, comments start with '#'):
//   enabled=1              master switch for instrumentation
//   bypass=0               TEST-ONLY, also requires build-time opt-in
//   verbose=0              extra per-library/per-symbol diagnostics
//   match_subprocesses=0   also match "<target>:<suffix>" processes
//   target=com.example.app one line per authorized test app
//
// The parser is deliberately strict and bounded; unknown keys are ignored.

#include <cstddef>
#include <string>
#include <vector>

namespace trustmycert {
namespace runtime_config {

inline constexpr const char *kConfigPath = "/data/adb/trustmycert/config.conf";

// Bounds (also enforced by the companion reader and the tmc CLI).
inline constexpr std::size_t kMaxConfigBytes = 64 * 1024;
inline constexpr std::size_t kMaxTargets = 64;
inline constexpr std::size_t kMaxTargetLen = 255;

struct RuntimeConfig {
    bool enabled = false;
    bool bypass = false;
    bool verbose = false;
    bool match_subprocesses = false;
    std::vector<std::string> targets;

    // Non-fatal parser diagnostics, e.g. "target limit reached".
    std::vector<std::string> warnings;
};

// Parse a config document. Never throws; malformed lines are ignored and
// noted in warnings. The returned config is fail-closed by default.
RuntimeConfig Parse(const std::string &text);

// Pure matching rule: exact nice_name match against targets, plus
// "<target>:<suffix>" when match_subprocesses is enabled. system_server and
// empty names never match.
bool MatchesProcess(const RuntimeConfig &cfg, const std::string &process);

// Fetch a config document from the root companion socket (opcode 'C',
// 4-byte little-endian length, payload). Returns false on protocol error.
bool FetchFromCompanion(int fd, std::string *out);

// Install the active per-process config. Called once in preAppSpecialize
// before any instrumentation is installed.
void SetActive(const RuntimeConfig &cfg);
const RuntimeConfig &Active();

// Effective switches: compile-time master AND runtime value.
bool Verbose();
bool BypassActive();

// True when the build permits runtime bypass at all (diagnostics/UI help).
bool RuntimeBypassSupported();

}  // namespace runtime_config
}  // namespace trustmycert
