// TrustMyCert runtime config parsing + companion fetch. See runtime_config.h.

#include "runtime_config.h"

#include <cerrno>
#include <cstdint>
#include <sys/socket.h>
#include <sys/types.h>

#include <atomic>

#include "config.h"
#include "log.h"

namespace trustmycert {
namespace runtime_config {

namespace {

std::string Trim(const std::string &s) {
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

bool ParseBool(const std::string &v, bool *out) {
    if (v == "1" || v == "true" || v == "yes" || v == "on") {
        *out = true;
        return true;
    }
    if (v == "0" || v == "false" || v == "no" || v == "off") {
        *out = false;
        return true;
    }
    return false;
}

bool ValidTarget(const std::string &t) {
    if (t.empty() || t.size() > kMaxTargetLen) return false;
    if (t == "system_server") return false;
    for (char c : t) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '.';
        if (!ok) return false;
    }
    return true;
}

// Blocking write/read of an exact byte count on the companion socket.
// MSG_NOSIGNAL prevents SIGPIPE from killing the target process if the
// companion dies mid-request.
bool SendAll(int fd, const void *buf, std::size_t len) {
    const char *p = static_cast<const char *>(buf);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

bool RecvAll(int fd, void *buf, std::size_t len) {
    char *p = static_cast<char *>(buf);
    while (len > 0) {
        ssize_t n = ::recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

RuntimeConfig g_active;
std::atomic<bool> g_verbose{false};
std::atomic<bool> g_bypass{false};

}  // namespace

RuntimeConfig Parse(const std::string &text) {
    RuntimeConfig cfg;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t end = text.find('\n', pos);
        if (end == std::string::npos) end = text.size();
        std::string line = Trim(text.substr(pos, end - pos));
        pos = end + 1;
        if (line.empty() || line[0] == '#') continue;

        std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
            cfg.warnings.push_back("ignored line without '='");
            continue;
        }
        std::string key = Trim(line.substr(0, eq));
        std::string value = Trim(line.substr(eq + 1));
        // Allow trailing comments ("enabled=1  # note") but never inline
        // '#' inside a value that is not preceded by whitespace.
        std::size_t hash = value.find('#');
        if (hash != std::string::npos && hash > 0 &&
            (value[hash - 1] == ' ' || value[hash - 1] == '\t')) {
            value = Trim(value.substr(0, hash));
        }

        if (key == "target") {
            if (!ValidTarget(value)) {
                cfg.warnings.push_back("ignored invalid target");
                continue;
            }
            if (cfg.targets.size() >= kMaxTargets) {
                cfg.warnings.push_back("target limit reached; extra entries ignored");
                continue;
            }
            bool dup = false;
            for (const auto &t : cfg.targets)
                if (t == value) {
                    dup = true;
                    break;
                }
            if (!dup) cfg.targets.push_back(value);
            continue;
        }

        bool b = false;
        if (!ParseBool(value, &b)) {
            cfg.warnings.push_back("ignored non-boolean value for " + key);
            continue;
        }
        if (key == "enabled")
            cfg.enabled = b;
        else if (key == "bypass")
            cfg.bypass = b;
        else if (key == "verbose")
            cfg.verbose = b;
        else if (key == "match_subprocesses")
            cfg.match_subprocesses = b;
        else
            cfg.warnings.push_back("ignored unknown key: " + key);
    }
    return cfg;
}

bool MatchesProcess(const RuntimeConfig &cfg, const std::string &process) {
    if (process.empty() || process == "system_server") return false;
    for (const auto &t : cfg.targets) {
        if (process == t) return true;
        if (cfg.match_subprocesses && process.size() > t.size() &&
            process.compare(0, t.size(), t) == 0 && process[t.size()] == ':') {
            return true;
        }
    }
    return false;
}

bool FetchFromCompanion(int fd, std::string *out) {
    if (fd < 0 || out == nullptr) return false;
    out->clear();
    const char op = 'C';  // C = config
    if (!SendAll(fd, &op, 1)) return false;

    unsigned char lenbuf[4];
    if (!RecvAll(fd, lenbuf, sizeof(lenbuf))) return false;
    std::uint32_t len = static_cast<std::uint32_t>(lenbuf[0]) |
                        (static_cast<std::uint32_t>(lenbuf[1]) << 8) |
                        (static_cast<std::uint32_t>(lenbuf[2]) << 16) |
                        (static_cast<std::uint32_t>(lenbuf[3]) << 24);
    if (len > kMaxConfigBytes) {
        TMC_LOGW("Runtime config rejected: companion length %u exceeds limit", len);
        return false;
    }
    out->resize(len);
    if (len > 0 && !RecvAll(fd, &(*out)[0], len)) {
        out->clear();
        return false;
    }
    return true;
}

void SetActive(const RuntimeConfig &cfg) {
    g_active = cfg;
    // Effective values are cached atomically because hook wrappers call them
    // from arbitrary app threads after specialization.
    g_verbose.store(config::kVerbose || cfg.verbose, std::memory_order_relaxed);
    g_bypass.store(config::kEnableBypass && config::kAllowRuntimeBypass && cfg.bypass,
                   std::memory_order_relaxed);
}

const RuntimeConfig &Active() { return g_active; }

bool Verbose() { return g_verbose.load(std::memory_order_relaxed); }

bool BypassActive() { return g_bypass.load(std::memory_order_relaxed); }

bool RuntimeBypassSupported() {
    return config::kEnableBypass && config::kAllowRuntimeBypass;
}

}  // namespace runtime_config
}  // namespace trustmycert
