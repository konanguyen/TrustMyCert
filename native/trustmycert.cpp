// TrustMyCert — Zygisk native SSL-pinning research/testing module.
//
// Lifecycle:
//   preAppSpecialize    runtime config fetch (root companion) + target match
//                       + JNI hooks.
//   postAppSpecialize   discovery, fingerprinting, PLT hooks.
//   preServerSpecialize always opts out (system_server never instrumented).
//
// The module is fail-closed: it instruments only processes named in
// /data/adb/trustmycert/config.conf. Reading that path requires root, so a
// small companion handler serves the config over the Zygisk companion socket
// during preAppSpecialize. The companion exposes exactly one fixed file and
// never accepts a client-supplied path (no arbitrary root file read).

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <string>

#include "config.h"
#include "discovery.h"
#include "hooks.h"
#include "log.h"
#include "runtime_config.h"
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

namespace {

std::string g_process;

// ---------- root companion: fixed-path config reader ----------

bool WriteAll(int fd, const void *buf, std::size_t len) {
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

void CompanionHandler(int client) {
    // Protocol: one request byte 'C', then 4-byte LE length + config bytes.
    // Anything else closes the connection. The path is compile-time fixed.
    char op = 0;
    ssize_t got = ::recv(client, &op, 1, 0);
    if (got != 1 || op != 'C') {
        TMC_LOGW("Companion request rejected: unsupported opcode");
        ::close(client);
        return;
    }

    std::string data;
    int fd = ::open(trustmycert::runtime_config::kConfigPath, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[4096];
        for (;;) {
            ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (n == 0) break;
            if (data.size() + static_cast<std::size_t>(n) >
                trustmycert::runtime_config::kMaxConfigBytes) {
                data.resize(trustmycert::runtime_config::kMaxConfigBytes);
                TMC_LOGE("Runtime config truncated at %zu bytes",
                         trustmycert::runtime_config::kMaxConfigBytes);
                break;
            }
            data.append(buf, static_cast<std::size_t>(n));
        }
        ::close(fd);
    } else {
        TMC_LOGW("Runtime config missing: %s (fail-closed until configured)",
                 trustmycert::runtime_config::kConfigPath);
    }

    std::uint32_t len = static_cast<std::uint32_t>(data.size());
    unsigned char header[4] = {
        static_cast<unsigned char>(len & 0xff),
        static_cast<unsigned char>((len >> 8) & 0xff),
        static_cast<unsigned char>((len >> 16) & 0xff),
        static_cast<unsigned char>((len >> 24) & 0xff),
    };
    if (WriteAll(client, header, sizeof(header)) && len > 0) {
        WriteAll(client, data.data(), data.size());
    }
    ::close(client);
}

// Observe-only discovery report shared by postAppSpecialize and the
// late-load path in hooks.cpp.
void RunDiscoveryReport() {
    if (!trustmycert::config::kEnableDiscovery) {
        TMC_LOGI("Diagnostic result: discovery disabled by config");
        return;
    }
    auto libs = trustmycert::discovery::EnumerateLoadedLibraries();
    TMC_LOGI("Diagnostic result: %zu mapped files enumerated", libs.size());

    std::size_t shown = 0;
    for (const auto &m : libs) {
        if (shown >= trustmycert::config::kMaxLibsLogged) break;
        if (m.path.find(".so") == std::string::npos) continue;
        if (trustmycert::runtime_config::Verbose())
            TMC_LOGI("Native library loaded: %s", m.path.c_str());
        ++shown;
    }

    auto probes = trustmycert::discovery::ProbeTlsSymbols(libs);
    if (probes.empty()) {
        TMC_LOGI("Diagnostic result: no known TLS symbols resolved in loaded libraries");
        TMC_LOGI("Diagnostic result: static-link/stripped candidates need controlled-test confirmation");
    }
    std::size_t n = 0;
    for (const auto &pr : probes) {
        trustmycert::discovery::MappedLib m;
        m.path = pr.lib_path;
        auto impl = trustmycert::discovery::Fingerprint(m, pr.found);
        TMC_LOGI("TLS implementation identified: %s (%s)", trustmycert::discovery::ToString(impl),
                 pr.lib_path.c_str());
        TMC_LOGI("Pinning mechanism: %s",
                 trustmycert::discovery::ClassifyVerification(impl, pr.found).c_str());
        if (trustmycert::runtime_config::Verbose()) {
            std::string syms;
            for (const auto &s : pr.found) {
                if (!syms.empty()) syms += ",";
                syms += s;
            }
            TMC_LOGI("Candidate verification function discovered: %s", syms.c_str());
        }
        if (++n >= trustmycert::config::kMaxLibsLogged) break;
    }
    // Known stripped carriers (e.g. Flutter): basename hint + recon advice.
    for (const auto &m : libs) {
        if (!trustmycert::discovery::IsKnownStrippedCarrier(m.path)) continue;
        bool probed = false;
        for (const auto &pr : probes)
            if (pr.lib_path == m.path) {
                probed = true;
                break;
            }
        if (probed) continue;
        TMC_LOGI("TLS implementation identified: Flutter-embedded-BoringSSL(stripped, exports-none) (%s)",
                 m.path.c_str());
        TMC_LOGI("Diagnostic result: stripped carrier, no exported verify symbols; "
                 "use string-anchor recon (ssl_verify_peer_cert/handshake.cc) per docs/RESEARCH.md");
    }
}

}  // namespace

class TrustMyCertModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
        TMC_LOGI("Module initialized (Zygisk API %d)", ZYGISK_API_VERSION);
        if (trustmycert::config::kEnableBypass) {
            if (trustmycert::runtime_config::RuntimeBypassSupported()) {
                TMC_LOGW("TEST-ONLY bypass compiled in; runtime bypass=1 can activate it");
            } else {
                TMC_LOGW("TEST-ONLY bypass compiled in, but runtime activation is disabled");
            }
        }
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process = env_->GetStringUTFChars(args->nice_name, nullptr);
        g_process = process ? process : "";
        if (process) env_->ReleaseStringUTFChars(args->nice_name, process);

        trustmycert::runtime_config::RuntimeConfig cfg;
        bool have_config = false;

        // Api::connectCompanion only works in pre[XXX]Specialize. Failure is
        // fail-closed: no config means no instrumentation.
        int fd = api_->connectCompanion();
        if (fd < 0) {
            TMC_LOGE("Hook installation failed: companion connection unavailable (fail-closed)");
        } else {
            std::string text;
            if (trustmycert::runtime_config::FetchFromCompanion(fd, &text)) {
                cfg = trustmycert::runtime_config::Parse(text);
                have_config = true;
                TMC_LOGI("Runtime config: loaded %zu bytes, enabled=%d targets=%zu bypass=%d "
                         "verbose=%d subprocesses=%d",
                         text.size(), cfg.enabled ? 1 : 0, cfg.targets.size(),
                         cfg.bypass ? 1 : 0, cfg.verbose ? 1 : 0,
                         cfg.match_subprocesses ? 1 : 0);
                for (const auto &w : cfg.warnings) TMC_LOGW("Runtime config: %s", w.c_str());
                if (cfg.verbose) {
                    for (const auto &t : cfg.targets)
                        TMC_LOGI("Runtime config: target allowlisted: %s", t.c_str());
                }
            } else {
                TMC_LOGE("Hook installation failed: runtime config IPC error (fail-closed)");
            }
            ::close(fd);
        }
        trustmycert::runtime_config::SetActive(cfg);

        if (!have_config) {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            target_ = false;
            return;
        }
        if (!cfg.enabled) {
            if (cfg.verbose)
                TMC_LOGI("Target process skipped: %s (module disabled by runtime config)",
                         g_process.c_str());
            else
                TMC_LOGD("Target process skipped: %s (module disabled by runtime config)",
                         g_process.c_str());
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            target_ = false;
            return;
        }
        if (!trustmycert::runtime_config::MatchesProcess(cfg, g_process)) {
            if (cfg.verbose)
                TMC_LOGI("Target process skipped: %s (not in runtime allowlist, %zu targets)",
                         g_process.c_str(), cfg.targets.size());
            else
                TMC_LOGD("Target process skipped: %s (not in runtime allowlist)", g_process.c_str());
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            target_ = false;
            return;
        }

        target_ = true;
        TMC_LOGI("Target process selected: %s", g_process.c_str());
        if (cfg.bypass) {
            if (trustmycert::runtime_config::BypassActive()) {
                TMC_LOGW("TEST-ONLY bypass is ACTIVE for this process; do not use with real accounts");
            } else {
                TMC_LOGW("Runtime bypass requested but build disallows it "
                         "(kEnableBypass/kAllowRuntimeBypass); observe-only");
            }
        }
        int n = trustmycert::hooks::InstallJniHooks(api_, env_);
        TMC_LOGI("Diagnostic result: %d JNI hooks installed", n);
        // Do NOT dlclose: PLT hooks are installed in postAppSpecialize.
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        (void)args;
        if (!target_) return;
        TMC_LOGI("Target process specialized: %s", g_process.c_str());
        RunDiscoveryReport();
        if (!trustmycert::hooks::InstallNativeHooks(api_)) {
            TMC_LOGE("Hook installation failed: native hooks (continuing observe-only)");
        }
        // Library stays mapped: hooks are live. No DLCLOSE here by design.
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        (void)args;
        TMC_LOGI("Target process skipped: system_server (never instrumented)");
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    bool target_ = false;
};

REGISTER_ZYGISK_MODULE(TrustMyCertModule)

// Root companion handler (runs in the Zygisk root daemon, per ABI).
REGISTER_ZYGISK_COMPANION(CompanionHandler)
