// TrustMyCert — Zygisk native SSL-pinning research/testing module.
//
// Lifecycle:
//   preAppSpecialize    target selection (allowlist) + JNI hooks.
//   postAppSpecialize   discovery, fingerprinting, PLT hooks.
//   preServerSpecialize always opts out (system_server never instrumented).
// No root companion: the module needs no superuser operations, so none is
// registered (smaller attack surface; rationale in docs/RESEARCH.md).

#include <jni.h>

#include <string>

#include "config.h"
#include "discovery.h"
#include "hooks.h"
#include "log.h"
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

namespace {

std::string g_process;

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
        if (trustmycert::config::kVerbose)
            TMC_LOGI("Native library loaded: %s", m.path.c_str());
        ++shown;
    }

    auto probes = trustmycert::discovery::ProbeTlsSymbols(libs);
    if (probes.empty()) {
        TMC_LOGI("Diagnostic result: no known TLS symbols resolved in loaded libraries");
        TMC_LOGI("Diagnostic result: static-link/stripped candidates need controlled-test confirmation");
        return;
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
        if (trustmycert::config::kVerbose) {
            std::string syms;
            for (const auto &s : pr.found) {
                if (!syms.empty()) syms += ",";
                syms += s;
            }
            TMC_LOGI("Candidate verification function discovered: %s", syms.c_str());
        }
        if (++n >= trustmycert::config::kMaxLibsLogged) break;
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
            TMC_LOGW("TEST-ONLY bypass is ENABLED: verification overrides active, do not release");
        }
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process = env_->GetStringUTFChars(args->nice_name, nullptr);
        g_process = process ? process : "";
        if (process) env_->ReleaseStringUTFChars(args->nice_name, process);

        if (!trustmycert::config::IsTargetApp(g_process.c_str())) {
            TMC_LOGI("Target process skipped: %s (not in allowlist)", g_process.c_str());
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            target_ = false;
            return;
        }
        target_ = true;
        TMC_LOGI("Target process selected: %s", g_process.c_str());
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
