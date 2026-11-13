// Host tests for native/runtime_config.cpp (no device required).
//
// Build:
//   g++ -std=c++17 -Wall -Wextra -Itest/host_stubs -Inative
//       test/runtime_config_host_test.cpp native/runtime_config.cpp
//       -o /tmp/tmc_runtime && /tmp/tmc_runtime

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "runtime_config.h"

using trustmycert::runtime_config::FetchFromCompanion;
using trustmycert::runtime_config::MatchesProcess;
using trustmycert::runtime_config::Parse;
using trustmycert::runtime_config::RuntimeConfig;

static void TestFailClosedDefaults() {
    RuntimeConfig cfg = Parse("");
    assert(!cfg.enabled);
    assert(!cfg.bypass);
    assert(!cfg.verbose);
    assert(!cfg.match_subprocesses);
    assert(cfg.targets.empty());
    assert(!MatchesProcess(cfg, "com.example.app"));
}

static void TestFullConfig() {
    const std::string text =
        "# comment\r\n"
        "\r\n"
        "  enabled = 1  # master\n"
        "bypass=true\r\n"
        "verbose=0\n"
        "match_subprocesses=yes\n"
        "target=com.example.app\n"
        "target = com.example.second\n"
        "target=com.example.app\n"
        "unknownkey=1\n"
        "target=bad target\n"
        "target=system_server\n";
    RuntimeConfig cfg = Parse(text);
    assert(cfg.enabled);
    assert(cfg.bypass);
    assert(!cfg.verbose);
    assert(cfg.match_subprocesses);
    assert(cfg.targets.size() == 2);
    assert(cfg.targets[0] == "com.example.app");
    assert(cfg.targets[1] == "com.example.second");
    // unknown key + invalid target + system_server produce warnings.
    assert(cfg.warnings.size() >= 3);
}

static void TestBooleanAndBounds() {
    RuntimeConfig cfg = Parse("enabled=maybe\nbypass=2\nverbose=on\n");
    assert(!cfg.enabled);
    assert(!cfg.bypass);
    assert(cfg.verbose);

    std::string many;
    for (int i = 0; i < 100; ++i) many += "target=com.example.app" + std::to_string(i) + "\n";
    RuntimeConfig capped = Parse(many);
    assert(capped.targets.size() == trustmycert::runtime_config::kMaxTargets);

    std::string longname(trustmycert::runtime_config::kMaxTargetLen + 1, 'a');
    RuntimeConfig longcfg = Parse("target=" + longname + "\n");
    assert(longcfg.targets.empty());
}

static void TestMatching() {
    RuntimeConfig cfg;
    cfg.targets.push_back("com.example.game");
    cfg.targets.push_back("com.example.bank");

    assert(MatchesProcess(cfg, "com.example.game"));
    assert(MatchesProcess(cfg, "com.example.bank"));
    assert(!MatchesProcess(cfg, "com.example.game2"));
    assert(!MatchesProcess(cfg, "com.example.game:remote"));
    assert(!MatchesProcess(cfg, ""));
    assert(!MatchesProcess(cfg, "system_server"));

    cfg.match_subprocesses = true;
    assert(MatchesProcess(cfg, "com.example.game:remote"));
    assert(MatchesProcess(cfg, "com.example.game:sandbox"));
    assert(!MatchesProcess(cfg, "com.example.game2:remote"));
    assert(!MatchesProcess(cfg, "com.example.gamex"));
    assert(!MatchesProcess(cfg, "system_server"));
}

static void TestActiveSwitches() {
    // Build defaults: kEnableBypass=false, kAllowRuntimeBypass=false,
    // kVerbose=false. Runtime bypass must therefore stay inert.
    RuntimeConfig cfg;
    cfg.enabled = true;
    cfg.bypass = true;
    cfg.verbose = true;
    trustmycert::runtime_config::SetActive(cfg);
    assert(trustmycert::runtime_config::Verbose());
    assert(!trustmycert::runtime_config::BypassActive());
    assert(!trustmycert::runtime_config::RuntimeBypassSupported());
    assert(trustmycert::runtime_config::Active().enabled);
    assert(trustmycert::runtime_config::Active().targets.empty());

    RuntimeConfig off;
    trustmycert::runtime_config::SetActive(off);
    assert(!trustmycert::runtime_config::Verbose());
    assert(!trustmycert::runtime_config::BypassActive());
}

static void SendRaw(int fd, const void *data, std::size_t len) {
    const char *p = static_cast<const char *>(data);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, 0);
        assert(n > 0);
        p += n;
        len -= static_cast<std::size_t>(n);
    }
}

static void TestCompanionFetch() {
    int sv[2] = {-1, -1};
    assert(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    const std::string payload = "enabled=1\ntarget=com.example.app\n";
    unsigned char header[4] = {
        static_cast<unsigned char>(payload.size() & 0xff),
        static_cast<unsigned char>((payload.size() >> 8) & 0xff),
        0, 0,
    };
    SendRaw(sv[1], header, sizeof(header));
    SendRaw(sv[1], payload.data(), payload.size());

    std::string out;
    assert(FetchFromCompanion(sv[0], &out));
    assert(out == payload);
    ::close(sv[0]);
    ::close(sv[1]);

    // Zero-length config is a valid "no file / empty" response.
    assert(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    unsigned char zero[4] = {0, 0, 0, 0};
    SendRaw(sv[1], zero, sizeof(zero));
    out = "stale";
    assert(FetchFromCompanion(sv[0], &out));
    assert(out.empty());
    ::close(sv[0]);
    ::close(sv[1]);

    // Oversized length must be rejected before allocation/read.
    assert(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    unsigned char huge[4] = {0xff, 0xff, 0xff, 0xff};
    SendRaw(sv[1], huge, sizeof(huge));
    out.clear();
    assert(!FetchFromCompanion(sv[0], &out));
    assert(out.empty());
    ::close(sv[0]);
    ::close(sv[1]);

    assert(!FetchFromCompanion(-1, &out));
}

int main() {
    TestFailClosedDefaults();
    TestFullConfig();
    TestBooleanAndBounds();
    TestMatching();
    TestActiveSwitches();
    TestCompanionFetch();
    std::puts("RUNTIME CONFIG HOST TESTS PASSED");
    return 0;
}
