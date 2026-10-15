// TrustMyCert native library discovery + TLS fingerprinting.
// See discovery.h for the design contract.

#include "discovery.h"

#include <dlfcn.h>

#include <cstdio>
#include <cstring>
#include <set>
#include <utility>

namespace trustmycert {
namespace discovery {

const char *ToString(TlsImpl impl) {
    switch (impl) {
        case TlsImpl::kBoringSsl: return "BoringSSL";
        case TlsImpl::kOpenSsl: return "OpenSSL";
        case TlsImpl::kConscryptNative: return "Conscrypt-native";
        case TlsImpl::kCronet: return "Chromium-network-stack(Cronet)";
        case TlsImpl::kMbedTls: return "mbed-TLS";
        case TlsImpl::kWolfSsl: return "wolfSSL";
        case TlsImpl::kGnuTls: return "GnuTLS";
        case TlsImpl::kCustomStatic: return "custom-or-static-TLS(symbols-without-known-library)";
        case TlsImpl::kUnknown:
        default: return "unknown";
    }
}

bool ParseMapsLine(const std::string &line, MappedLib *out) {
    if (out == nullptr) return false;
    // <addr> <perms> <offset> <dev> <inode> <pathname?>
    unsigned long start = 0, end = 0, offset = 0;
    char perms[8] = {};
    unsigned devMaj = 0, devMin = 0;
    unsigned long inode = 0;
    int pathOff = 0;
    // %n captures where the pathname starts (may be absent).
    int n = std::sscanf(line.c_str(), "%lx-%lx %7s %lx %x:%x %lu %n",
                         &start, &end, perms, &offset, &devMaj, &devMin, &inode, &pathOff);
    if (n < 7) return false;
    std::string path;
    if (pathOff > 0 && static_cast<std::size_t>(pathOff) < line.size()) {
        std::size_t b = line.find_first_not_of(" ", pathOff);
        if (b != std::string::npos) path = line.substr(b);
    }
    // Skip anonymous mappings, [heap]/[stack]/[vdso] style regions.
    if (path.empty() || path[0] == '[') return false;
    out->path = path;
    // makedev-equivalent without <sys/sysmacros.h> dependency.
    out->dev = static_cast<dev_t>((static_cast<unsigned long long>(devMaj) << 8) |
                                  static_cast<unsigned long long>(devMin));
    out->inode = static_cast<ino_t>(inode);
    out->executable = std::strchr(perms, 'x') != nullptr;
    return true;
}

std::vector<MappedLib> EnumerateLoadedLibraries() {
    std::vector<MappedLib> libs;
    std::set<std::pair<unsigned long long, unsigned long long>> seen;
    FILE *f = std::fopen("/proc/self/maps", "r");
    if (f == nullptr) return libs;
    char buf[1024];
    while (std::fgets(buf, sizeof(buf), f) != nullptr) {
        // fgets may split very long lines; only accept newline-terminated
        // complete lines to avoid parsing truncated entries.
        std::string line(buf);
        if (line.empty() || line.back() != '\n') continue;
        MappedLib m;
        if (!ParseMapsLine(line, &m)) continue;
        auto key = std::make_pair(static_cast<unsigned long long>(m.dev),
                                  static_cast<unsigned long long>(m.inode));
        auto it = seen.find(key);
        if (it == seen.end()) {
            seen.insert(key);
            libs.push_back(m);
        } else if (m.executable) {
            for (auto &l : libs) {
                if (static_cast<unsigned long long>(l.dev) == key.first &&
                    static_cast<unsigned long long>(l.inode) == key.second) {
                    l.executable = true;
                    break;
                }
            }
        }
    }
    std::fclose(f);
    return libs;
}

namespace {

// basename without <libgen.h> (not async-signal concerns here, but trivial).
const char *BaseName(const std::string &p) {
    std::size_t i = p.find_last_of('/');
    return p.c_str() + (i == std::string::npos ? 0 : i + 1);
}

bool Contains(const char *hay, const char *needle) { return std::strstr(hay, needle) != nullptr; }

// Candidate exported symbols per implementation. All names verified against
// public headers / symbol tables; see docs/RESEARCH.md. Version-dependent or
// rename-prone entries are marked and treated as hints only.
struct ImplCandidates {
    TlsImpl impl;
    const char *name_hint;  // substring of basename, "" = any
    const char *symbols[8];
};

// Table order = probe order; a library may match several rows (e.g. an app
// bundling both BoringSSL-sourced libssl and mbed TLS) — all matches kept.
const ImplCandidates kCandidates[] = {
    {TlsImpl::kBoringSsl, "ssl",
     {"SSL_get_verify_result", "SSL_CTX_set_custom_verify",  // BoringSSL-only custom-verify API
      "SSL_set_custom_verify", "X509_verify_cert", "SSL_CTX_set_verify", nullptr}},
    {TlsImpl::kBoringSsl, "crypto",
     {"X509_verify_cert", "EVP_DigestVerify", "RSA_verify", nullptr}},
    {TlsImpl::kOpenSsl, "ssl",
     {"SSL_get_verify_result", "SSL_CTX_set_verify", "X509_verify_cert",
      "SSL_CTX_set_cert_verify_callback", nullptr}},  // cert-verify-callback: OpenSSL >= 1.0.2 style
    {TlsImpl::kConscryptNative, "conscrypt",
     {"NativeCrypto_SSL_do_handshake", "X509_verify_cert", "SSL_get_verify_result", nullptr}},
    {TlsImpl::kCronet, "cronet",
     {"Cronet_Engine_Create", "Cronet_UrlRequest_Create", nullptr}},  // intentionally short: Cronet strips most symbols
    {TlsImpl::kMbedTls, "mbedtls",
     {"mbedtls_ssl_get_verify_result", "mbedtls_x509_crt_verify", "mbedtls_ssl_set_hostname", nullptr}},
    {TlsImpl::kMbedTls, "mbedcrypto",
     {"mbedtls_x509_crt_verify", "mbedtls_pk_verify", nullptr}},
    {TlsImpl::kMbedTls, "mbedtls",
     {"mbedtls_ssl_get_verify_result", "mbedtls_x509_crt_verify", "mbedtls_ssl_set_hostname", nullptr}},
    {TlsImpl::kWolfSsl, "wolfssl",
     {"wolfSSL_CTX_set_verify", "wolfSSL_get_verify_result", "wolfSSL_X509_verify_cert", nullptr}},
    {TlsImpl::kGnuTls, "gnutls",
     {"gnutls_certificate_verify_peers2", "gnutls_x509_crt_verify", nullptr}},
    // Generic TLS footprints for statically linked / stripped libraries that
    // still export the classic OpenSSL-compatible entry points.
    {TlsImpl::kCustomStatic, "",
     {"SSL_get_verify_result", "X509_verify_cert", "SSL_CTX_set_verify", nullptr}},
};

}  // namespace

std::vector<SymbolProbe> ProbeTlsSymbols(const std::vector<MappedLib> &libs) {
    std::vector<SymbolProbe> out;
    for (const auto &lib : libs) {
        // RTLD_NOLOAD: resolve against the already-mapped object only.
        void *h = ::dlopen(lib.path.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (h == nullptr) continue;  // e.g. permission or non-dl object: not a failure
        const char *base = BaseName(lib.path);
        for (const auto &cand : kCandidates) {
            if (cand.name_hint[0] != '\0' && !Contains(base, cand.name_hint)) continue;
            SymbolProbe p;
            p.lib_path = lib.path;
            p.impl = cand.impl;
            for (int i = 0; cand.symbols[i] != nullptr; ++i) {
                ::dlerror();
                void *sym = ::dlsym(h, cand.symbols[i]);
                if (sym != nullptr)
                    p.found.emplace_back(cand.symbols[i]);
                else
                    p.missing.emplace_back(cand.symbols[i]);
            }
            if (!p.found.empty()) out.push_back(p);
        }
        ::dlclose(h);
    }
    return out;
}

TlsImpl Fingerprint(const MappedLib &lib, const std::vector<std::string> &found) {
    if (found.empty()) return TlsImpl::kUnknown;
    const char *base = BaseName(lib.path);
    auto has = [&](const char *s) {
        for (const auto &f : found)
            if (f == s) return true;
        return false;
    };
    // BoringSSL is distinguished from OpenSSL by the custom-verify API,
    // which has no OpenSSL equivalent (docs/RESEARCH.md section B).
    if (has("SSL_CTX_set_custom_verify") || has("SSL_set_custom_verify"))
        return TlsImpl::kBoringSsl;
    if (Contains(base, "cronet") && has("Cronet_Engine_Create")) return TlsImpl::kCronet;
    if (Contains(base, "conscrypt")) return TlsImpl::kConscryptNative;
    for (const auto &f : found) {
        if (f.rfind("mbedtls_", 0) == 0) return TlsImpl::kMbedTls;
        if (f.rfind("wolfSSL_", 0) == 0) return TlsImpl::kWolfSsl;
        if (f.rfind("gnutls_", 0) == 0) return TlsImpl::kGnuTls;
    }
    if (Contains(base, "libssl") || Contains(base, "libcrypto") || Contains(base, "libboringssl")) {
        // libssl/libcrypto basename + classic symbols but no custom-verify
        // export: OpenSSL-compatible (could still be BoringSSL with stripped
        // extras — reported as OpenSSL-compatible, never asserted).
        if (has("SSL_get_verify_result") || has("X509_verify_cert")) return TlsImpl::kOpenSsl;
    }
    if (has("SSL_get_verify_result") || has("X509_verify_cert")) return TlsImpl::kCustomStatic;
    return TlsImpl::kUnknown;
}

std::string ClassifyVerification(TlsImpl impl, const std::vector<std::string> &found) {
    bool hasVerify = false, hasCustom = false, hasSpkiHelper = false;
    for (const auto &f : found) {
        if (f == "X509_verify_cert" || f == "mbedtls_x509_crt_verify" ||
            f == "wolfSSL_X509_verify_cert" || f == "gnutls_x509_crt_verify" ||
            f == "gnutls_certificate_verify_peers2")
            hasVerify = true;
        if (f == "SSL_CTX_set_custom_verify" || f == "SSL_set_custom_verify" ||
            f == "SSL_CTX_set_cert_verify_callback" || f == "SSL_CTX_set_verify")
            hasCustom = true;
        if (f == "EVP_DigestVerify" || f == "mbedtls_pk_verify" || f == "RSA_verify") hasSpkiHelper = true;
    }
    std::string s = "impl=";
    s += ToString(impl);
    s += "; chain-validation=";
    s += (hasVerify ? "present" : "not-observed");
    s += "; custom-verify-callback=";
    s += (hasCustom ? "available" : "not-observed");
    s += "; spki-helpers=";
    s += (hasSpkiHelper ? "present" : "not-observed");
    // Deliberately no "pinning detected" claim: exported symbols show the
    // verification *path*, not the app's pin policy. Pin policy is confirmed
    // only by the controlled test app (docs/TEST_PLAN.md).
    s += "; pinning=undetermined-from-symbols (use controlled test app)";
    return s;
}

}  // namespace discovery
}  // namespace trustmycert
