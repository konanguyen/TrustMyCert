// Host driver for the NDK-independent discovery maps parser.
// Compiles native/discovery.cpp on host against test/host_stubs/android/log.h.
// See docs/TEST_PLAN.md section A for the build command.

#include <cassert>
#include <cstdio>
#include <string>

#include "discovery.h"

using namespace trustmycert::discovery;

int main() {
    MappedLib m;
    // Standard 64-bit line.
    assert(ParseMapsLine(
        "7b0a9c4000-7b0a9c6000 r-xp 00000000 fe:00 235 /system/lib64/libssl.so", &m));
    assert(m.path == "/system/lib64/libssl.so" && m.executable);
    // Non-executable mapping of the same file keeps path, executable=false.
    assert(ParseMapsLine(
        "7b0a9c6000-7b0a9c8000 r--p 00002000 fe:00 235 /system/lib64/libssl.so", &m));
    assert(m.path == "/system/lib64/libssl.so" && !m.executable);
    // Anonymous + bracket regions rejected.
    assert(!ParseMapsLine("7b0a9c8000-7b0a9ca000 rw-p 00000000 00:00 0 ", &m));
    assert(!ParseMapsLine("7b0a9ca000-7b0a9cb000 rw-p 00000000 00:00 0 [heap]", &m));
    // Malformed rejected.
    assert(!ParseMapsLine("not a maps line", &m));

    // Fingerprint rules.
    MappedLib boring;
    boring.path = "/system/lib64/libssl.so";
    assert(Fingerprint(boring, {"SSL_CTX_set_custom_verify", "SSL_get_verify_result"}) ==
           TlsImpl::kBoringSsl);
    MappedLib ossl;
    ossl.path = "/data/app/lib/libssl.so";
    assert(Fingerprint(ossl, {"SSL_get_verify_result", "X509_verify_cert"}) == TlsImpl::kOpenSsl);
    MappedLib mbed;
    mbed.path = "/data/app/lib/libmbedtls.so";
    assert(Fingerprint(mbed, {"mbedtls_x509_crt_verify"}) == TlsImpl::kMbedTls);
    assert(Fingerprint(boring, {}) == TlsImpl::kUnknown);

    // Proxygen/Fizz: exact mangled names resolve, substring rule classifies.
    MappedLib cold;
    cold.path = "/data/app/lib/arm64/libcoldstart.so";
    const std::string proxygenSym =
        "_ZN8proxygen15SSLVerification17verifyWithMetricsEbP17x509_store_ctx_stRKNSt6__ndk212"
        "basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS0_"
        "31SSLFailureVerificationCallbacksEPNS0_31SSLSuccessVerificationCallbacksERKNS_"
        "15TimeUtilGenericINS3_6chrono12steady_clockEEERNS_10TraceEventERKNS_16SSLVerifyOptionsE";
    assert(Fingerprint(cold, {proxygenSym}) == TlsImpl::kProxygen);
    MappedLib tiktok;
    tiktok.path = "/data/app/lib/arm64/libttboringssl.so";
    assert(Fingerprint(tiktok, {"SSL_CTX_set_custom_verify", "SSL_get_verify_result"}) ==
           TlsImpl::kBoringSsl);

    // Liger stack: basename rule + third mangling variant (__ndk112).
    MappedLib liger;
    liger.path = "/data/app/lib/arm64/libliger.so";
    const std::string ligerSym =
        "_ZN8proxygen15SSLVerification17verifyWithMetricsEbP17x509_store_ctx_stRKNSt6__ndk112"
        "basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS0_"
        "31SSLFailureVerificationCallbacksEPNS0_31SSLSuccessVerificationCallbacksERKNS_"
        "15TimeUtilGenericINS3_6chrono12steady_clockEEERNS_10TraceEventE";
    assert(Fingerprint(liger, {ligerSym}) == TlsImpl::kProxygen);

    // Stripped carriers: basename hint only, never identification.
    assert(IsKnownStrippedCarrier("/data/app/lib/arm64/libflutter.so"));
    assert(IsKnownStrippedCarrier("/data/app/lib/arm64/libapp.so"));
    assert(!IsKnownStrippedCarrier("/system/lib64/libssl.so"));

    // Classification never claims pinning from symbols alone.
    std::string c = ClassifyVerification(TlsImpl::kOpenSsl, {"X509_verify_cert"});
    assert(c.find("pinning=undetermined-from-symbols") != std::string::npos);
    assert(c.find("chain-validation=present") != std::string::npos);

    std::printf("DISCOVERY HOST TESTS PASSED\n");
    return 0;
}
