#pragma once

// Controlled native test library (test-only, never shipped in the module).
//
// Exercises, through JNI-callable C++:
//   1. standard chain validation (simulated trust-store check),
//   2. a deliberately configured certificate pin (exact-match),
//   3. SPKI/public-key pin verification (real SHA-256 over the SPKI bytes),
//   4. success AND failure cases for each.
//
// The failure taxonomy distinguishes "unknown CA" from "pin mismatch" so the
// TrustMyCert module's reporting can be validated against known ground truth.
// Compiles both on host (unit test) and under the Android NDK (used by the
// test APK via testlib_jni.cpp).

#include <cstddef>
#include <cstdint>

namespace trustmycert_test {

enum class ChainResult {
    kOk = 0,          // chain validates against the test trust store
    kUnknownCa = 1,   // issuer not in trust store (NOT pinning)
    kExpired = 2,     // validity window failure (NOT pinning)
};

enum class PinResult {
    kMatch = 0,       // presented credential equals the configured pin
    kMismatch = 1,    // chain valid, but pin differs -> explicit pin failure
    kNoPinConfigured = 2,
};

// Simulated trust-store chain check against the test CA sheep.
// `issuer_tag` must equal kTestCaTag for success. Pure logic, deterministic.
ChainResult VerifyTestChain(const char *issuer_tag, bool expired);

// Exact certificate pin: byte-compare presented DER against pinned DER.
PinResult CheckCertPin(const uint8_t *presented_der, std::size_t presented_len,
                       const uint8_t *pinned_der, std::size_t pinned_len);

// SPKI pin: SHA-256(presented_spki) == expected_sha256 (32 bytes).
PinResult CheckSpkiPin(const uint8_t *presented_spki, std::size_t presented_len,
                       const uint8_t expected_sha256[32]);

// Minimal public-domain-style SHA-256 (test vectors verified in test_main).
void Sha256(const uint8_t *data, std::size_t len, uint8_t out[32]);

inline constexpr char kTestCaTag[] = "trustmycert-test-ca";

}  // namespace trustmycert_test
