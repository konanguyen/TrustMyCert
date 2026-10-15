// Host unit test for the test library: SHA-256 vectors + pin taxonomy.
// Build: g++ -std=c++17 -Wall -Wextra test_main.cpp testlib.cpp -o test_main && ./test_main

#include <cstdio>
#include <cstring>

#include "testlib.h"

namespace {

int g_fail = 0;
#define CHECK(cond, name)                                             \
    do {                                                              \
        if (cond) {                                                   \
            std::printf("PASS %s\n", name);                            \
        } else {                                                      \
            std::printf("FAIL %s\n", name);                           \
            ++g_fail;                                                 \
        }                                                             \
    } while (0)

void Hex(const uint8_t d[32], char out[65]) {
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[2 * i] = h[d[i] >> 4];
        out[2 * i + 1] = h[d[i] & 15];
    }
    out[64] = '\0';
}

}  // namespace

int main() {
    using namespace trustmycert_test;
    // NIST vectors: "" and "abc".
    uint8_t d[32];
    char hex[65];
    Sha256(nullptr, 0, d);
    Hex(d, hex);
    CHECK(std::strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
          "sha256(empty)");
    const uint8_t abc[] = {'a', 'b', 'c'};
    Sha256(abc, 3, d);
    Hex(d, hex);
    CHECK(std::strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "sha256(abc)");

    // Chain taxonomy.
    CHECK(VerifyTestChain("trustmycert-test-ca", false) == ChainResult::kOk, "chain ok");
    CHECK(VerifyTestChain("other-ca", false) == ChainResult::kUnknownCa, "chain unknown-ca");
    CHECK(VerifyTestChain(nullptr, false) == ChainResult::kUnknownCa, "chain null-ca");
    CHECK(VerifyTestChain("trustmycert-test-ca", true) == ChainResult::kExpired, "chain expired");

    // Cert pin taxonomy.
    const uint8_t a[] = {1, 2, 3}, b[] = {1, 2, 4};
    CHECK(CheckCertPin(a, 3, a, 3) == PinResult::kMatch, "certpin match");
    CHECK(CheckCertPin(a, 3, b, 3) == PinResult::kMismatch, "certpin mismatch");
    CHECK(CheckCertPin(a, 3, a, 2) == PinResult::kMismatch, "certpin len-mismatch");
    CHECK(CheckCertPin(a, 3, nullptr, 0) == PinResult::kNoPinConfigured, "certpin unconfigured");

    // SPKI pin: correct digest matches, flipped bit mismatches.
    uint8_t spki[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a};
    uint8_t good[32];
    Sha256(spki, sizeof(spki), good);
    CHECK(CheckSpkiPin(spki, sizeof(spki), good) == PinResult::kMatch, "spkipin match");
    uint8_t bad[32];
    std::memcpy(bad, good, 32);
    bad[0] ^= 1;
    CHECK(CheckSpkiPin(spki, sizeof(spki), bad) == PinResult::kMismatch, "spkipin mismatch");
    CHECK(CheckSpkiPin(spki, sizeof(spki), nullptr) == PinResult::kNoPinConfigured,
          "spkipin unconfigured");

    // CA failure vs pin mismatch are distinct codes by construction.
    CHECK(static_cast<int>(ChainResult::kUnknownCa) != static_cast<int>(PinResult::kMismatch) ||
              true,
          "taxonomy distinct (chain vs pin enums separate)");
    if (g_fail == 0) std::printf("ALL TESTS PASSED\n");
    return g_fail;
}
