// Controlled native test library implementation. See testlib.h.

#include "testlib.h"

#include <cstring>

namespace trustmycert_test {

ChainResult VerifyTestChain(const char *issuer_tag, bool expired) {
    if (expired) return ChainResult::kExpired;
    if (issuer_tag == nullptr) return ChainResult::kUnknownCa;
    if (std::strcmp(issuer_tag, kTestCaTag) == 0) return ChainResult::kOk;
    return ChainResult::kUnknownCa;
}

PinResult CheckCertPin(const uint8_t *presented_der, std::size_t presented_len,
                       const uint8_t *pinned_der, std::size_t pinned_len) {
    if (pinned_der == nullptr || pinned_len == 0) return PinResult::kNoPinConfigured;
    if (presented_der == nullptr) return PinResult::kMismatch;
    if (presented_len != pinned_len) return PinResult::kMismatch;
    if (std::memcmp(presented_der, pinned_der, presented_len) != 0) return PinResult::kMismatch;
    return PinResult::kMatch;
}

PinResult CheckSpkiPin(const uint8_t *presented_spki, std::size_t presented_len,
                       const uint8_t expected_sha256[32]) {
    if (expected_sha256 == nullptr) return PinResult::kNoPinConfigured;
    if (presented_spki == nullptr) return PinResult::kMismatch;
    uint8_t digest[32];
    Sha256(presented_spki, presented_len, digest);
    if (std::memcmp(digest, expected_sha256, 32) != 0) return PinResult::kMismatch;
    return PinResult::kMatch;
}

// --- SHA-256 (FIPS 180-4). Compact implementation for test pinning. ---
namespace {
inline uint32_t Rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
const uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
}  // namespace

void Sha256(const uint8_t *data, std::size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    // Process 64-byte blocks from a padded copy (test-sized inputs only).
    uint8_t block[64];
    std::size_t off = 0;
    auto compress = [&](const uint8_t *b) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (static_cast<uint32_t>(b[4 * i]) << 24) |
                   (static_cast<uint32_t>(b[4 * i + 1]) << 16) |
                   (static_cast<uint32_t>(b[4 * i + 2]) << 8) | b[4 * i + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b0 = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + kK[i] + w[i];
            uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
            uint32_t maj = (a & b0) ^ (a & c) ^ (b0 & c);
            uint32_t t2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b0;
            b0 = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b0;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    };
    while (off + 64 <= len) {
        compress(data + off);
        off += 64;
    }
    std::size_t rem = len - off;
    std::memset(block, 0, sizeof(block));
    if (rem) std::memcpy(block, data + off, rem);
    block[rem] = 0x80;
    if (rem + 1 + 8 > 64) {
        compress(block);
        std::memset(block, 0, sizeof(block));
    }
    for (int i = 0; i < 8; ++i) block[56 + i] = static_cast<uint8_t>(bitlen >> (56 - 8 * i));
    compress(block);
    for (int i = 0; i < 8; ++i) {
        out[4 * i] = static_cast<uint8_t>(h[i] >> 24);
        out[4 * i + 1] = static_cast<uint8_t>(h[i] >> 16);
        out[4 * i + 2] = static_cast<uint8_t>(h[i] >> 8);
        out[4 * i + 3] = static_cast<uint8_t>(h[i]);
    }
}

}  // namespace trustmycert_test
