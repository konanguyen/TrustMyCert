#pragma once

// Native library discovery + TLS implementation fingerprinting.
//
// Design notes (AGENTS.md section 4):
// - Never trust filenames alone: every fingerprint is a (name hint +
//   exported-symbol probe) pair, and inconclusive results are reported as
//   such instead of guessed.
// - /proc/self/maps parsing is pure STL with no Android dependencies so the
//   parser is unit-testable on host.
// - Symbol probing uses dlopen(path, RTLD_NOW | RTLD_NOLOAD): it never loads
//   a library that is not already mapped.

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace trustmycert {
namespace discovery {

// One shared object (or other mapped file) observed in /proc/self/maps.
struct MappedLib {
    std::string path;  // empty for anonymous mappings
    dev_t dev = 0;     // st_dev pair used by Zygisk pltHookRegister
    ino_t inode = 0;   // st_ino pair used by Zygisk pltHookRegister
    bool executable = false;
};

enum class TlsImpl {
    kUnknown = 0,
    kBoringSsl,
    kOpenSsl,
    kConscryptNative,
    kCronet,
    kProxygen,  // Meta Proxygen/Fizz stack (e.g. libcoldstart.so), BoringSSL-based
    kMbedTls,
    kWolfSsl,
    kGnuTls,
    kCustomStatic,  // TLS-looking symbols, no known library identity
};

const char *ToString(TlsImpl impl);

// Parse one /proc/self/maps line.
// Example:
//   7b0a9c4000-7b0a9c6000 r-xp 00000000 fe:00 235 /system/lib64/libssl.so
// Returns false for malformed lines or anonymous mappings (path empty).
bool ParseMapsLine(const std::string &line, MappedLib *out);

// Enumerate distinct mapped files with a pathname. Reads /proc/self/maps.
// Dedupes by (dev, inode); keeps the first executable flag seen per file.
std::vector<MappedLib> EnumerateLoadedLibraries();

// Probe already-loaded libraries for known TLS exported symbols.
// For each lib in libs, dlopen(RTLD_NOLOAD) + dlsym the candidate table and
// report which symbols resolved. Never loads new code.
struct SymbolProbe {
    std::string lib_path;
    TlsImpl impl = TlsImpl::kUnknown;
    std::vector<std::string> found;    // resolved exported symbols
    std::vector<std::string> missing;  // candidate symbols not resolved
};

std::vector<SymbolProbe> ProbeTlsSymbols(const std::vector<MappedLib> &libs);

// Fingerprint one library from its path hint + resolved symbols.
TlsImpl Fingerprint(const MappedLib &lib, const std::vector<std::string> &foundSymbols);

// Human-readable classification of the pinning/verification mechanism that
// the observed symbols suggest. Never claims "pinning" for plain CA
// validation (AGENTS.md section 3C).
std::string ClassifyVerification(TlsImpl impl, const std::vector<std::string> &foundSymbols);

}  // namespace discovery
}  // namespace trustmycert
