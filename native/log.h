#pragma once

// TrustMyCert logging helpers.
//
// Every module-generated log entry must contain the literal marker
// "[TrustMyCert]" and use the log tag "TrustMyCert".
// See AGENTS.md section 7.
//
// Build channels:
//   product (TMC_DEBUG_BUILD=0): only TMC_LOGE is compiled in.
//   debug   (TMC_DEBUG_BUILD=1): debug, info, warning and error are compiled in.
//
// Build with DEBUG=1 or DEBUG=0 (see build.py). The CMake build receives
// TMC_DEBUG_BUILD from build.py; a direct CMake build defaults to product.

#include <android/log.h>

#ifndef TMC_DEBUG_BUILD
#define TMC_DEBUG_BUILD 0
#endif

#define TRUSTMYCERT_TAG "TrustMyCert"

// NOTE: fmt must be a string literal so the marker is always present.
#if TMC_DEBUG_BUILD
#define TMC_LOGD(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, TRUSTMYCERT_TAG, "[TrustMyCert] " fmt, ##__VA_ARGS__)
#define TMC_LOGI(fmt, ...) \
    __android_log_print(ANDROID_LOG_INFO, TRUSTMYCERT_TAG, "[TrustMyCert] " fmt, ##__VA_ARGS__)
#define TMC_LOGW(fmt, ...) \
    __android_log_print(ANDROID_LOG_WARN, TRUSTMYCERT_TAG, "[TrustMyCert] " fmt, ##__VA_ARGS__)
#else
// Product builds are silent except for real errors. The empty variadic
// function consumes its arguments so variables used only in diagnostics do
// not trigger -Wunused warnings; always_inline + the empty body let the
// compiler drop both the call and the format strings.
namespace trustmycert {
namespace log_internal {
template <typename... Args>
__attribute__((always_inline)) inline void DebugNoop(const char *, Args &&...) {}
}  // namespace log_internal
}  // namespace trustmycert

#define TMC_LOGD(fmt, ...) ::trustmycert::log_internal::DebugNoop(fmt, ##__VA_ARGS__)
#define TMC_LOGI(fmt, ...) ::trustmycert::log_internal::DebugNoop(fmt, ##__VA_ARGS__)
#define TMC_LOGW(fmt, ...) ::trustmycert::log_internal::DebugNoop(fmt, ##__VA_ARGS__)
#endif

#define TMC_LOGE(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, TRUSTMYCERT_TAG, "[TrustMyCert] " fmt, ##__VA_ARGS__)
