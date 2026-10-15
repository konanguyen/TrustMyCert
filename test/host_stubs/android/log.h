// Host stub for <android/log.h>: lets NDK-independent TU's compile on host.
// Only used by test/discovery_host_test.cpp. Never shipped.
#pragma once
#define ANDROID_LOG_DEBUG 3
#define ANDROID_LOG_INFO 4
#define ANDROID_LOG_WARN 5
#define ANDROID_LOG_ERROR 6
static inline int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    (void)prio;
    (void)tag;
    (void)fmt;
    return 0;
}
