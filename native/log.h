#pragma once

// TrustMyCert logging helpers.
//
// Every module-generated log entry must contain the literal marker
// "[TrustMyCert]" and use the log tag "TrustMyCert".
// See AGENTS.md section 7.

#include <android/log.h>

#define TRUSTMYCERT_TAG "TrustMyCert"

// NOTE: fmt must be a string literal so the marker is always present.
#define TMC_LOGD(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, TRUSTMYCERT_TAG, "[TrustMyCert] " fmt, ##__VA_ARGS__)
#define TMC_LOGI(fmt, ...) \
    __android_log_print(ANDROID_LOG_INFO, TRUSTMYCERT_TAG, "[TrustMyCert] " fmt, ##__VA_ARGS__)
#define TMC_LOGW(fmt, ...) \
    __android_log_print(ANDROID_LOG_WARN, TRUSTMYCERT_TAG, "[TrustMyCert] " fmt, ##__VA_ARGS__)
#define TMC_LOGE(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, TRUSTMYCERT_TAG, "[TrustMyCert] " fmt, ##__VA_ARGS__)
