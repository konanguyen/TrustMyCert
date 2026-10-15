// JNI bridge for the controlled test APK (package com.example.trustmycert.test).
// Built with the test APK's own CMake (NDK), NOT with the module build.
// Exercises: chain validation, cert pin, SPKI pin — success + failure cases.

#include <jni.h>

#include <vector>

#include "testlib.h"

namespace {

std::vector<uint8_t> JBytesToVec(JNIEnv *env, jbyteArray arr) {
    std::vector<uint8_t> v;
    if (arr == nullptr) return v;
    jsize n = env->GetArrayLength(arr);
    v.resize(static_cast<std::size_t>(n));
    if (n) env->GetByteArrayRegion(arr, 0, n, reinterpret_cast<jbyte *>(v.data()));
    return v;
}

}  // namespace

extern "C" {

// int verifyChain(String issuerTag, boolean expired)
//   -> 0 ok, 1 unknown CA, 2 expired
JNIEXPORT jint JNICALL
Java_com_example_trustmycert_test_NativeVerify_verifyChain(JNIEnv *env, jclass, jstring issuerTag,
                                                           jboolean expired) {
    const char *tag = issuerTag ? env->GetStringUTFChars(issuerTag, nullptr) : nullptr;
    auto r = trustmycert_test::VerifyTestChain(tag, expired == JNI_TRUE);
    if (tag) env->ReleaseStringUTFChars(issuerTag, tag);
    return static_cast<jint>(r);
}

// int checkCertPin(byte[] presentedDer, byte[] pinnedDer)
//   -> 0 match, 1 mismatch, 2 no pin configured
JNIEXPORT jint JNICALL Java_com_example_trustmycert_test_NativeVerify_checkCertPin(
    JNIEnv *env, jclass, jbyteArray presentedDer, jbyteArray pinnedDer) {
    auto p = JBytesToVec(env, presentedDer);
    auto q = JBytesToVec(env, pinnedDer);
    const uint8_t *qd = q.empty() ? nullptr : q.data();
    auto r = trustmycert_test::CheckCertPin(p.empty() ? nullptr : p.data(), p.size(), qd, q.size());
    return static_cast<jint>(r);
}

// int checkSpkiPin(byte[] presentedSpki, byte[] expectedSha256)
//   -> 0 match, 1 mismatch, 2 no pin configured
JNIEXPORT jint JNICALL Java_com_example_trustmycert_test_NativeVerify_checkSpkiPin(
    JNIEnv *env, jclass, jbyteArray presentedSpki, jbyteArray expectedSha256) {
    auto p = JBytesToVec(env, presentedSpki);
    auto q = JBytesToVec(env, expectedSha256);
    if (q.size() != 32) return static_cast<jint>(trustmycert_test::PinResult::kNoPinConfigured);
    auto r = trustmycert_test::CheckSpkiPin(p.empty() ? nullptr : p.data(), p.size(), q.data());
    return static_cast<jint>(r);
}

// byte[] sha256(byte[] data) — lets the APK compute pins for the test server cert.
JNIEXPORT jbyteArray JNICALL
Java_com_example_trustmycert_test_NativeVerify_sha256(JNIEnv *env, jclass, jbyteArray data) {
    auto v = JBytesToVec(env, data);
    uint8_t digest[32];
    trustmycert_test::Sha256(v.empty() ? nullptr : v.data(), v.size(), digest);
    jbyteArray out = env->NewByteArray(32);
    if (out) env->SetByteArrayRegion(out, 0, 32, reinterpret_cast<const jbyte *>(digest));
    return out;
}
}
