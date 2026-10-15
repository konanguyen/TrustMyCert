package com.example.trustmycert.test;

/** JNI facade over test/native_testlib (libtestverify.so). Return codes in docs/TEST_PLAN.md. */
public final class NativeVerify {
    static { System.loadLibrary("testverify"); }

    private NativeVerify() {}

    public static native int verifyChain(String issuerTag, boolean expired);
    public static native int checkCertPin(byte[] presentedDer, byte[] pinnedDer);
    public static native int checkSpkiPin(byte[] presentedSpki, byte[] expectedSha256);
    public static native byte[] sha256(byte[] data);
}
