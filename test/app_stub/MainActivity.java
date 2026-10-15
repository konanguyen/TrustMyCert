package com.example.trustmycert.test;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Stub test APK (package com.example.trustmycert.test).
 *
 * Assemble in Android Studio: new project (Empty Activity), package name above,
 * add src/main/cpp/CMakeLists.txt building ../../native_testlib/testlib.cpp +
 * testlib_jni.cpp as libtestverify.so, replace MainActivity with this file.
 * Each button exercises one ground-truth case from docs/TEST_PLAN.md section C.
 */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        TextView out = new TextView(this);
        out.setText("TrustMyCert test harness");
        layout.addView(out);
        addCase(layout, out, "Chain-OK", () -> "verifyChain=" +
                NativeVerify.verifyChain("trustmycert-test-ca", false) + " (want 0)");
        addCase(layout, out, "Chain-bad-CA", () -> "verifyChain=" +
                NativeVerify.verifyChain("other-ca", false) + " (want 1)");
        addCase(layout, out, "CertPin-match", () -> {
            byte[] cert = new byte[]{1, 2, 3};
            return "checkCertPin=" + NativeVerify.checkCertPin(cert, cert) + " (want 0)";
        });
        addCase(layout, out, "CertPin-mismatch", () -> "checkCertPin=" +
                NativeVerify.checkCertPin(new byte[]{1, 2, 3}, new byte[]{1, 2, 4}) + " (want 1)");
        addCase(layout, out, "SPKI-match", () -> {
            byte[] spki = new byte[]{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a};
            return "checkSpkiPin=" + NativeVerify.checkSpkiPin(spki, NativeVerify.sha256(spki)) +
                    " (want 0)";
        });
        addCase(layout, out, "SPKI-mismatch", () -> {
            byte[] spki = new byte[]{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a};
            byte[] pin = NativeVerify.sha256(spki);
            pin[0] ^= 1;
            return "checkSpkiPin=" + NativeVerify.checkSpkiPin(spki, pin) + " (want 1)";
        });
        setContentView(layout);
    }

    interface Case { String run(); }

    void addCase(LinearLayout layout, TextView out, String label, Case c) {
        Button btn = new Button(this);
        btn.setText(label);
        btn.setOnClickListener(v -> out.setText(label + ": " + c.run()));
        layout.addView(btn);
    }
}
