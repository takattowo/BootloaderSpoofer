package com.takattowo.bootloaderspoofer;

import android.os.Build;
import android.util.Log;

import java.lang.reflect.Method;
import java.util.concurrent.ThreadLocalRandom;

final class BootKey {

    private static volatile byte[] cachedBootKey;
    private static volatile byte[] cachedBootHash;

    static byte[] getBootKey() {
        byte[] k = cachedBootKey;
        if (k == null) {
            synchronized (BootKey.class) {
                k = cachedBootKey;
                if (k == null) {
                    k = randomBytes(32);
                    cachedBootKey = k;
                }
            }
        }
        return k;
    }

    static byte[] getBootHash() {
        byte[] h = cachedBootHash;
        if (h == null) {
            synchronized (BootKey.class) {
                h = cachedBootHash;
                if (h == null) {
                    h = bootHashFromProp();
                    if (h == null) h = randomBytes(32);
                    cachedBootHash = h;
                }
            }
        }
        return h;
    }

    private static byte[] bootHashFromProp() {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getDeclaredMethod("get", String.class, String.class);
            String b = (String) get.invoke(null, "ro.boot.vbmeta.digest", null);
            if (b == null || b.length() != 64) return null;
            return hexToBytes(b);
        } catch (Throwable t) {
            Log.w(ModuleMain.TAG, "bootHashFromProp failed: " + t);
            return null;
        }
    }

    private static byte[] hexToBytes(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return out;
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        ThreadLocalRandom.current().nextBytes(b);
        return b;
    }

    static int getOsVersion() {
        switch (Build.VERSION.SDK_INT) {
            case 36: return 160000;
            case 35: return 150000;
            case 34: return 140000;
            case 33: return 130000;
            case 32: return 120100;
            case 31: return 120000;
            default: return Build.VERSION.SDK_INT * 10000;
        }
    }

    static int getPatchLevel() {
        return convertPatchLevel(Build.VERSION.SECURITY_PATCH, false);
    }

    static long getPatchLevelLong() {
        return convertPatchLevel(Build.VERSION.SECURITY_PATCH, true);
    }

    private static int convertPatchLevel(String patch, boolean longForm) {
        try {
            String[] parts = patch.split("-");
            int y = Integer.parseInt(parts[0]);
            int m = Integer.parseInt(parts[1]);
            int d = parts.length > 2 ? Integer.parseInt(parts[2]) : 0;
            return longForm ? y * 10000 + m * 100 + d : y * 100 + m;
        } catch (Throwable t) {
            return 202404;
        }
    }

    private BootKey() {}
}
