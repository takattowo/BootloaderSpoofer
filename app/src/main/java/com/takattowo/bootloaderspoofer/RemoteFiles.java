package com.takattowo.bootloaderspoofer;

import android.os.ParcelFileDescriptor;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import io.github.libxposed.api.XposedInterface;

/**
 * Helper for reading module-shared files via {@link XposedInterface#openRemoteFile(String)}.
 * Only used in the injected target process. Module-process code must not touch this class.
 */
final class RemoteFiles {

    static String read(XposedInterface xposed, String name) {
        ParcelFileDescriptor pfd = null;
        try {
            pfd = xposed.openRemoteFile(name);
            if (pfd == null) return null;
            try (FileInputStream in = new FileInputStream(pfd.getFileDescriptor());
                 BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    if (sb.length() > 0) sb.append('\n');
                    sb.append(line);
                }
                return sb.toString();
            }
        } catch (Throwable t) {
            return null;
        } finally {
            if (pfd != null) try { pfd.close(); } catch (Throwable ignored) {}
        }
    }

    private RemoteFiles() {}
}
