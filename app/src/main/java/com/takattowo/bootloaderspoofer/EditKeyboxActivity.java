package com.takattowo.bootloaderspoofer;

import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import io.github.libxposed.service.XposedService;

public class EditKeyboxActivity extends AppCompatActivity {

    private EditText editor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_edit_keybox);

        editor = findViewById(R.id.keybox_edit);
        ImageButton back = findViewById(R.id.btn_back);
        MaterialButton save = findViewById(R.id.btn_save);

        back.setOnClickListener(v -> finish());
        save.setOnClickListener(v -> save());

        loadExisting();
    }

    private void loadExisting() {
        XposedService svc = App.getService();
        if (svc == null) return;

        ParcelFileDescriptor pfd = null;
        try {
            String[] list = svc.listRemoteFiles();
            boolean has = false;
            if (list != null) for (String n : list) if (Config.KEYBOX_FILE.equals(n)) { has = true; break; }
            if (!has) return;

            pfd = svc.openRemoteFile(Config.KEYBOX_FILE);
            if (pfd == null) return;
            try (FileInputStream in = new FileInputStream(pfd.getFileDescriptor())) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) baos.write(buf, 0, n);
                editor.setText(baos.toString("UTF-8"));
            }
        } catch (Throwable t) {
            toast("Load failed: " + t.getMessage());
        } finally {
            if (pfd != null) try { pfd.close(); } catch (Throwable ignored) {}
        }
    }

    private void save() {
        XposedService svc = App.getService();
        if (svc == null) { toast(getString(R.string.toast_not_connected)); return; }

        String xml = editor.getText().toString();
        if (TextUtils.isEmpty(xml.trim())) { toast("Empty input"); return; }

        try { svc.deleteRemoteFile(Config.KEYBOX_FILE); } catch (Throwable ignored) {}

        ParcelFileDescriptor pfd = null;
        try {
            pfd = svc.openRemoteFile(Config.KEYBOX_FILE);
            if (pfd == null) throw new IOException("openRemoteFile returned null");
            try (FileOutputStream out = new FileOutputStream(pfd.getFileDescriptor())) {
                out.write(xml.getBytes(StandardCharsets.UTF_8));
                out.getFD().sync();
            }
            toast(getString(R.string.toast_saved));
            finish();
        } catch (Throwable t) {
            toast("Save failed: " + t.getMessage());
        } finally {
            if (pfd != null) try { pfd.close(); } catch (Throwable ignored) {}
        }
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}
