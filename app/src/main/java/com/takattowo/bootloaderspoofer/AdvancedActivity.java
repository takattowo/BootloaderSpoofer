package com.takattowo.bootloaderspoofer;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;

import io.github.libxposed.service.XposedService;

public class AdvancedActivity extends AppCompatActivity implements App.ServiceStateListener {

    private static final int REQ_PICK_KEYBOX = 100;

    private View rowPick;
    private View rowEdit;
    private View rowClear;

    private volatile XposedService service;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced);

        ImageButton back = findViewById(R.id.btn_back);
        back.setOnClickListener(v -> finish());

        rowPick = findViewById(R.id.row_pick);
        bindRow(rowPick, R.drawable.ic_file,
                getString(R.string.row_pick_title),
                getString(R.string.row_pick_subtitle),
                v -> pickFile());

        rowEdit = findViewById(R.id.row_edit);
        bindRow(rowEdit, R.drawable.ic_edit,
                getString(R.string.row_edit_title),
                getString(R.string.row_edit_subtitle_absent),
                v -> startActivity(new Intent(this, EditKeyboxActivity.class)));

        rowClear = findViewById(R.id.row_clear);
        bindRow(rowClear, R.drawable.ic_delete,
                getString(R.string.row_clear_title),
                getString(R.string.row_clear_subtitle),
                v -> confirmClear());
    }

    private void bindRow(View row, int iconRes, String title, String subtitle, View.OnClickListener onClick) {
        ImageView icon = row.findViewById(R.id.row_icon);
        TextView t = row.findViewById(R.id.row_title);
        TextView s = row.findViewById(R.id.row_subtitle);
        icon.setImageResource(iconRes);
        t.setText(title);
        s.setText(subtitle);
        row.setOnClickListener(onClick);
    }

    private void setRowSubtitle(View row, String subtitle) {
        TextView s = row.findViewById(R.id.row_subtitle);
        s.setText(subtitle);
    }

    @Override
    protected void onStart() {
        super.onStart();
        App.addServiceStateListener(this, true);
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateEditRow();
    }

    @Override
    protected void onStop() {
        App.removeServiceStateListener(this);
        super.onStop();
    }

    @Override
    public void onServiceStateChanged(XposedService svc) {
        service = svc;
        runOnUiThread(this::updateEditRow);
    }

    private void updateEditRow() {
        boolean hasUser = remoteFileExists(Config.KEYBOX_FILE);
        setRowSubtitle(rowEdit, getString(
                hasUser ? R.string.row_edit_subtitle_present : R.string.row_edit_subtitle_absent));
    }

    private void confirmClear() {
        if (service == null) { toast(getString(R.string.toast_not_connected)); return; }
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.confirm_clear_title)
                .setMessage(R.string.confirm_clear_msg)
                .setPositiveButton(R.string.confirm_clear_ok, (d, w) -> {
                    try {
                        service.deleteRemoteFile(Config.KEYBOX_FILE);
                        toast(getString(R.string.toast_cleared));
                    } catch (Throwable t) {
                        toast("Delete failed: " + t.getMessage());
                    }
                    updateEditRow();
                })
                .setNegativeButton(R.string.confirm_cancel, null)
                .show();
    }

    private void pickFile() {
        if (service == null) { toast(getString(R.string.toast_not_connected)); return; }
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"text/xml", "application/xml", "*/*"});
        try {
            startActivityForResult(Intent.createChooser(intent, "Select keybox.xml"), REQ_PICK_KEYBOX);
        } catch (Throwable t) {
            toast("No file picker available");
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_PICK_KEYBOX && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri == null) return;
            try (InputStream in = getContentResolver().openInputStream(uri)) {
                if (in == null) throw new IOException("openInputStream returned null");
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) baos.write(buf, 0, n);
                String xml = baos.toString("UTF-8");
                if (writeRemoteString(Config.KEYBOX_FILE, xml)) {
                    toast(getString(R.string.toast_saved));
                    updateEditRow();
                }
            } catch (Throwable t) {
                toast("Read failed: " + t.getMessage());
            }
        }
    }

    private boolean remoteFileExists(String name) {
        XposedService svc = service;
        if (svc == null) return false;
        try {
            String[] list = svc.listRemoteFiles();
            return list != null && new HashSet<>(Arrays.asList(list)).contains(name);
        } catch (Throwable t) {
            return false;
        }
    }

    private boolean writeRemoteString(String name, String content) {
        XposedService svc = service;
        if (svc == null) { toast(getString(R.string.toast_not_connected)); return false; }
        try { svc.deleteRemoteFile(name); } catch (Throwable ignored) {}
        ParcelFileDescriptor pfd = null;
        try {
            pfd = svc.openRemoteFile(name);
            if (pfd == null) throw new IOException("openRemoteFile returned null");
            try (FileOutputStream out = new FileOutputStream(pfd.getFileDescriptor())) {
                out.write(content.getBytes(StandardCharsets.UTF_8));
                out.getFD().sync();
            }
            return true;
        } catch (Throwable t) {
            toast("Write failed: " + t.getMessage());
            return false;
        } finally {
            if (pfd != null) try { pfd.close(); } catch (Throwable ignored) {}
        }
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}
