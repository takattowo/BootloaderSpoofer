package com.takattowo.bootloaderspoofer;

import android.content.Intent;
import android.content.pm.PackageInfo;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

public class AboutActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_about);

        ImageButton back = findViewById(R.id.btn_back);
        back.setOnClickListener(v -> finish());

        TextView version = findViewById(R.id.about_version);
        version.setText(buildVersionString());

        View rowSource = findViewById(R.id.row_source);
        bindRow(rowSource, R.drawable.ic_github,
                getString(R.string.row_source_title),
                getString(R.string.row_source_subtitle),
                v -> openUrl(getString(R.string.repo_url)));

        View rowLicenses = findViewById(R.id.row_licenses);
        bindRow(rowLicenses, R.drawable.ic_gavel,
                getString(R.string.row_licenses_title),
                getString(R.string.row_licenses_subtitle),
                v -> showLicenses());

        View rowIssue = findViewById(R.id.row_issue);
        bindRow(rowIssue, R.drawable.ic_bug,
                getString(R.string.row_issue_title),
                getString(R.string.row_issue_subtitle),
                v -> openUrl(getString(R.string.repo_issues_url)));
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

    private String buildVersionString() {
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), 0);
            long code = android.os.Build.VERSION.SDK_INT >= 28
                    ? info.getLongVersionCode()
                    : info.versionCode;
            return getString(R.string.about_version_fmt, info.versionName, code, "release");
        } catch (Throwable t) {
            return "";
        }
    }

    private void openUrl(String url) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
        } catch (Throwable t) {
            Toast.makeText(this, "No browser available", Toast.LENGTH_SHORT).show();
        }
    }

    private void showLicenses() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.row_licenses_title)
                .setMessage(R.string.licenses_body)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }
}
