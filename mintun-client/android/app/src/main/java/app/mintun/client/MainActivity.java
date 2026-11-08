package app.mintun.client;

import android.Manifest;
import android.app.NativeActivity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;

/** The only UI is the native Slint activity; Android owns consent and SAF sheets. */
public final class MainActivity extends NativeActivity {
    static final int VPN_CONSENT = 401;
    static final int INVITATION = 402;
    // Each export uses a fresh code in this range so a late result cannot target a later save.
    static final int APPLICATION_EXPORT = 404;
    private static final String EXPORT_COUNTER_STATE = "mintun.apk-export.next-request";

    @Override public void onCreate(Bundle state) {
        if (state != null) AppBridge.restoreExportRequestCounter(state.getInt(EXPORT_COUNTER_STATE, APPLICATION_EXPORT));
        AppBridge.attachActivity(this);
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().getDecorView().addOnLayoutChangeListener((view, left, top, right, bottom,
                oldLeft, oldTop, oldRight, oldBottom) -> AppBridge.updateMetrics(this));
        getWindow().getDecorView().post(() -> AppBridge.updateMetrics(this));
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        state.putInt(EXPORT_COUNTER_STATE, AppBridge.exportRequestCounter());
        super.onSaveInstanceState(state);
    }

    @Override protected void onResume() {
        super.onResume();
        AppBridge.attachActivity(this);
    }

    @Override public void onConfigurationChanged(android.content.res.Configuration configuration) {
        super.onConfigurationChanged(configuration);
        AppBridge.updateMetrics(this);
    }

    void requestVpnConsent() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 403);
            return;
        }
        openVpnConsent();
    }

    private void openVpnConsent() {
        Intent consent = VpnService.prepare(this);
        if (consent == null) AppBridge.finishConsent(true);
        else startActivityForResult(consent, VPN_CONSENT);
    }

    void openInvitation() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivityForResult(intent, INVITATION);
    }

    void openApplicationExport(int requestCode, String basename) {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/vnd.android.package-archive");
        intent.putExtra(Intent.EXTRA_TITLE, basename);
        intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        startActivityForResult(intent, requestCode);
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        // Android permits foreground VPNs even when notification-drawer permission is denied.
        if (request == 403) openVpnConsent();
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == VPN_CONSENT) AppBridge.finishConsent(result == RESULT_OK);
        if (request == INVITATION) {
            AppBridge.finishInvitation(result == RESULT_OK && data != null ? data.getData() : null);
        }
        if (request >= APPLICATION_EXPORT) {
            AppBridge.finishApplicationExport(request, result == RESULT_OK && data != null ? data.getData() : null);
        }
    }

    @Override protected void onDestroy() {
        AppBridge.detachActivity(this);
        // The foreground service owns libbox and its descriptor, not this activity.
        super.onDestroy();
    }
}
