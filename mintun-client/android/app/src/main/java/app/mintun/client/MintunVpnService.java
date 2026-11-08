package app.mintun.client;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.MintunService;

/** Sole owner of the Go core and Android TUN. The activity may be hidden or destroyed. */
public final class MintunVpnService extends VpnService {
    private static final String CHANNEL = "mintun.vpn";
    private static final int NOTIFICATION = 10;
    private static final String STOP = "app.mintun.client.STOP";
    private static volatile MintunVpnService instance;
    private final ExecutorService lifecycle = Executors.newSingleThreadExecutor();
    private final CompletableFuture<Void> destroyed = new CompletableFuture<>();
    private MintunService core;
    private AndroidPlatform platform;
    private ParcelFileDescriptor tunnel;

    @Override public void onCreate() {
        super.onCreate();
        instance = this;
        getSystemService(NotificationManager.class).createNotificationChannel(
                new NotificationChannel(CHANNEL, "VPN connection", NotificationManager.IMPORTANCE_LOW));
    }
    private Notification notification(boolean connected) {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, MintunVpnService.class).setAction(STOP),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_mintun)
                .setContentTitle("MinTun").setContentText(connected ? "VPN connected" : "Connecting VPN")
                .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
                .setCategory(Notification.CATEGORY_SERVICE)
                .addAction(new Notification.Action.Builder(null, "Disconnect", stop).build()).build();
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) { requestStop(); return START_NOT_STICKY; }
        // Must happen immediately, before Go initialization or any waiting.
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION, notification(false), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(NOTIFICATION, notification(false));
        AppBridge.StartRequest request = AppBridge.PENDING_START.getAndSet(null);
        if (request == null) {
            if (!AppBridge.running) stopSelf();
            return START_NOT_STICKY;
        }
        lifecycle.execute(() -> startCore(request));
        // Never persist a decrypted profile just to auto-restart after process death.
        return START_NOT_STICKY;
    }
    private void startCore(AppBridge.StartRequest request) {
        try {
            if (request.cancelled) throw new IllegalStateException();
            if (core != null) throw new IllegalStateException("VPN is already connected");
            AppBridge.initializeCore();
            if (VpnService.prepare(this) != null) throw new SecurityException();
            platform = new AndroidPlatform(this);
            core = Libbox.newMintunService(request.json, platform);
            core.start();
            if (request.cancelled) throw new IllegalStateException();
            AppBridge.activeProxy = request.proxy;
            AppBridge.serviceChanged(true);
            getSystemService(NotificationManager.class).notify(NOTIFICATION, notification(true));
            request.finished.complete(null);
        } catch (Exception error) {
            stopCore();
            request.finished.completeExceptionally(new IllegalStateException("Could not start the embedded Android VPN; verify profile compatibility and VPN consent"));
            stopSelf();
        } finally { request.json = null; }
    }
    synchronized void retainTunnel(ParcelFileDescriptor descriptor) throws java.io.IOException {
        if (tunnel != null) throw new java.io.IOException("Configuration attempted to open multiple tunnels");
        tunnel = descriptor;
    }
    private void stopCore() {
        MintunService previous = core;
        core = null;
        if (previous != null) {
            try { previous.close(); } catch (Exception ignored) { /* Continue closing our Android descriptor. */ }
        }
        if (platform != null) { platform.close(); platform = null; }
        synchronized (this) {
            if (tunnel != null) {
                try { tunnel.close(); } catch (java.io.IOException ignored) { }
                tunnel = null;
            }
        }
        if (instance == this) AppBridge.serviceChanged(false);
        stopForeground(STOP_FOREGROUND_REMOVE);
    }
    static void requestStop() {
        MintunVpnService current = instance;
        if (current == null) return;
        try { current.lifecycle.execute(() -> { current.stopCore(); current.stopSelf(); }); }
        catch (java.util.concurrent.RejectedExecutionException ignored) { /* onDestroy already owns shutdown. */ }
    }
    static void stopAndWait() throws Exception {
        MintunVpnService current = instance;
        if (current == null) return;
        CompletableFuture<Void> done = new CompletableFuture<>();
        try {
            current.lifecycle.execute(() -> {
                try { current.stopCore(); current.stopSelf(); done.complete(null); }
                catch (Exception error) { done.completeExceptionally(new IllegalStateException("Could not close the Android VPN")); }
            });
        } catch (java.util.concurrent.RejectedExecutionException closing) {
            current.destroyed.get(30, TimeUnit.SECONDS);
            return;
        }
        done.get(30, TimeUnit.SECONDS);
    }
    @Override public void onRevoke() { requestStop(); }
    @Override public void onDestroy() {
        lifecycle.execute(() -> {
            try { stopCore(); }
            finally {
                if (instance == this) instance = null;
                destroyed.complete(null);
            }
        });
        lifecycle.shutdown();
        super.onDestroy();
    }
}
