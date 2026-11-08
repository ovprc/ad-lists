package app.mintun.client;

import android.app.Application;
import android.net.Uri;
import android.net.VpnService;
import android.os.Looper;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.SetupOptions;

/** JNI API. Blocking methods are invoked only by the Rust application worker, never the UI thread. */
public final class AppBridge {
    private static final String KEY_ALIAS = "app.mintun.client.state.v1";
    private static final byte[] STATE_AAD = "MinTun.Android.State.v1".getBytes(StandardCharsets.US_ASCII);
    private static Application application;
    private static WeakReference<MainActivity> activity = new WeakReference<>(null);
    private static CompletableFuture<Boolean> consent;
    private static CompletableFuture<String> invitation;
    private static int invitationLimit;
    private static ApplicationExport applicationExport;
    private static int nextApplicationExportCode = MainActivity.APPLICATION_EXPORT;
    private static final long MAX_APK_BYTES = 256L * 1024 * 1024;
    private static final String EXPORT_FAILED = "Не удалось сохранить APK. Скачанный файл остался в MinTun. "
            + "Повторите «Сохранить APK…» и выберите доступную папку; при ошибке проверки скачайте обновление заново. "
            + "Если в выбранной папке остался неполный APK, удалите его вручную.";
    private static final String EXPORT_CANCELLED = "Сохранение APK отменено. Скачанный файл остался в MinTun. "
            + "Для повтора нажмите «Сохранить APK…».";
    private static final String EXPORT_TIMEOUT = "Время сохранения APK истекло. Скачанный файл остался в MinTun. "
            + "Повторите «Сохранить APK…»; если остался неполный APK, удалите его в выбранной папке.";
    private static boolean coreInitialized;
    static final ExecutorService IO = Executors.newFixedThreadPool(2);
    private static volatile float[] metrics = new float[]{0, 0, 0, 0, 1};
    public static float[] uiMetrics() { return metrics.clone(); }
    static native void nativeMetricsChanged();
    static void updateMetrics(MainActivity current) {
        android.view.WindowInsets insets = current.getWindow().getDecorView().getRootWindowInsets();
        float density = current.getResources().getDisplayMetrics().density;
        float left = 0, top = 0, right = 0, bottom = 0;
        if (insets != null) {
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets safe = insets.getInsetsIgnoringVisibility(
                        android.view.WindowInsets.Type.systemBars() | android.view.WindowInsets.Type.displayCutout());
                left = safe.left; top = safe.top; right = safe.right; bottom = safe.bottom;
            } else {
                left = insets.getStableInsetLeft(); top = insets.getStableInsetTop();
                right = insets.getStableInsetRight(); bottom = insets.getStableInsetBottom();
            }
        }
        float[] next = new float[]{left / density, top / density, right / density, bottom / density,
                current.getResources().getConfiguration().fontScale};
        if (!Arrays.equals(metrics, next)) { metrics = next; nativeMetricsChanged(); }
    }
    public static void reportStartupError(String ignored) {
        MainActivity current = requireActivity();
        current.runOnUiThread(() -> new android.app.AlertDialog.Builder(current)
                .setTitle("MinTun could not start")
                .setMessage("The native interface could not be initialized. Restart MinTun or install a compatible APK.")
                .setPositiveButton(android.R.string.ok, (dialog, which) -> current.finish()).show());
    }
    static final AtomicReference<StartRequest> PENDING_START = new AtomicReference<>();
    static volatile boolean running;
    static volatile String[] activeProxy;

    private AppBridge() {}
    static void initialize(Application context) { application = context; }
    static synchronized void attachActivity(MainActivity value) { activity = new WeakReference<>(value); }
    static synchronized void detachActivity(MainActivity value) {
        if (activity.get() == value) activity.clear();
    }
    static Application context() { return application; }
    private static synchronized MainActivity requireActivity() {
        MainActivity value = activity.get();
        if (value == null || value.isFinishing()) throw new IllegalStateException("Open MinTun to complete this action");
        return value;
    }
    private static void requireWorker() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Blocking Android operation must run on the application worker");
        }
    }
    public static String dataDirectory() { return application.getFilesDir().getAbsolutePath(); }

    private static synchronized SecretKey stateKey(boolean create) throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        SecretKey key = (SecretKey) store.getKey(KEY_ALIAS, null);
        if (key == null && create) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true).build());
            key = generator.generateKey();
        }
        if (key == null) throw new java.security.GeneralSecurityException("Android state key is unavailable");
        return key;
    }
    public static byte[] protectState(byte[] plaintext) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, stateKey(true));
            cipher.updateAAD(STATE_AAD);
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(4 + 12 + ciphertext.length)
                    .put(new byte[]{'M', 'T', 'A', 1}).put(cipher.getIV()).put(ciphertext).array();
        } finally { Arrays.fill(plaintext, (byte) 0); }
    }
    public static byte[] unprotectState(byte[] protectedBytes) throws Exception {
        if (protectedBytes.length < 32 || protectedBytes[0] != 'M' || protectedBytes[1] != 'T'
                || protectedBytes[2] != 'A' || protectedBytes[3] != 1) {
            throw new java.security.GeneralSecurityException("Invalid Android encrypted state");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, stateKey(false), new GCMParameterSpec(128, protectedBytes, 4, 12));
        cipher.updateAAD(STATE_AAD);
        return cipher.doFinal(protectedBytes, 16, protectedBytes.length - 16);
    }

    public static String pickInvitation(int maximumBytes) throws Exception {
        requireWorker();
        if (maximumBytes < 1 || maximumBytes > 16 * 1024 * 1024) throw new IllegalArgumentException("Invalid invitation size bound");
        CompletableFuture<String> request = new CompletableFuture<>();
        synchronized (AppBridge.class) {
            if (invitation != null) throw new IllegalStateException("An invitation picker is already open");
            invitation = request;
            invitationLimit = maximumBytes;
        }
        try {
            MainActivity current = requireActivity();
            current.runOnUiThread(() -> {
                try { current.openInvitation(); }
                catch (Exception e) { request.completeExceptionally(new IllegalStateException("Could not open Android file picker")); }
            });
            return request.get(120, TimeUnit.SECONDS);
        } finally {
            request.completeExceptionally(new java.util.concurrent.CancellationException("Invitation picker closed"));
            synchronized (AppBridge.class) { if (invitation == request) invitation = null; }
        }
    }
    static void finishInvitation(Uri uri) {
        final CompletableFuture<String> request;
        final int maximum;
        synchronized (AppBridge.class) { request = invitation; maximum = invitationLimit; }
        if (request == null) return;
        if (uri == null) { request.complete(null); return; }
        android.os.CancellationSignal cancellation = new android.os.CancellationSignal();
        AtomicReference<android.content.res.AssetFileDescriptor> opened = new AtomicReference<>();
        request.whenComplete((value, failure) -> {
            cancellation.cancel();
            android.content.res.AssetFileDescriptor descriptor = opened.getAndSet(null);
            if (descriptor != null) try { descriptor.close(); } catch (java.io.IOException ignored) { }
        });
        IO.execute(() -> {
            byte[] bytes = null;
            byte[] buffer = new byte[8192];
            try (android.content.res.AssetFileDescriptor asset = application.getContentResolver()
                    .openAssetFileDescriptor(uri, "r", cancellation)) {
                if (asset == null) throw new java.io.IOException();
                opened.set(asset);
                if (request.isDone()) return;
                if (asset.getDeclaredLength() > maximum) throw new IllegalArgumentException("Invitation exceeds the size limit");
                try (InputStream input = asset.createInputStream(); WipingBytes output = new WipingBytes()) {
                    int total = 0;
                    for (;;) {
                        if (request.isDone()) return;
                        int count = input.read(buffer, 0, Math.min(buffer.length, maximum - total + 1));
                        if (count == -1) break;
                        total += count;
                        if (total > maximum) throw new IllegalArgumentException("Invitation exceeds the size limit");
                        output.write(buffer, 0, count);
                    }
                    bytes = output.toByteArray();
                    String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
                    request.complete(text);
                }
            } catch (Exception e) {
                request.completeExceptionally(new IllegalArgumentException("Invitation is unreadable, too large, or not UTF-8"));
            } finally {
                opened.set(null);
                Arrays.fill(buffer, (byte) 0);
                if (bytes != null) Arrays.fill(bytes, (byte) 0);
            }
        });
    }
    private static final class WipingBytes extends ByteArrayOutputStream {
        @Override public void close() { Arrays.fill(buf, (byte) 0); reset(); }
    }

    static synchronized void initializeCore() throws Exception {
        if (coreInitialized) return;
        java.io.File root = new java.io.File(application.getFilesDir(), "MinTunClient");
        java.io.File cache = new java.io.File(root, "cache");
        java.io.File temp = new java.io.File(application.getCacheDir(), "libbox");
        if ((!cache.isDirectory() && !cache.mkdirs()) || (!temp.isDirectory() && !temp.mkdirs())) {
            throw new java.io.IOException("Could not create private core directories");
        }
        SetupOptions options = new SetupOptions();
        options.setBasePath(root.getAbsolutePath());
        options.setWorkingPath(cache.getAbsolutePath());
        options.setTempPath(temp.getAbsolutePath());
        options.setFixAndroidStack(true);
        options.setDebug(false);
        options.setLogMaxLines(0);
        options.setOomKillerDisabled(true);
        options.setPowerReportEnabled(false);
        Libbox.mintunSetup(options);
        coreInitialized = true;
    }
    public static String coreVersion() throws Exception { initializeCore(); return Libbox.version(); }
    public static void validate(String json) throws Exception {
        initializeCore();
        try { Libbox.checkConfig(json); }
        catch (Exception e) { throw new IllegalArgumentException("The embedded Android core rejected the configuration"); }
    }
    @SuppressWarnings("deprecation")
    public static void verifyApplication(String apkPath, String expectedVersion) throws Exception {
        java.io.File apk = new java.io.File(apkPath).getCanonicalFile();
        String files = application.getFilesDir().getCanonicalPath() + java.io.File.separator;
        if (!apk.getPath().startsWith(files) || !apk.isFile()) throw new SecurityException("APK is outside private application storage");
        android.content.pm.PackageManager manager = application.getPackageManager();
        int flags = android.os.Build.VERSION.SDK_INT >= 28
                ? android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES : android.content.pm.PackageManager.GET_SIGNATURES;
        android.content.pm.PackageInfo installed = manager.getPackageInfo(application.getPackageName(), flags);
        android.content.pm.PackageInfo archive = manager.getPackageArchiveInfo(apk.getPath(), flags);
        if (archive == null || !application.getPackageName().equals(archive.packageName)) {
            throw new SecurityException("APK does not belong to MinTun");
        }
        long current = android.os.Build.VERSION.SDK_INT >= 28 ? installed.getLongVersionCode() : installed.versionCode;
        long candidate = android.os.Build.VERSION.SDK_INT >= 28 ? archive.getLongVersionCode() : archive.versionCode;
        if (candidate <= current) throw new SecurityException("APK version is not newer than the installed application");
        if (expectedVersion == null || !expectedVersion.equals(archive.versionName)) {
            throw new SecurityException("APK version does not match the selected release");
        }
        if (android.os.Build.VERSION.SDK_INT >= 28) {
            if (installed.signingInfo == null || archive.signingInfo == null) throw new SecurityException("APK signature information is missing");
            android.content.pm.Signature[] oldSigners = installed.signingInfo.getApkContentsSigners();
            android.content.pm.Signature[] newSigners = archive.signingInfo.getApkContentsSigners();
            if (installed.signingInfo.hasMultipleSigners() || archive.signingInfo.hasMultipleSigners()) {
                if (!sameSigners(oldSigners, newSigners)) throw new SecurityException("APK signing certificate does not match MinTun");
            } else {
                // PackageManager verifies the APK signing lineage while parsing. A legitimate
                // key rotation must retain the installed current signer in the candidate history.
                android.content.pm.Signature[] history = archive.signingInfo.getSigningCertificateHistory();
                if (oldSigners == null || oldSigners.length != 1 || history == null
                        || !Arrays.asList(history).contains(oldSigners[0])) {
                    throw new SecurityException("APK signing lineage does not match MinTun");
                }
            }
        } else if (!sameSigners(installed.signatures, archive.signatures)) {
            throw new SecurityException("APK signing certificate does not match MinTun");
        }
    }
    private static boolean sameSigners(android.content.pm.Signature[] left, android.content.pm.Signature[] right) {
        return left != null && right != null && left.length > 0 && left.length == right.length
                && new java.util.HashSet<>(Arrays.asList(left)).equals(new java.util.HashSet<>(Arrays.asList(right)));
    }

    public static native boolean nativeExportCancelled();

    /** Fast cancellation entry point: no Activity, UI work, or blocking provider calls. */
    public static void cancelExport() {
        ApplicationExport request;
        synchronized (AppBridge.class) { request = applicationExport; }
        if (request != null) request.fail(EXPORT_CANCELLED);
    }

    static synchronized int exportRequestCounter() { return nextApplicationExportCode; }
    static synchronized void restoreExportRequestCounter(int counter) {
        // Saved Activity state may outlive this Java process and its pending picker.
        nextApplicationExportCode = Math.max(nextApplicationExportCode, Math.min(0x10000, counter));
    }

    /** Saves only a verified private download, after an explicit Android document-picker result. */
    public static void exportApplication(String apkPath, String expectedVersion) throws Exception {
        requireWorker();
        if (nativeExportCancelled()) throw new CancellationException(EXPORT_CANCELLED);
        final ApplicationExport request;
        synchronized (AppBridge.class) {
            if (applicationExport != null) {
                throw new IllegalStateException("Сохранение APK ещё не завершено. Дождитесь завершения и повторите «Сохранить APK…».");
            }
            // Activity request codes are 16-bit. Never reuse one in this process.
            if (nextApplicationExportCode > 0xffff) {
                throw new IllegalStateException("Перезапустите интерфейс MinTun и повторите «Сохранить APK…».");
            }
            request = new ApplicationExport(nextApplicationExportCode++);
            applicationExport = request;
            request.tasks = 1;
        }
        if (nativeExportCancelled()) {
            request.fail(EXPORT_CANCELLED);
            finishExportTask(request);
            throw new CancellationException(EXPORT_CANCELLED);
        }
        IO.execute(() -> {
            try {
                request.checkActive();
                request.apk = new File(apkPath).getCanonicalFile();
                String basename = request.apk.getName();
                if (basename.length() <= 4 || !basename.endsWith(".apk") || basename.indexOf('\\') >= 0
                        || basename.chars().anyMatch(character -> Character.isISOControl(character))) {
                    throw new SecurityException();
                }
                request.version = expectedVersion;
                verifyApplication(request.apk.getPath(), request.version);
                try (FileInputStream input = openExportSource(request.apk)) {
                    request.input.set(input);
                    request.length = Os.fstat(input.getFD()).st_size;
                    request.digest = transferExport(request, input, null);
                } finally { request.input.set(null); }
                request.checkActive();
                MainActivity current = requireActivity();
                current.runOnUiThread(() -> {
                    try {
                        request.checkActive();
                        request.pickerActivity = new WeakReference<>(current);
                        current.openApplicationExport(request.code, basename);
                    } catch (CancellationException failure) {
                        request.fail(EXPORT_CANCELLED);
                    } catch (Exception failure) { request.fail(EXPORT_FAILED); }
                });
            } catch (CancellationException failure) {
                request.fail(EXPORT_CANCELLED);
            } catch (TimeoutException failure) {
                request.fail(EXPORT_TIMEOUT);
            } catch (Exception failure) {
                request.fail(EXPORT_FAILED);
            } finally { finishExportTask(request); }
        });
        try {
            request.finished.get(120, TimeUnit.SECONDS);
        } catch (TimeoutException failure) {
            // Completion and the caller's timeout can cross at the deadline.
            if (request.fail(EXPORT_TIMEOUT)) throw new IOException(EXPORT_TIMEOUT);
        } catch (InterruptedException failure) {
            boolean cancelled = request.fail(EXPORT_CANCELLED);
            Thread.currentThread().interrupt();
            if (cancelled) throw new CancellationException(EXPORT_CANCELLED);
        } catch (ExecutionException failure) {
            // Only our sanitized messages enter this future, never provider/path details.
            throw new IOException(failure.getCause().getMessage());
        } finally {
            request.fail(EXPORT_CANCELLED);
            if (!request.isPublished()) request.dismissPicker();
            synchronized (AppBridge.class) {
                if (applicationExport == request && request.tasks == 0) applicationExport = null;
            }
        }
    }

    static void finishApplicationExport(int code, Uri uri) {
        final ApplicationExport request;
        synchronized (AppBridge.class) {
            request = applicationExport;
            if (request == null || request.code != code || request.resultReceived || request.finished.isDone()) return;
            request.resultReceived = true;
            request.tasks++;
        }
        IO.execute(() -> {
            Uri createdDocument = null;
            try {
                if (uri == null) { request.fail(EXPORT_CANCELLED); return; }
                request.checkActive();
                if (!"content".equals(uri.getScheme()) || !DocumentsContract.isDocumentUri(application, uri)) {
                    throw new SecurityException();
                }
                // Only this matching, still-live ACTION_CREATE_DOCUMENT result is ours to clean up.
                synchronized (request) {
                    request.checkActive();
                    createdDocument = uri;
                }
                try (FileInputStream input = openExportSource(request.apk)) {
                    request.input.set(input);
                    if (Os.fstat(input.getFD()).st_size != request.length
                            || !MessageDigest.isEqual(request.digest, transferExport(request, input, null))) {
                        throw new SecurityException();
                    }
                    input.getChannel().position(0);
                    verifyApplication(request.apk.getPath(), request.version);
                    StructStat opened = Os.fstat(input.getFD());
                    StructStat named = Os.lstat(request.apk.getPath());
                    if (!request.apk.equals(request.apk.getCanonicalFile()) || !OsConstants.S_ISREG(named.st_mode)
                            || opened.st_dev != named.st_dev || opened.st_ino != named.st_ino
                            || opened.st_size != request.length || named.st_size != request.length) {
                        throw new SecurityException();
                    }
                    request.checkActive();
                    try (ParcelFileDescriptor descriptor = application.getContentResolver()
                            .openFileDescriptor(createdDocument, "w", request.cancellation)) {
                        if (descriptor == null) throw new IOException();
                        request.output.set(descriptor);
                        request.checkActive();
                        try (OutputStream output = new ParcelFileDescriptor.AutoCloseOutputStream(descriptor)) {
                            if (!MessageDigest.isEqual(request.digest, transferExport(request, input, output))) {
                                throw new SecurityException();
                            }
                            output.flush();
                        }
                    }
                } finally {
                    request.input.set(null);
                    request.output.set(null);
                }
                // Publication is committed only after exact bytes and all close operations succeeded.
                request.succeed();
            } catch (CancellationException failure) {
                request.fail(EXPORT_CANCELLED);
            } catch (TimeoutException failure) {
                request.fail(EXPORT_TIMEOUT);
            } catch (Exception failure) {
                request.fail(EXPORT_FAILED);
            } finally {
                if (createdDocument != null && !request.isPublished()) {
                    try { DocumentsContract.deleteDocument(application.getContentResolver(), createdDocument); }
                    catch (Exception ignored) { /* Provider may forbid deletion; recovery message covers this. */ }
                }
                finishExportTask(request);
            }
        });
    }

    private static FileInputStream openExportSource(File apk) throws Exception {
        FileInputStream input = new FileInputStream(Os.open(apk.getPath(),
                OsConstants.O_RDONLY | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW | OsConstants.O_NONBLOCK, 0));
        try {
            StructStat stat = Os.fstat(input.getFD());
            if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_size <= 0 || stat.st_size > MAX_APK_BYTES) {
                throw new SecurityException();
            }
            return input;
        } catch (Exception failure) {
            input.close();
            throw failure;
        }
    }

    private static byte[] transferExport(ApplicationExport request, InputStream input, OutputStream output) throws Exception {
        if (request.length <= 0 || request.length > MAX_APK_BYTES) throw new SecurityException();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        long remaining = request.length;
        while (remaining > 0) {
            request.checkActive();
            int count = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
            if (count < 0) throw new IOException();
            if (count == 0) continue;
            request.checkActive();
            if (output != null) output.write(buffer, 0, count);
            digest.update(buffer, 0, count);
            remaining -= count;
        }
        request.checkActive();
        if (input.read() != -1) throw new IOException();
        return digest.digest();
    }

    private static synchronized void finishExportTask(ApplicationExport request) {
        request.tasks--;
        if (applicationExport == request && request.tasks == 0 && request.finished.isDone()) applicationExport = null;
    }

    private static final class ApplicationExport {
        final int code;
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(120);
        final CompletableFuture<Void> finished = new CompletableFuture<>();
        final CancellationSignal cancellation = new CancellationSignal();
        final AtomicReference<Closeable> input = new AtomicReference<>();
        final AtomicReference<Closeable> output = new AtomicReference<>();
        volatile WeakReference<MainActivity> pickerActivity = new WeakReference<>(null);
        File apk;
        String version;
        long length;
        byte[] digest;
        int tasks; // Guarded by AppBridge.class; includes cleanup, not only the JNI wait.
        boolean resultReceived; // Guarded by AppBridge.class.
        private boolean cancelled;
        private boolean published;
        ApplicationExport(int requestCode) { code = requestCode; }
        synchronized void checkActive() throws TimeoutException {
            if (cancelled || nativeExportCancelled()) throw new CancellationException(EXPORT_CANCELLED);
            if (System.nanoTime() - deadline >= 0) throw new TimeoutException();
        }
        synchronized boolean isPublished() { return published; }
        synchronized void succeed() throws TimeoutException {
            checkActive();
            published = true;
            finished.complete(null);
        }
        boolean fail(String message) {
            synchronized (this) {
                if (published) return false;
                if (cancelled) return true;
                cancelled = true;
                finished.completeExceptionally(EXPORT_CANCELLED.equals(message)
                        ? new CancellationException(message) : new IOException(message));
            }
            // Abort must not wait behind a blocked SAF read/write in the fixed IO pool.
            CompletableFuture.runAsync(() -> {
                close(input.getAndSet(null));
                close(output.getAndSet(null));
                try { cancellation.cancel(); } catch (Exception ignored) { }
            });
            return true;
        }
        void dismissPicker() {
            new android.os.Handler(Looper.getMainLooper()).post(() -> {
                MainActivity owner = pickerActivity.get();
                MainActivity current;
                synchronized (AppBridge.class) { current = activity.get(); }
                if (owner != null) try { owner.finishActivity(code); } catch (Exception ignored) { }
                if (current != null && current != owner) {
                    try { current.finishActivity(code); } catch (Exception ignored) { }
                }
            });
        }
        private static void close(Closeable descriptor) {
            if (descriptor != null) try { descriptor.close(); } catch (IOException ignored) { }
        }
    }
    public static void start(String json, int port, String user, String password) throws Exception {
        requireWorker();
        initializeCore();
        android.content.Intent consentIntent = VpnService.prepare(application);
        StartRequest request = new StartRequest(json, new String[]{Integer.toString(port), user, password});
        CompletableFuture<Boolean> permission = new CompletableFuture<>();
        synchronized (AppBridge.class) {
            if (consent != null || PENDING_START.get() != null || running) throw new IllegalStateException("VPN is already starting or connected");
            consent = permission;
        }
        try {
            if (consentIntent != null) {
                MainActivity current = requireActivity();
                current.runOnUiThread(() -> {
                    try { current.requestVpnConsent(); }
                    catch (Exception e) { permission.completeExceptionally(new IllegalStateException("Could not open VPN consent")); }
                });
            } else { permission.complete(true); }
            if (!permission.get(120, TimeUnit.SECONDS)) throw new SecurityException("Android VPN consent was not granted");
            synchronized (AppBridge.class) {
                if (consent != permission) throw new java.util.concurrent.CancellationException("VPN start cancelled");
                if (!PENDING_START.compareAndSet(null, request)) throw new IllegalStateException("VPN start is already pending");
                consent = null;
            }
        } finally {
            synchronized (AppBridge.class) { if (consent == permission) consent = null; }
        }
        try {
            application.startForegroundService(new android.content.Intent(application, MintunVpnService.class));
            request.finished.get(60, TimeUnit.SECONDS);
        } catch (Exception e) {
            request.cancelled = true;
            PENDING_START.compareAndSet(request, null);
            MintunVpnService.requestStop();
            throw e;
        } finally { request.json = null; }
    }
    static synchronized void finishConsent(boolean granted) { if (consent != null) consent.complete(granted); }
    public static void stop() throws Exception {
        requireWorker();
        StartRequest pending;
        synchronized (AppBridge.class) {
            if (consent != null) { consent.complete(false); consent = null; }
            pending = PENDING_START.getAndSet(null);
        }
        if (pending != null) {
            pending.cancelled = true;
            pending.json = null;
            pending.finished.completeExceptionally(new java.util.concurrent.CancellationException("VPN start cancelled"));
        }
        MintunVpnService.stopAndWait();
    }
    public static boolean isRunning() { return running; }
    public static String[] proxy() { return running ? activeProxy : null; }
    static native void nativeServiceChanged(boolean connected);
    static void serviceChanged(boolean connected) {
        running = connected;
        if (!connected) activeProxy = null;
        nativeServiceChanged(connected);
    }
    static final class StartRequest {
        volatile String json;
        final String[] proxy;
        volatile boolean cancelled;
        final CompletableFuture<Void> finished = new CompletableFuture<>();
        StartRequest(String configuration, String[] endpoint) { json = configuration; proxy = endpoint; }
    }
}
