package app.mintun.client;

import android.net.DnsResolver;
import android.net.Network;
import android.os.Build;
import android.os.CancellationSignal;
import android.system.OsConstants;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import io.nekohasekai.libbox.ExchangeContext;
import io.nekohasekai.libbox.LocalDNSTransport;

/** Local DNS always uses the selected physical network, never the app's VPN network. */
final class AndroidResolver implements LocalDNSTransport {
    private final AndroidPlatform platform;
    AndroidResolver(AndroidPlatform owner) { platform = owner; }
    @Override public boolean raw() { return Build.VERSION.SDK_INT >= 29; }
    @Override public void lookup(ExchangeContext context, String family, String domain) throws Exception {
        Network network = platform.physicalNetwork();
        if (network == null) { context.errnoCode(OsConstants.ENETUNREACH); return; }
        StringBuilder addresses = new StringBuilder();
        try {
            for (InetAddress address : network.getAllByName(domain)) {
                if (("ip4".equals(family) && !(address instanceof Inet4Address))
                        || ("ip6".equals(family) && !(address instanceof Inet6Address))) continue;
                if (addresses.length() != 0) addresses.append('\n');
                addresses.append(address.getHostAddress());
            }
            context.success(addresses.toString());
        } catch (java.net.UnknownHostException e) { context.errorCode(3); }
    }
    @Override public void exchange(ExchangeContext context, byte[] message) throws Exception {
        if (Build.VERSION.SDK_INT < 29) throw new UnsupportedOperationException("Raw Android DNS requires Android 10");
        exchangeModern(context, message);
    }
    @android.annotation.TargetApi(29)
    private void exchangeModern(ExchangeContext context, byte[] message) throws Exception {
        Network network = platform.physicalNetwork();
        if (network == null) { context.errnoCode(OsConstants.ENETUNREACH); return; }
        CancellationSignal cancellation = new CancellationSignal();
        java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicBoolean completed = new java.util.concurrent.atomic.AtomicBoolean();
        context.onCancel(() -> {
            cancellation.cancel();
            if (completed.compareAndSet(false, true)) {
                context.errnoCode(OsConstants.ECANCELED);
                done.countDown();
            }
        });
        DnsResolver.getInstance().rawQuery(network, message, DnsResolver.FLAG_EMPTY,
                AppBridge.IO, cancellation, new DnsResolver.Callback<byte[]>() {
                    @Override public void onAnswer(byte[] answer, int rcode) {
                        if (completed.compareAndSet(false, true)) {
                            if (rcode == 0) context.rawSuccess(answer); else context.errorCode(rcode);
                            done.countDown();
                        }
                    }
                    @Override public void onError(DnsResolver.DnsException error) {
                        if (completed.compareAndSet(false, true)) {
                            context.errnoCode(OsConstants.EIO);
                            done.countDown();
                        }
                    }
                });
        done.await();
    }
}
