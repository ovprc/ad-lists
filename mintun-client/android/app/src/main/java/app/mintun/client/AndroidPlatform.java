package app.mintun.client;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.ProxyInfo;
import android.net.RouteInfo;
import android.net.VpnService;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import io.nekohasekai.libbox.*;

/** Android adapter for the exact 1.15.0-alpha.13 PlatformInterface. No shell/root helper is used. */
final class AndroidPlatform implements PlatformInterface, AutoCloseable {
    private final MintunVpnService service;
    private final ConnectivityManager connectivity;
    private final ConcurrentHashMap<Network, LinkProperties> physical = new ConcurrentHashMap<>();
    private final Object monitorLock = new Object();
    private InterfaceUpdateListener listener;
    private ConnectivityManager.NetworkCallback callback;
    private volatile Network underlying;
    private String ownInterface = "";

    AndroidPlatform(MintunVpnService owner) {
        service = owner;
        connectivity = owner.getSystemService(ConnectivityManager.class);
    }
    static StringIterator strings(List<String> values) {
        Iterator<String> iterator = values.iterator();
        return new StringIterator() {
            public boolean hasNext() { return iterator.hasNext(); }
            public String next() { return iterator.next(); }
            public int len() { return values.size(); }
        };
    }
    private static List<String> collect(StringIterator iterator) {
        List<String> values = new ArrayList<>();
        while (iterator.hasNext()) values.add(iterator.next());
        return values;
    }
    @Override public boolean usePlatformAutoDetectInterfaceControl() { return true; }
    @Override public void autoDetectInterfaceControl(int fd) throws Exception {
        if (!service.protect(fd)) throw new java.io.IOException("Android could not protect an outbound socket");
    }
    @Override public int openTun(TunOptions options) throws Exception {
        if (VpnService.prepare(service) != null) throw new SecurityException("Android VPN consent is missing");
        VpnService.Builder builder = service.new Builder().setSession("MinTun").setMtu(options.getMTU())
                .setConfigureIntent(PendingIntent.getActivity(service, 0, new Intent(service, MainActivity.class),
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE));
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false);
        RoutePrefixIterator v4 = options.getInet4Address();
        boolean has4 = v4.hasNext();
        while (v4.hasNext()) { RoutePrefix address = v4.next(); builder.addAddress(address.address(), address.prefix()); }
        RoutePrefixIterator v6 = options.getInet6Address();
        boolean has6 = v6.hasNext();
        while (v6.hasNext()) { RoutePrefix address = v6.next(); builder.addAddress(address.address(), address.prefix()); }
        if (options.getAutoRoute()) {
            if (!Libbox.DNSModeDisabled.equals(options.getDNSMode().getValue())) {
                StringIterator servers = options.getDNSServerAddress();
                while (servers.hasNext()) builder.addDnsServer(servers.next());
            }
            if (Build.VERSION.SDK_INT >= 33) {
                addRoutes(builder, options.getInet4RouteAddress(), has4 ? "0.0.0.0" : null);
                addRoutes(builder, options.getInet6RouteAddress(), has6 ? "::" : null);
                excludeRoutes(builder, options.getInet4RouteExcludeAddress());
                excludeRoutes(builder, options.getInet6RouteExcludeAddress());
            } else {
                addRoutes(builder, options.getInet4RouteRange(), null);
                addRoutes(builder, options.getInet6RouteRange(), null);
            }
            List<String> include = collect(options.getIncludePackage());
            List<String> exclude = collect(options.getExcludePackage());
            if (!include.isEmpty() && !exclude.isEmpty()) throw new IllegalArgumentException("Android cannot combine include and exclude package lists");
            for (String packageName : include) builder.addAllowedApplication(packageName);
            for (String packageName : exclude) builder.addDisallowedApplication(packageName);
        }
        if (options.isHTTPProxyEnabled()) {
            if (Build.VERSION.SDK_INT < 29) throw new UnsupportedOperationException("Android 10 is required for a system HTTP proxy");
            if (options.getHTTPProxyMatchDomain().hasNext()) throw new UnsupportedOperationException("Android does not support HTTP proxy match domains");
            builder.setHttpProxy(ProxyInfo.buildDirectProxy(options.getHTTPProxyServer(), options.getHTTPProxyServerPort(),
                    collect(options.getHTTPProxyBypassDomain())));
        }
        if (underlying != null) builder.setUnderlyingNetworks(new Network[]{underlying});
        ParcelFileDescriptor descriptor = builder.establish();
        if (descriptor == null) throw new java.io.IOException("Android VPN establishment was revoked");
        try { service.retainTunnel(descriptor); }
        catch (Exception e) { descriptor.close(); throw e; }
        // libbox duplicates this fd. The service retains and closes the original after core shutdown.
        return descriptor.getFd();
    }
    private static void addRoutes(VpnService.Builder builder, RoutePrefixIterator routes, String fallback) {
        if (!routes.hasNext() && fallback != null) builder.addRoute(fallback, 0);
        while (routes.hasNext()) { RoutePrefix route = routes.next(); builder.addRoute(route.address(), route.prefix()); }
    }
    @android.annotation.TargetApi(33)
    private static void excludeRoutes(VpnService.Builder builder, RoutePrefixIterator routes) throws java.net.UnknownHostException {
        while (routes.hasNext()) {
            RoutePrefix route = routes.next();
            builder.excludeRoute(new IpPrefix(InetAddress.getByName(route.address()), route.prefix()));
        }
    }
    @Override public ConnectionOwner findConnectionOwner(int protocol, String source, int sourcePort,
            String destination, int destinationPort) throws Exception {
        ConnectionOwner owner;
        if (Build.VERSION.SDK_INT >= 29) {
            int uid = connectivity.getConnectionOwnerUid(protocol, new InetSocketAddress(source, sourcePort),
                    new InetSocketAddress(destination, destinationPort));
            if (uid == android.os.Process.INVALID_UID) throw new java.io.IOException("Connection owner not found");
            owner = new ConnectionOwner();
            owner.setUserId(uid);
        } else {
            owner = Libbox.findConnectionOwner(protocol, source, sourcePort, destination, destinationPort);
        }
        String[] packages = service.getPackageManager().getPackagesForUid(owner.getUserId());
        List<String> names = packages == null ? Collections.emptyList() : Arrays.asList(packages);
        owner.setUserName(names.isEmpty() ? "" : names.get(0));
        owner.setAndroidPackageNames(strings(names));
        return owner;
    }
    @Override public void startDefaultInterfaceMonitor(InterfaceUpdateListener value) throws Exception {
        synchronized (monitorLock) {
            if (callback != null) throw new IllegalStateException("Network monitor is already registered");
            listener = value;
            callback = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { update(network); }
                @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) { physical.put(network, properties); publishNetwork(); }
                @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) { update(network); }
                @Override public void onLost(Network network) { physical.remove(network); publishNetwork(); }
                private void update(Network network) {
                    NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                    LinkProperties properties = connectivity.getLinkProperties(network);
                    if (capabilities != null && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) && properties != null) physical.put(network, properties);
                    else physical.remove(network);
                    publishNetwork();
                }
            };
            NetworkRequest request = new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build();
            connectivity.registerNetworkCallback(request, callback);
            for (Network network : connectivity.getAllNetworks()) {
                NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                LinkProperties properties = connectivity.getLinkProperties(network);
                if (capabilities != null && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && properties != null) physical.put(network, properties);
            }
        }
        publishNetwork();
    }
    private void publishNetwork() {
        synchronized (monitorLock) {
            if (listener == null) return;
            Network selected = connectivity.getActiveNetwork();
            if (selected == null || !physical.containsKey(selected)) {
                selected = null;
                // Prefer validated, unmetered physical networks; never select the VPN itself.
                int best = -1;
                for (Network network : physical.keySet()) {
                    NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
                    if (caps == null) continue;
                    int score = (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? 2 : 0)
                            + (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ? 1 : 0);
                    if (score > best) { selected = network; best = score; }
                }
            }
            underlying = selected;
            service.setUnderlyingNetworks(selected == null ? new Network[0] : new Network[]{selected});
            LinkProperties properties = selected == null ? null : physical.get(selected);
            try {
                NetworkInterface net = properties == null ? null : NetworkInterface.getByName(properties.getInterfaceName());
                NetworkCapabilities caps = selected == null ? null : connectivity.getNetworkCapabilities(selected);
                listener.updateDefaultInterface(net == null ? "" : net.getName(), net == null ? -1 : net.getIndex(),
                        caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED), false);
                listener.updateNetworkPath(net == null ? "offline" : net.getName());
            } catch (java.net.SocketException e) { listener.updateDefaultInterface("", -1, false, false); }
        }
    }
    @Override public void closeDefaultInterfaceMonitor(InterfaceUpdateListener ignored) {
        synchronized (monitorLock) {
            listener = null;
            if (callback != null) { connectivity.unregisterNetworkCallback(callback); callback = null; }
            physical.clear();
            underlying = null;
        }
    }
    @Override public void close() { closeDefaultInterfaceMonitor(null); }
    Network physicalNetwork() { return underlying; }
    @Override public NetworkInterfaceIterator getInterfaces() throws Exception {
        List<io.nekohasekai.libbox.NetworkInterface> interfaces = new ArrayList<>();
        for (Network network : connectivity.getAllNetworks()) {
            LinkProperties properties = connectivity.getLinkProperties(network);
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            if (properties == null || caps == null || properties.getInterfaceName() == null || properties.getInterfaceName().equals(ownInterface)) continue;
            NetworkInterface net = NetworkInterface.getByName(properties.getInterfaceName());
            if (net == null) continue;
            io.nekohasekai.libbox.NetworkInterface entry = new io.nekohasekai.libbox.NetworkInterface();
            entry.setName(net.getName()); entry.setIndex(net.getIndex()); entry.setMTU(net.getMTU());
            List<String> addresses = new ArrayList<>(), dns = new ArrayList<>(), gateways = new ArrayList<>();
            for (LinkAddress address : properties.getLinkAddresses()) addresses.add(address.toString());
            for (InetAddress address : properties.getDnsServers()) dns.add(address.getHostAddress());
            for (RouteInfo route : properties.getRoutes()) {
                if (route.isDefaultRoute() && route.getGateway() != null && !route.getGateway().isAnyLocalAddress()) gateways.add(route.getGateway().getHostAddress());
            }
            entry.setAddresses(strings(addresses)); entry.setDNSServer(strings(dns)); entry.setGateway(strings(gateways));
            String domains = properties.getDomains();
            entry.setDNSSearchDomain(strings(domains == null || domains.isEmpty() ? Collections.emptyList() : Arrays.asList(domains.split(" +"))));
            int flags = net.isUp() ? OsConstants.IFF_UP | OsConstants.IFF_RUNNING : 0;
            if (net.isLoopback()) flags |= OsConstants.IFF_LOOPBACK;
            if (net.isPointToPoint()) flags |= OsConstants.IFF_POINTOPOINT;
            if (net.supportsMulticast()) flags |= OsConstants.IFF_MULTICAST;
            entry.setFlags(flags);
            entry.setType(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ? Libbox.InterfaceTypeWIFI :
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ? Libbox.InterfaceTypeCellular :
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ? Libbox.InterfaceTypeEthernet : Libbox.InterfaceTypeOther);
            entry.setMetered(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED));
            interfaces.add(entry);
        }
        Iterator<io.nekohasekai.libbox.NetworkInterface> iterator = interfaces.iterator();
        return new NetworkInterfaceIterator() {
            public boolean hasNext() { return iterator.hasNext(); }
            public io.nekohasekai.libbox.NetworkInterface next() { return iterator.next(); }
        };
    }
    @Override public LocalDNSTransport localDNSTransport() { return new AndroidResolver(this); }
    @Override public boolean underNetworkExtension() { return false; }
    @Override public boolean includeAllNetworks() { return false; }
    @Override public WIFIState readWIFIState() {
        WifiManager manager = service.getSystemService(WifiManager.class);
        @SuppressWarnings("deprecation") WifiInfo wifi = manager == null ? null : manager.getConnectionInfo();
        if (wifi == null || "<unknown ssid>".equals(wifi.getSSID())) return null;
        String ssid = wifi.getSSID();
        if (ssid != null && ssid.startsWith("\"") && ssid.endsWith("\"")) ssid = ssid.substring(1, ssid.length() - 1);
        return Libbox.newWIFIState(ssid == null ? "" : ssid, wifi.getBSSID() == null ? "" : wifi.getBSSID());
    }
    @Override public void clearDNSCache() {
        // Android exposes no public DNS-cache flush API. Each resolver request targets the current physical Network.
    }
    @Override public void sendNotification(io.nekohasekai.libbox.Notification value) {
        NotificationManager manager = service.getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new android.app.NotificationChannel("mintun.core", "VPN notices", NotificationManager.IMPORTANCE_DEFAULT));
        android.app.Notification.Builder builder = new android.app.Notification.Builder(service, "mintun.core")
                .setSmallIcon(R.drawable.ic_mintun).setContentTitle(value.getTitle()).setContentText(value.getBody()).setAutoCancel(true);
        manager.notify(value.getIdentifier(), value.getTypeID(), builder.build());
    }
    @Override public void cancelNotification(String identifier, int typeID) {
        service.getSystemService(NotificationManager.class).cancel(identifier, typeID);
    }
    @Override public void registerMyInterface(String name) { ownInterface = name; }
    @Override public void startNeighborMonitor(NeighborUpdateListener value) throws Exception {
        throw new UnsupportedOperationException("Neighbor-table monitoring requires Android root and is not available in a VpnService");
    }
    @Override public void closeNeighborMonitor(NeighborUpdateListener value) { }
    @Override public boolean usePlatformShell() { return false; }
    @Override public void checkPlatformShell() throws Exception { throw unavailable("shell"); }
    @Override public ShellSession openShellSession(PlatformUser user, String command, StringIterator environment, String term, int rows, int columns) throws Exception { throw unavailable("shell"); }
    @Override public PlatformUser lookupUser(String username) throws Exception { throw unavailable("system users"); }
    @Override public String lookupSFTPServer() throws Exception { throw unavailable("SFTP server"); }
    @Override public String readSystemSSHHostKey() throws Exception { throw unavailable("system SSH host keys"); }
    @Override public String tailscaleHostname() { return "MinTun-Android"; }
    @Override public boolean usePlatformBridge() { return false; }
    @Override public BridgeSession createBridge(BridgeOptions options) throws Exception { throw unavailable("network bridge"); }
    @Override public boolean usePlatformAutoRedirect() { return false; }
    @Override public AutoRedirectSession createAutoRedirect(byte[] options, AutoRedirectHandler handler) throws Exception { throw unavailable("kernel auto-redirect"); }
    private static UnsupportedOperationException unavailable(String capability) { return new UnsupportedOperationException("Android VpnService does not support " + capability); }
}
