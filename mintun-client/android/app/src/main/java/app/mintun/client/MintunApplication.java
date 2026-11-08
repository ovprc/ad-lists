package app.mintun.client;

import android.app.Application;

public final class MintunApplication extends Application {
    @Override public void onCreate() {
        super.onCreate();
        System.loadLibrary("mintun_client");
        AppBridge.initialize(this);
    }
}
