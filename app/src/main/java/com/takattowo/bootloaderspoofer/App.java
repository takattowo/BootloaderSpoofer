package com.takattowo.bootloaderspoofer;

import android.app.Application;

import java.util.concurrent.CopyOnWriteArraySet;

import io.github.libxposed.service.XposedService;
import io.github.libxposed.service.XposedServiceHelper;

public class App extends Application implements XposedServiceHelper.OnServiceListener {

    public interface ServiceStateListener {
        void onServiceStateChanged(XposedService service);
    }

    private static volatile XposedService sService;
    private static final CopyOnWriteArraySet<ServiceStateListener> sListeners = new CopyOnWriteArraySet<>();

    public static XposedService getService() {
        return sService;
    }

    public static void addServiceStateListener(ServiceStateListener listener, boolean notifyImmediately) {
        sListeners.add(listener);
        if (notifyImmediately) listener.onServiceStateChanged(sService);
    }

    public static void removeServiceStateListener(ServiceStateListener listener) {
        sListeners.remove(listener);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        XposedServiceHelper.registerListener(this);
    }

    @Override
    public void onServiceBind(XposedService service) {
        sService = service;
        for (ServiceStateListener l : sListeners) l.onServiceStateChanged(service);
    }

    @Override
    public void onServiceDied(XposedService service) {
        sService = null;
        for (ServiceStateListener l : sListeners) l.onServiceStateChanged(null);
    }
}
