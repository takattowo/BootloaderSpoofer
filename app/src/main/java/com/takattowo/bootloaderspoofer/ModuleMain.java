package com.takattowo.bootloaderspoofer;

import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

import io.github.libxposed.api.XposedModule;

public class ModuleMain extends XposedModule {

    static final String TAG = "BootloaderSpoofer";

    private volatile KeyboxRegistry registry;
    private volatile String mode = Config.MODE_LEAF_HACK;
    private volatile boolean loaded = false;

    private final Map<Object, KeyGenParameters> specByGenerator =
            Collections.synchronizedMap(new WeakHashMap<>());
    private final Map<String, Certificate[]> chainByAlias = new ConcurrentHashMap<>();

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        log(Log.INFO, TAG, "module loaded in " + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!param.isFirstPackage()) return;

        ensureLoaded();
        if (Config.MODE_OFF.equals(mode)) {
            log(Log.INFO, TAG, "mode=off for " + param.getPackageName() + "; no hooks installed");
            return;
        }

        ClassLoader cl = param.getDefaultClassLoader();
        hookPackageManager(cl);

        Class<?> delegateClass = probeKeyPairGeneratorClass();
        if (delegateClass != null) {
            hookKeyPairGeneratorInitialize(delegateClass);
            hookKeyPairGenerators(delegateClass);
        }
        hookKeyStoreSpi();
    }

    private Class<?> probeKeyPairGeneratorClass() {
        for (String algo : new String[]{"EC", "RSA"}) {
            try {
                return KeyPairGenerator.getInstance(algo).getClass();
            } catch (Throwable ignored) {
            }
        }
        log(Log.WARN, TAG, "could not probe KeyPairGenerator class");
        return null;
    }

    private synchronized void ensureLoaded() {
        if (loaded) return;
        String xml = RemoteFiles.read(this, Config.KEYBOX_FILE);
        KeyboxLoader.Result r = KeyboxLoader.loadFromXmlOrBundled(xml);
        registry = r.registry;
        mode = Config.normalizeMode(RemoteFiles.read(this, Config.MODE_FILE));
        loaded = true;
        log(Log.INFO, TAG, "keybox source=" + r.source
                + " (userEC=" + r.userEC + " userRSA=" + r.userRSA + ")"
                + " EC expiry=" + r.ecExpiry + " RSA expiry=" + r.rsaExpiry
                + " mode=" + mode);
        if (r.ecExpired || r.rsaExpired) {
            log(Log.ERROR, TAG, "*** KEYBOX CHAIN EXPIRED *** Attestation will be rejected. "
                    + "Open the Bootloader Spoofer app and load a fresh keybox.xml.");
        }
    }

    private void hookPackageManager(ClassLoader cl) {
        try {
            Class<?> pmClass = Class.forName("android.app.ApplicationPackageManager", false, cl);

            Method m1 = pmClass.getDeclaredMethod("hasSystemFeature", String.class);
            hook(m1).intercept(chain -> spoofedSystemFeature((String) chain.getArg(0), chain));

            Method m2 = pmClass.getDeclaredMethod("hasSystemFeature", String.class, int.class);
            hook(m2).intercept(chain -> spoofedSystemFeature((String) chain.getArg(0), chain));

            log(Log.INFO, TAG, "hooked ApplicationPackageManager.hasSystemFeature");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "hasSystemFeature hook failed", t);
        }
    }

    private static Object spoofedSystemFeature(String featureName, io.github.libxposed.api.XposedInterface.Chain chain) throws Throwable {
        if (PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(featureName)
                || PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(featureName)
                || "android.software.device_id_attestation".equals(featureName)) {
            return Boolean.FALSE;
        }
        return chain.proceed();
    }

    private void hookKeyPairGeneratorInitialize(Class<?> delegateClass) {
        try {
            Method m1 = findConcreteMethod(delegateClass, "initialize", AlgorithmParameterSpec.class);
            if (m1 != null) {
                hook(m1).intercept(chain -> {
                    captureSpec(chain.getThisObject(), chain.getArg(0));
                    return chain.proceed();
                });
                log(Log.INFO, TAG, "hooked " + m1.getDeclaringClass().getName() + ".initialize(spec)");
            }
            Method m2 = findConcreteMethod(delegateClass, "initialize",
                    AlgorithmParameterSpec.class, SecureRandom.class);
            if (m2 != null) {
                hook(m2).intercept(chain -> {
                    captureSpec(chain.getThisObject(), chain.getArg(0));
                    return chain.proceed();
                });
                log(Log.INFO, TAG, "hooked " + m2.getDeclaringClass().getName() + ".initialize(spec,rand)");
            }
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "KeyPairGenerator.initialize hook failed", t);
        }
    }

    private void captureSpec(Object gen, Object specObj) {
        if (!(specObj instanceof KeyGenParameterSpec spec) || gen == null) return;
        try {
            if (!(gen instanceof KeyPairGenerator kpg)) return;
            if (!"AndroidKeyStore".equals(kpg.getProvider().getName())) return;
            String reqAlgo = kpg.getAlgorithm();
            KeyGenParameters params = KeyGenParameters.from(spec, reqAlgo);
            specByGenerator.put(gen, params);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "captureSpec failed", t);
        }
    }

    private void hookKeyPairGenerators(Class<?> delegateClass) {
        try {
            Method m = findConcreteMethod(delegateClass, "generateKeyPair");
            if (m == null) {
                log(Log.WARN, TAG, "KeyPairGenerator.generateKeyPair not found");
                return;
            }
            hook(m).intercept(chain -> {
                Object gen = chain.getThisObject();
                KeyGenParameters params = gen != null ? specByGenerator.get(gen) : null;
                if (params == null) {
                    return chain.proceed();
                }
                if (!(gen instanceof KeyPairGenerator kpg)
                        || !"AndroidKeyStore".equals(kpg.getProvider().getName())) {
                    return chain.proceed();
                }

                if (Config.MODE_CERT_GENERATE.equals(mode)) {
                    CertHack.Result r = CertHack.generateLeaf(params, registry);
                    if (r != null) {
                        if (params.alias != null) chainByAlias.put(params.alias, r.chain);
                        log(Log.INFO, TAG, "cert_generate: synthesized chain for alias=" + params.alias
                                + " algo=" + params.algorithm);
                        return r.keyPair;
                    }
                    log(Log.WARN, TAG, "cert_generate failed, falling through to real generateKeyPair");
                }
                return chain.proceed();
            });
            log(Log.INFO, TAG, "hooked " + m.getDeclaringClass().getName() + ".generateKeyPair");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "generateKeyPair hook failed", t);
        }
    }

    private static Method findDeclaredMethod(Class<?> start, String name, Class<?>... params) {
        for (Class<?> c = start; c != null; c = c.getSuperclass()) {
            try {
                return c.getDeclaredMethod(name, params);
            } catch (NoSuchMethodException ignored) {
            }
        }
        return null;
    }

    private static Method findConcreteMethod(Class<?> start, String name, Class<?>... params) {
        for (Class<?> c = start; c != null; c = c.getSuperclass()) {
            try {
                Method m = c.getDeclaredMethod(name, params);
                if (!Modifier.isAbstract(m.getModifiers())) return m;
            } catch (NoSuchMethodException ignored) {
            }
        }
        return null;
    }

    private void hookKeyStoreSpi() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            Field spiField = KeyStore.class.getDeclaredField("keyStoreSpi");
            spiField.setAccessible(true);
            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) spiField.get(keyStore);
            if (keyStoreSpi == null) {
                log(Log.WARN, TAG, "no keyStoreSpi");
                return;
            }
            Method m = findDeclaredMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class);
            if (m == null) {
                log(Log.WARN, TAG, "engineGetCertificateChain not found");
                return;
            }
            hook(m).intercept(chain -> {
                String alias = (String) chain.getArg(0);

                Certificate[] cached = alias != null ? chainByAlias.get(alias) : null;
                if (cached != null) {
                    return cached;
                }

                Certificate[] caList;
                try {
                    caList = (Certificate[]) chain.proceed();
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "engineGetCertificateChain proceed failed (TEE may be broken)", t);
                    caList = null;
                }

                if (Config.MODE_LEAF_HACK.equals(mode)) {
                    if (caList == null) return null;
                    return CertHack.hackCertificateChain(caList, registry);
                }
                return caList;
            });
            log(Log.INFO, TAG, "hooked " + keyStoreSpi.getClass().getName()
                    + ".engineGetCertificateChain");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "engineGetCertificateChain hook failed", t);
        }
    }
}
