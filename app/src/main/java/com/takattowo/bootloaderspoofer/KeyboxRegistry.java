package com.takattowo.bootloaderspoofer;

import android.security.keystore.KeyProperties;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class KeyboxRegistry {

    static final class Entry {
        final PEMKeyPair pemKeyPair;
        final KeyPair keyPair;
        final List<Certificate> certificates;

        Entry(PEMKeyPair pemKeyPair, KeyPair keyPair, List<Certificate> certificates) {
            this.pemKeyPair = pemKeyPair;
            this.keyPair = keyPair;
            this.certificates = certificates;
        }
    }

    private final Map<String, Entry> byAlgorithm = new HashMap<>();

    void put(String algorithmKey, PEMKeyPair pemKp, List<Certificate> chain) throws Throwable {
        KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKp);
        byAlgorithm.put(algorithmKey, new Entry(pemKp, kp, chain));
    }

    Entry get(String algorithmKey) {
        return byAlgorithm.get(algorithmKey);
    }

    Entry forAlgorithmInt(int keymintAlgorithm) {
        return byAlgorithm.get(keymintAlgorithm == KeymintConst.Algorithm.EC
                ? KeyProperties.KEY_ALGORITHM_EC
                : KeyProperties.KEY_ALGORITHM_RSA);
    }

    boolean isEmpty() {
        return byAlgorithm.isEmpty();
    }

    boolean has(String algorithmKey) {
        return byAlgorithm.containsKey(algorithmKey);
    }
}
