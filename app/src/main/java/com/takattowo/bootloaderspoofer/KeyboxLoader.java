package com.takattowo.bootloaderspoofer;

import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Objects;

/**
 * Loads keyboxes into a KeyboxRegistry from TrickyStore-format XML, with per-algorithm
 * fallback to bundled {@link KeyboxData} for any algorithm missing from the user file.
 *
 * Caller-agnostic - safe to use from module process (UI) or target process.
 */
final class KeyboxLoader {

    static final class Result {
        final KeyboxRegistry registry;
        final String source;
        final boolean userEC;
        final boolean userRSA;
        final String ecExpiry;
        final String rsaExpiry;
        final boolean ecExpired;
        final boolean rsaExpired;

        Result(KeyboxRegistry registry, String source,
               boolean userEC, boolean userRSA,
               String ecExpiry, String rsaExpiry,
               boolean ecExpired, boolean rsaExpired) {
            this.registry = registry;
            this.source = source;
            this.userEC = userEC;
            this.userRSA = userRSA;
            this.ecExpiry = ecExpiry;
            this.rsaExpiry = rsaExpiry;
            this.ecExpired = ecExpired;
            this.rsaExpired = rsaExpired;
        }
    }

    static Result loadFromXmlOrBundled(String xml) {
        KeyboxRegistry registry = new KeyboxRegistry();
        boolean ec = false;
        boolean rsa = false;

        if (xml != null) {
            try {
                XMLParser parser = new XMLParser(xml);
                int numberOfKeyboxes = Integer.parseInt(Objects.requireNonNull(
                        parser.obtainPath("AndroidAttestation.NumberOfKeyboxes").get("text")).trim());
                for (int i = 0; i < numberOfKeyboxes; i++) {
                    String algo = parser.obtainPath("AndroidAttestation.Keybox.Key[" + i + "]").get("algorithm");
                    String privateKey = parser.obtainPath("AndroidAttestation.Keybox.Key[" + i + "].PrivateKey").get("text");
                    int numCerts = Integer.parseInt(Objects.requireNonNull(parser.obtainPath(
                            "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.NumberOfCertificates").get("text")).trim());
                    LinkedList<Certificate> chain = new LinkedList<>();
                    for (int j = 0; j < numCerts; j++) {
                        String certText = parser.obtainPath(
                                "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]").get("text");
                        chain.add(parseCert(certText));
                    }
                    String key = "ecdsa".equalsIgnoreCase(algo)
                            ? KeyProperties.KEY_ALGORITHM_EC
                            : KeyProperties.KEY_ALGORITHM_RSA;
                    registry.put(key, parseKeyPair(privateKey), chain);
                    if (KeyProperties.KEY_ALGORITHM_EC.equals(key)) ec = true;
                    else rsa = true;
                }
            } catch (Throwable t) {
                Log.w(ModuleMain.TAG, "parse keybox.xml failed; will fall back to bundled", t);
            }
        }

        boolean userEC = ec;
        boolean userRSA = rsa;

        if (!registry.has(KeyProperties.KEY_ALGORITHM_EC)) {
            try {
                registry.put(KeyProperties.KEY_ALGORITHM_EC,
                        parseKeyPair(KeyboxData.EC.PRIVATE_KEY),
                        parseChain(KeyboxData.EC.CERTIFICATE_1, KeyboxData.EC.CERTIFICATE_2));
            } catch (Throwable t) {
                Log.e(ModuleMain.TAG, "bundled EC parse failed", t);
            }
        }
        if (!registry.has(KeyProperties.KEY_ALGORITHM_RSA)) {
            try {
                registry.put(KeyProperties.KEY_ALGORITHM_RSA,
                        parseKeyPair(KeyboxData.RSA.PRIVATE_KEY),
                        parseChain(KeyboxData.RSA.CERTIFICATE_1, KeyboxData.RSA.CERTIFICATE_2));
            } catch (Throwable t) {
                Log.e(ModuleMain.TAG, "bundled RSA parse failed", t);
            }
        }

        String source;
        if (userEC && userRSA) source = "user keybox.xml";
        else if (userEC || userRSA) source = "user keybox.xml + bundled (mixed)";
        else source = "bundled";

        Date now = new Date();
        ExpiryInfo ecInfo = expiry(registry.get(KeyProperties.KEY_ALGORITHM_EC), now);
        ExpiryInfo rsaInfo = expiry(registry.get(KeyProperties.KEY_ALGORITHM_RSA), now);

        if (ecInfo.expired) {
            Log.e(ModuleMain.TAG, "EC keybox chain is EXPIRED (" + ecInfo.text
                    + "). Attestation will be rejected. Supply a fresh keybox.xml via the UI.");
        }
        if (rsaInfo.expired) {
            Log.e(ModuleMain.TAG, "RSA keybox chain is EXPIRED (" + rsaInfo.text
                    + "). Attestation will be rejected. Supply a fresh keybox.xml via the UI.");
        }

        return new Result(registry, source, userEC, userRSA,
                ecInfo.text, rsaInfo.text, ecInfo.expired, rsaInfo.expired);
    }

    private static final class ExpiryInfo {
        final String text;
        final boolean expired;

        ExpiryInfo(String text, boolean expired) {
            this.text = text;
            this.expired = expired;
        }
    }

    private static ExpiryInfo expiry(KeyboxRegistry.Entry e, Date now) {
        if (e == null || e.certificates == null || e.certificates.isEmpty()) {
            return new ExpiryInfo("n/a", false);
        }
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
        Date earliest = null;
        boolean anyExpired = false;
        for (Certificate c : e.certificates) {
            if (!(c instanceof X509Certificate x)) continue;
            Date notAfter = x.getNotAfter();
            if (notAfter.before(now)) anyExpired = true;
            if (earliest == null || notAfter.before(earliest)) earliest = notAfter;
        }
        if (earliest == null) return new ExpiryInfo("unknown", false);
        return new ExpiryInfo(fmt.format(earliest) + (anyExpired ? " EXPIRED" : ""), anyExpired);
    }

    private static LinkedList<Certificate> parseChain(String... pems) throws Throwable {
        LinkedList<Certificate> out = new LinkedList<>();
        for (String pem : pems) out.add(parseCert(pem));
        return out;
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(XMLParser.trimLine(key)))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        try (PemReader reader = new PemReader(new StringReader(XMLParser.trimLine(cert)))) {
            return CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
    }

    private KeyboxLoader() {}
}
