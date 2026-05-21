package com.takattowo.bootloaderspoofer;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Adapted from TrickyStore CertHack (yujincheng08/TrickyStore, GPL-3) for
 * libxposed app-level interception.
 */
final class CertHack {

    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

    private static final CertificateFactory CERT_FACTORY;

    static {
        try {
            CERT_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    static final class Result {
        final KeyPair keyPair;
        final Certificate[] chain;

        Result(KeyPair keyPair, Certificate[] chain) {
            this.keyPair = keyPair;
            this.chain = chain;
        }
    }

    /** Leaf-hack mode: rewrite RoT extension in real leaf, re-sign with keybox. */
    static Certificate[] hackCertificateChain(Certificate[] caList, KeyboxRegistry registry) {
        if (caList == null || caList.length == 0) return caList;
        try {
            X509Certificate leaf = (X509Certificate) CERT_FACTORY.generateCertificate(
                    new ByteArrayInputStream(caList[0].getEncoded()));
            byte[] extBytes = leaf.getExtensionValue(OID.getId());
            if (extBytes == null) return caList;

            X509CertificateHolder leafHolder = new X509CertificateHolder(leaf.getEncoded());
            Extension ext = leafHolder.getExtension(OID);
            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());
            ASN1Encodable[] encodables = sequence.toArray();
            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];
            ASN1EncodableVector vector = new ASN1EncodableVector();
            ASN1Encodable rootOfTrust = null;

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                if (taggedObject.getTagNo() == 704) {
                    rootOfTrust = taggedObject.getBaseObject().toASN1Primitive();
                    continue;
                }
                vector.add(taggedObject);
            }

            String pubAlgo = leaf.getPublicKey().getAlgorithm();
            KeyboxRegistry.Entry k = registry.get(pubAlgo);
            if (k == null) {
                Log.w(ModuleMain.TAG, "no keybox for algorithm " + pubAlgo);
                return caList;
            }
            LinkedList<Certificate> certificates = new LinkedList<>(k.certificates);

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    new X509CertificateHolder(certificates.get(0).getEncoded()).getSubject(),
                    leafHolder.getSerialNumber(),
                    leafHolder.getNotBefore(),
                    leafHolder.getNotAfter(),
                    leafHolder.getSubject(),
                    leafHolder.getSubjectPublicKeyInfo()
            );
            ContentSigner signer = new JcaContentSignerBuilder(leaf.getSigAlgName())
                    .build(k.keyPair.getPrivate());

            byte[] verifiedBootKey = BootKey.getBootKey();
            byte[] verifiedBootHash = null;
            try {
                if (rootOfTrust instanceof ASN1Sequence r && r.size() >= 4) {
                    ASN1Encodable maybeHash = r.getObjectAt(3);
                    if (maybeHash instanceof DEROctetString os) {
                        verifiedBootHash = os.getOctets();
                    }
                }
            } catch (Throwable t) {
                Log.w(ModuleMain.TAG, "failed to extract original boot hash", t);
            }
            if (verifiedBootHash == null) verifiedBootHash = BootKey.getBootHash();

            ASN1Encodable[] rootOfTrustEnc = {
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(verifiedBootHash)
            };
            ASN1Sequence hackedRootOfTrust = new DERSequence(rootOfTrustEnc);
            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, hackedRootOfTrust);
            vector.add(rootOfTrustTagObj);

            ASN1Sequence hackEnforced = new DERSequence(vector);
            encodables[7] = hackEnforced;
            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);
            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);
            builder.addExtension(hackedExt);

            for (ASN1ObjectIdentifier extensionOID : leafHolder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(leafHolder.getExtension(extensionOID));
            }
            certificates.addFirst(new JcaX509CertificateConverter().getCertificate(builder.build(signer)));
            return certificates.toArray(new Certificate[0]);
        } catch (Throwable t) {
            Log.e(ModuleMain.TAG, "hackCertificateChain failed", t);
            return caList;
        }
    }

    /** Cert-generate mode: build new keypair + leaf entirely. Works on broken TEE. */
    static Result generateLeaf(KeyGenParameters params, KeyboxRegistry registry) {
        try {
            KeyboxRegistry.Entry k = registry.forAlgorithmInt(params.algorithm);
            if (k == null) {
                Log.e(ModuleMain.TAG, "no keybox for keymint algorithm " + params.algorithm);
                return null;
            }

            KeyPair kp;
            if (params.algorithm == KeymintConst.Algorithm.EC) {
                kp = buildECKeyPair(params);
            } else if (params.algorithm == KeymintConst.Algorithm.RSA) {
                kp = buildRSAKeyPair(params);
            } else {
                Log.e(ModuleMain.TAG, "unsupported algorithm " + params.algorithm);
                return null;
            }

            X500Name issuer = new X509CertificateHolder(k.certificates.get(0).getEncoded()).getSubject();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    params.certificateSerial,
                    params.certificateNotBefore,
                    params.certificateNotAfter,
                    params.certificateSubject,
                    kp.getPublic()
            );

            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
            Extension keyDescription = createKeyDescriptionExtension(params);
            if (keyDescription != null) certBuilder.addExtension(keyDescription);

            String sigAlg = params.algorithm == KeymintConst.Algorithm.EC ? "SHA256withECDSA" : "SHA256withRSA";
            ContentSigner signer = new JcaContentSignerBuilder(sigAlg).build(k.keyPair.getPrivate());

            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(certHolder);

            List<Certificate> chain = new ArrayList<>(k.certificates.size() + 1);
            chain.add(leaf);
            chain.addAll(k.certificates);
            return new Result(kp, chain.toArray(new Certificate[0]));
        } catch (Throwable t) {
            Log.e(ModuleMain.TAG, "generateLeaf failed", t);
            return null;
        }
    }

    private static KeyPair buildECKeyPair(KeyGenParameters params) throws Exception {
        ECGenParameterSpec spec = new ECGenParameterSpec(params.ecCurveName);
        KeyPairGenerator kpg = pickKpg("EC");
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static KeyPair buildRSAKeyPair(KeyGenParameters params) throws Exception {
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(params.keySize, params.rsaPublicExponent);
        KeyPairGenerator kpg = pickKpg("RSA");
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    /**
     * Pick a {@link KeyPairGenerator} skipping AndroidKeyStore (we're spoofing it) so we
     * fall back to AndroidOpenSSL / Conscrypt. Avoids signed-JAR verification of BC under R8.
     */
    private static KeyPairGenerator pickKpg(String algorithm) throws Exception {
        for (String provider : Arrays.asList("AndroidOpenSSL", "Conscrypt")) {
            try {
                return KeyPairGenerator.getInstance(algorithm, provider);
            } catch (Throwable ignored) {
            }
        }
        return KeyPairGenerator.getInstance(algorithm);
    }

    private static Extension createKeyDescriptionExtension(KeyGenParameters params) {
        try {
            ASN1Encodable[] rootOfTrustEnc = {
                    new DEROctetString(BootKey.getBootKey()),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(BootKey.getBootHash())
            };
            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);

            DERSet aPurpose = new DERSet(fromIntList(params.purpose));
            ASN1Integer aAlgorithm = new ASN1Integer(params.algorithm);
            ASN1Integer aKeySize = new ASN1Integer(params.keySize);
            DERSet aDigest = new DERSet(fromIntList(params.digest));
            ASN1Integer aEcCurve = new ASN1Integer(params.ecCurve);
            DERNull aNoAuthRequired = DERNull.INSTANCE;
            ASN1Integer aOsVersion = new ASN1Integer(BootKey.getOsVersion());
            ASN1Integer aOsPatchLevel = new ASN1Integer(BootKey.getPatchLevel());
            ASN1OctetString aApplicationID = createApplicationId();
            ASN1Integer aBootPatchLevel = new ASN1Integer(BootKey.getPatchLevelLong());
            ASN1Integer aVendorPatchLevel = new ASN1Integer(BootKey.getPatchLevelLong());
            ASN1Integer aCreationDateTime = new ASN1Integer(System.currentTimeMillis());
            ASN1Integer aOrigin = new ASN1Integer(0);

            DERTaggedObject purpose = new DERTaggedObject(true, 1, aPurpose);
            DERTaggedObject algorithm = new DERTaggedObject(true, 2, aAlgorithm);
            DERTaggedObject keySize = new DERTaggedObject(true, 3, aKeySize);
            DERTaggedObject digest = new DERTaggedObject(true, 5, aDigest);
            DERTaggedObject ecCurve = new DERTaggedObject(true, 10, aEcCurve);
            DERTaggedObject noAuthRequired = new DERTaggedObject(true, 503, aNoAuthRequired);
            DERTaggedObject creationDateTime = new DERTaggedObject(true, 701, aCreationDateTime);
            DERTaggedObject origin = new DERTaggedObject(true, 702, aOrigin);
            DERTaggedObject rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            DERTaggedObject osVersion = new DERTaggedObject(true, 705, aOsVersion);
            DERTaggedObject osPatchLevel = new DERTaggedObject(true, 706, aOsPatchLevel);
            DERTaggedObject applicationID = aApplicationID != null
                    ? new DERTaggedObject(true, 709, aApplicationID) : null;
            DERTaggedObject vendorPatchLevel = new DERTaggedObject(true, 718, aVendorPatchLevel);
            DERTaggedObject bootPatchLevel = new DERTaggedObject(true, 719, aBootPatchLevel);

            List<ASN1Encodable> teeList = new ArrayList<>(Arrays.asList(
                    purpose, algorithm, keySize, digest, ecCurve,
                    noAuthRequired, origin, rootOfTrust,
                    osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel));
            ASN1Encodable[] teeEnforcedEncodables = teeList.toArray(new ASN1Encodable[0]);

            List<ASN1Encodable> swList = new ArrayList<>();
            if (applicationID != null) swList.add(applicationID);
            swList.add(creationDateTime);
            ASN1Encodable[] softwareEnforcedEncodables = swList.toArray(new ASN1Encodable[0]);

            ASN1OctetString keyDescriptionOctetStr = wrapKeyDescription(
                    teeEnforcedEncodables, softwareEnforcedEncodables, params);

            return new Extension(OID, false, keyDescriptionOctetStr);
        } catch (Throwable t) {
            Log.e(ModuleMain.TAG, "createKeyDescriptionExtension failed", t);
            return null;
        }
    }

    private static ASN1OctetString wrapKeyDescription(ASN1Encodable[] tee, ASN1Encodable[] sw, KeyGenParameters params) throws IOException {
        ASN1Integer attestationVersion = new ASN1Integer(100);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1);
        ASN1Integer keymasterVersion = new ASN1Integer(100);
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1);
        ASN1OctetString attestationChallenge = new DEROctetString(params.attestationChallenge);
        ASN1OctetString uniqueId = new DEROctetString(new byte[0]);
        ASN1Encodable softwareEnforced = new DERSequence(sw);
        ASN1Sequence teeEnforced = new DERSequence(tee);

        ASN1Encodable[] keyDescriptionEncodables = {
                attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel,
                attestationChallenge, uniqueId, softwareEnforced, teeEnforced
        };
        return new DEROctetString(new DERSequence(keyDescriptionEncodables));
    }

    private static ASN1OctetString createApplicationId() {
        try {
            Context ctx = currentApplication();
            if (ctx == null) return null;
            PackageManager pm = ctx.getPackageManager();
            int uid = Process.myUid();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages == null || packages.length == 0) {
                packages = new String[]{ctx.getPackageName()};
            }
            ASN1Encodable[] packageInfoAA = new ASN1Encodable[packages.length];
            Set<Digest> signatures = new HashSet<>();
            MessageDigest dg = MessageDigest.getInstance("SHA-256");

            for (int i = 0; i < packages.length; i++) {
                String name = packages[i];
                PackageInfo info = loadPackageInfo(pm, name);
                ASN1Encodable[] arr = new ASN1Encodable[2];
                arr[0] = new DEROctetString(name.getBytes(StandardCharsets.UTF_8));
                arr[1] = new ASN1Integer(info != null ? info.getLongVersionCode() : 0L);
                packageInfoAA[i] = new DERSequence(arr);

                for (byte[] sigBytes : extractSignatureBytes(info)) {
                    signatures.add(new Digest(dg.digest(sigBytes)));
                }
            }

            ASN1Encodable[] signaturesAA = new ASN1Encodable[signatures.size()];
            int i = 0;
            for (Digest d : signatures) {
                signaturesAA[i++] = new DEROctetString(d.digest);
            }
            ASN1Encodable[] applicationIdAA = {
                    new DERSet(packageInfoAA),
                    new DERSet(signaturesAA)
            };
            return new DEROctetString(new DERSequence(applicationIdAA).getEncoded());
        } catch (Throwable t) {
            Log.w(ModuleMain.TAG, "createApplicationId failed", t);
            return null;
        }
    }

    private static Context currentApplication() {
        try {
            Class<?> ath = Class.forName("android.app.ActivityThread");
            Method m = ath.getDeclaredMethod("currentApplication");
            Object app = m.invoke(null);
            return (Context) app;
        } catch (Throwable t) {
            Log.w(ModuleMain.TAG, "currentApplication reflection failed: " + t);
            return null;
        }
    }

    private static PackageInfo loadPackageInfo(PackageManager pm, String name) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return pm.getPackageInfo(name, PackageManager.GET_SIGNING_CERTIFICATES);
            }
            return pm.getPackageInfo(name, PackageManager.GET_SIGNATURES);
        } catch (Throwable t) {
            return null;
        }
    }

    private static List<byte[]> extractSignatureBytes(PackageInfo info) {
        List<byte[]> out = new ArrayList<>();
        if (info == null) return out;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && info.signingInfo != null) {
            Signature[] sigs = info.signingInfo.hasMultipleSigners()
                    ? info.signingInfo.getApkContentsSigners()
                    : info.signingInfo.getSigningCertificateHistory();
            if (sigs != null) {
                for (Signature s : sigs) out.add(s.toByteArray());
            }
        } else if (info.signatures != null) {
            for (Signature s : info.signatures) out.add(s.toByteArray());
        }
        return out;
    }

    private static ASN1Encodable[] fromIntList(List<Integer> list) {
        ASN1Encodable[] result = new ASN1Encodable[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = new ASN1Integer(list.get(i));
        }
        return result;
    }

    private record Digest(byte[] digest) {
        @Override
        public boolean equals(Object o) {
            return o instanceof Digest d && Arrays.equals(digest, d.digest);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(digest);
        }
    }

    private CertHack() {}
}
