package com.takattowo.bootloaderspoofer;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/** Adapter from app-level {@link KeyGenParameterSpec} to TrickyStore-style keymint params. */
final class KeyGenParameters {

    int algorithm;
    int keySize;
    BigInteger certificateSerial;
    Date certificateNotBefore;
    Date certificateNotAfter;
    X500Name certificateSubject;

    BigInteger rsaPublicExponent = BigInteger.valueOf(65537);
    int ecCurve = KeymintConst.EcCurve.P_256;
    String ecCurveName = "secp256r1";

    final List<Integer> purpose = new ArrayList<>();
    final List<Integer> digest = new ArrayList<>();

    byte[] attestationChallenge;
    String alias;

    static KeyGenParameters from(KeyGenParameterSpec spec, String requestedAlgorithm) {
        KeyGenParameters p = new KeyGenParameters();
        p.alias = spec.getKeystoreAlias();
        p.algorithm = "EC".equalsIgnoreCase(requestedAlgorithm)
                ? KeymintConst.Algorithm.EC
                : KeymintConst.Algorithm.RSA;

        int specSize = spec.getKeySize();
        if (specSize > 0) {
            p.keySize = specSize;
        } else {
            p.keySize = p.algorithm == KeymintConst.Algorithm.EC ? 256 : 2048;
        }

        p.certificateSerial = spec.getCertificateSerialNumber();
        if (p.certificateSerial == null) p.certificateSerial = BigInteger.ONE;
        p.certificateNotBefore = spec.getCertificateNotBefore();
        if (p.certificateNotBefore == null) p.certificateNotBefore = new Date();
        p.certificateNotAfter = spec.getCertificateNotAfter();
        if (p.certificateNotAfter == null) {
            p.certificateNotAfter = new Date(System.currentTimeMillis() + 10L * 365 * 24 * 3600 * 1000);
        }
        X500Principal subj = spec.getCertificateSubject();
        if (subj == null) subj = new X500Principal("CN=Android Keystore Key");
        p.certificateSubject = new X500Name(subj.getName());

        AlgorithmParameterSpec aps = spec.getAlgorithmParameterSpec();
        if (aps instanceof RSAKeyGenParameterSpec rsa) {
            p.keySize = rsa.getKeysize();
            p.rsaPublicExponent = rsa.getPublicExponent();
        } else if (aps instanceof ECGenParameterSpec ec) {
            p.ecCurveName = ec.getName();
            p.ecCurve = curveNameToInt(p.ecCurveName);
            p.keySize = curveKeySize(p.ecCurveName, p.keySize);
        } else if (p.algorithm == KeymintConst.Algorithm.EC) {
            p.ecCurveName = sizeToCurveName(p.keySize);
            p.ecCurve = curveNameToInt(p.ecCurveName);
        }

        int purposeMask = spec.getPurposes();
        if ((purposeMask & KeyProperties.PURPOSE_ENCRYPT) != 0) p.purpose.add(KeymintConst.KeyPurpose.ENCRYPT);
        if ((purposeMask & KeyProperties.PURPOSE_DECRYPT) != 0) p.purpose.add(KeymintConst.KeyPurpose.DECRYPT);
        if ((purposeMask & KeyProperties.PURPOSE_SIGN) != 0) p.purpose.add(KeymintConst.KeyPurpose.SIGN);
        if ((purposeMask & KeyProperties.PURPOSE_VERIFY) != 0) p.purpose.add(KeymintConst.KeyPurpose.VERIFY);
        if ((purposeMask & KeyProperties.PURPOSE_WRAP_KEY) != 0) p.purpose.add(KeymintConst.KeyPurpose.WRAP_KEY);
        if ((purposeMask & KeyProperties.PURPOSE_AGREE_KEY) != 0) p.purpose.add(KeymintConst.KeyPurpose.AGREE_KEY);
        try {
            int attestMask = (int) KeyProperties.class.getField("PURPOSE_ATTEST_KEY").get(null);
            if ((purposeMask & attestMask) != 0) p.purpose.add(KeymintConst.KeyPurpose.ATTEST_KEY);
        } catch (Throwable ignored) {
        }

        String[] digests = spec.getDigests();
        if (digests != null) {
            for (String d : digests) p.digest.add(digestStringToInt(d));
        }
        if (p.digest.isEmpty()) {
            p.digest.add(KeymintConst.Digest.SHA_2_256);
        }

        p.attestationChallenge = spec.getAttestationChallenge();
        if (p.attestationChallenge == null) p.attestationChallenge = new byte[0];

        return p;
    }

    private static int curveNameToInt(String name) {
        if (name == null) return KeymintConst.EcCurve.P_256;
        String n = name.toLowerCase();
        if (n.contains("224")) return KeymintConst.EcCurve.P_224;
        if (n.contains("384")) return KeymintConst.EcCurve.P_384;
        if (n.contains("521") || n.contains("512")) return KeymintConst.EcCurve.P_521;
        if (n.contains("25519")) return KeymintConst.EcCurve.CURVE_25519;
        return KeymintConst.EcCurve.P_256;
    }

    private static String sizeToCurveName(int size) {
        return switch (size) {
            case 224 -> "secp224r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> "secp256r1";
        };
    }

    private static int curveKeySize(String name, int fallback) {
        if (name == null) return fallback;
        String n = name.toLowerCase();
        if (n.contains("224")) return 224;
        if (n.contains("256")) return 256;
        if (n.contains("384")) return 384;
        if (n.contains("521")) return 521;
        if (n.contains("25519")) return 256;
        return fallback;
    }

    private static int digestStringToInt(String s) {
        if (s == null) return KeymintConst.Digest.NONE;
        switch (s) {
            case KeyProperties.DIGEST_NONE: return KeymintConst.Digest.NONE;
            case KeyProperties.DIGEST_MD5: return KeymintConst.Digest.MD5;
            case KeyProperties.DIGEST_SHA1: return KeymintConst.Digest.SHA1;
            case KeyProperties.DIGEST_SHA224: return KeymintConst.Digest.SHA_2_224;
            case KeyProperties.DIGEST_SHA256: return KeymintConst.Digest.SHA_2_256;
            case KeyProperties.DIGEST_SHA384: return KeymintConst.Digest.SHA_2_384;
            case KeyProperties.DIGEST_SHA512: return KeymintConst.Digest.SHA_2_512;
            default: return KeymintConst.Digest.SHA_2_256;
        }
    }

    private KeyGenParameters() {}
}
