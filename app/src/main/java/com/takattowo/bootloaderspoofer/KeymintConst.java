package com.takattowo.bootloaderspoofer;

/** Constants mirroring android.hardware.security.keymint.* AIDL values. */
final class KeymintConst {

    static final class Algorithm {
        static final int RSA = 1;
        static final int EC = 3;
    }

    static final class KeyPurpose {
        static final int ENCRYPT = 0;
        static final int DECRYPT = 1;
        static final int SIGN = 2;
        static final int VERIFY = 3;
        static final int WRAP_KEY = 5;
        static final int AGREE_KEY = 6;
        static final int ATTEST_KEY = 7;
    }

    static final class Digest {
        static final int NONE = 0;
        static final int MD5 = 1;
        static final int SHA1 = 2;
        static final int SHA_2_224 = 3;
        static final int SHA_2_256 = 4;
        static final int SHA_2_384 = 5;
        static final int SHA_2_512 = 6;
    }

    static final class EcCurve {
        static final int P_224 = 0;
        static final int P_256 = 1;
        static final int P_384 = 2;
        static final int P_521 = 3;
        static final int CURVE_25519 = 4;
    }

    private KeymintConst() {}
}
