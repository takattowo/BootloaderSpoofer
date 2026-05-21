package com.takattowo.bootloaderspoofer;

/** Pure constants. No framework imports - safe to load in module process. */
final class Config {

    static final String KEYBOX_FILE = "keybox.xml";
    static final String MODE_FILE = "mode.txt";

    static final String MODE_LEAF_HACK = "leaf_hack";
    static final String MODE_CERT_GENERATE = "cert_generate";
    static final String MODE_OFF = "off";

    static String normalizeMode(String raw) {
        if (raw == null) return MODE_LEAF_HACK;
        String m = raw.trim().toLowerCase();
        switch (m) {
            case MODE_LEAF_HACK:
            case MODE_CERT_GENERATE:
            case MODE_OFF:
                return m;
            default:
                return MODE_LEAF_HACK;
        }
    }

    private Config() {}
}
