package io.jvd.evidence;

import java.util.HexFormat;

public final class Hex {
    private Hex() {}

    public static String encode(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    public static byte[] decode(String s) {
        return HexFormat.of().parseHex(s);
    }
}
