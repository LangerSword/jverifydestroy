package io.jvd.verify;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/** HMAC-free canary derivation: SHA-256(seed || label), masked before the scanner stores it. */
public final class Canary {
    public static final int LEN = 32;
    public static final byte MASK = 0x5A;

    private Canary() {}

    public static byte[] newSeed() {
        byte[] s = new byte[16];
        new SecureRandom().nextBytes(s);
        return s;
    }

    public static byte[] derive(byte[] seed, String label) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] l = label.getBytes(StandardCharsets.UTF_8);
            byte[] in = new byte[seed.length + l.length];
            System.arraycopy(seed, 0, in, 0, seed.length);
            System.arraycopy(l, 0, in, seed.length, l.length);
            byte[] out = md.digest(in);
            byte[] copy = Arrays.copyOf(out, LEN);
            Arrays.fill(out, (byte) 0);
            Arrays.fill(in, (byte) 0);
            return copy;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] mask(byte[] raw) {
        byte[] m = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) m[i] = (byte) (raw[i] ^ MASK);
        return m;
    }

    /** Count occurrences of the raw canary in {@code data}, comparing through the mask. */
    public static int countMasked(byte[] data, int length, byte[] masked) {
        int n = 0;
        outer:
        for (int i = 0; i + masked.length <= length; i++) {
            for (int j = 0; j < masked.length; j++) {
                if ((byte) (data[i + j] ^ MASK) != masked[j]) continue outer;
            }
            n++;
        }
        return n;
    }

    public static String hex(byte[] b) {
        return java.util.HexFormat.of().formatHex(b);
    }
}
