package io.jvd.memory;

import java.lang.ref.Reference;
import java.util.Arrays;

/**
 * Best-effort wiping of on-heap arrays.
 *
 * <p>Java cannot guarantee that a heap wipe removes every copy: the JIT may keep values in
 * registers, the collector may have moved the object, and a helper may have copied it. The
 * implementation therefore wipes, publishes the array through a volatile field so the write
 * is observable to another thread (which prevents the fill from being treated as dead), and
 * fences it. It still does not make a guarantee; the verifier is what checks the result.</p>
 */
public final class HeapWipe {
    private static volatile Object PUBLISHED;
    private static volatile Object PUBLISHED_CHARS;

    private HeapWipe() {}

    public static void wipeBestEffort(byte[] data) {
        if (data == null) return;
        Arrays.fill(data, (byte) 0);
        PUBLISHED = data;
        Reference.reachabilityFence(data);
        PUBLISHED = null;
    }

    public static void wipeBestEffort(char[] data) {
        if (data == null) return;
        Arrays.fill(data, '\0');
        PUBLISHED_CHARS = data;
        Reference.reachabilityFence(data);
        PUBLISHED_CHARS = null;
    }

    /** Not a guarantee; named so callers cannot mistake it for one. */
    public static void wipeBestEffort(int[] data) {
        if (data == null) return;
        Arrays.fill(data, 0);
        PUBLISHED = data;
        Reference.reachabilityFence(data);
        PUBLISHED = null;
    }
}
