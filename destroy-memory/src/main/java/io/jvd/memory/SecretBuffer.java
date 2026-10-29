package io.jvd.memory;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;

/**
 * An off-heap secret buffer. The memory is wiped with zeros before the arena is closed.
 *
 * <p>This protects against the buffer remaining in the Java heap, not against a compromised
 * JVM, a debugger, a cold-boot attack, or a copy made by a library you passed the bytes to.
 * {@link #get()} returns a copy; the caller owns it and must wipe it.</p>
 */
public final class SecretBuffer implements AutoCloseable {
    private final Arena arena;
    private final MemorySegment segment;
    private final int length;
    private final NativeLock.LockResult lock;
    private boolean closed;

    public SecretBuffer(int length) {
        if (length <= 0) throw new IllegalArgumentException("length must be positive");
        this.length = length;
        this.arena = Arena.ofConfined();
        this.segment = arena.allocate(length, 64);
        this.segment.fill((byte) 0);
        this.lock = NativeLock.tryLock(segment);
    }

    public static SecretBuffer of(byte[] secret) {
        SecretBuffer b = new SecretBuffer(secret.length);
        b.put(secret);
        return b;
    }

    public int length() { return length; }

    public NativeLock.LockResult lockResult() { return lock; }

    public void put(byte[] src) {
        ensureOpen();
        if (src.length > length) throw new IllegalArgumentException("secret too long");
        MemorySegment.copy(src, 0, segment, ValueLayout.JAVA_BYTE, 0, src.length);
    }

    /** Returns a copy. The caller is responsible for wiping the returned array. */
    public byte[] get() {
        ensureOpen();
        byte[] out = new byte[length];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, out, 0, length);
        return out;
    }

    /** Overwrite the native memory with zeros. Idempotent. */
    public void wipe() {
        if (!closed) segment.fill((byte) 0);
    }

    public boolean isClosed() { return closed; }

    @Override
    public void close() {
        if (closed) return;
        try {
            segment.fill((byte) 0);
        } finally {
            closed = true;
            arena.close();
        }
    }

    private void ensureOpen() {
        if (closed) throw new IllegalStateException("secret buffer is closed");
    }

    @Override
    public String toString() {
        return "SecretBuffer[length=" + length + ", closed=" + closed + ", locked="
                + lock.locked() + ", noDump=" + lock.noDump() + "]";
    }

    /** Demo only: shows why a byte[] copy is a liability unless the caller wipes it. */
    public static String describeLeak(byte[] copy) {
        return "a " + copy.length + "-byte copy exists; wipe it with HeapWipe.wipeBestEffort";
    }

    static void zero(byte[] b) {
        Arrays.fill(b, (byte) 0);
    }
}
