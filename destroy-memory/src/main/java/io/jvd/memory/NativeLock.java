package io.jvd.memory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

/**
 * Best-effort process-memory hardening through libc. `mlock` prevents swapping;
 * `madvise(MADV_DONTDUMP)` asks the kernel to omit the mapping from core dumps.
 *
 * <p>Neither is a confidentiality boundary against a privileged attacker, and both can fail
 * under resource limits. Failures are reported, never hidden.</p>
 */
public final class NativeLock {
    public record LockResult(boolean locked, boolean noDump, String detail) {
        public static LockResult unavailable(String why) {
            return new LockResult(false, false, why);
        }
    }

    private static final int MADV_DONTDUMP = 16;

    private NativeLock() {}

    public static LockResult tryLock(MemorySegment segment) {
        Linker linker = Linker.nativeLinker();
        SymbolLookup libc = linker.defaultLookup();
        boolean locked = false;
        boolean noDump = false;
        StringBuilder detail = new StringBuilder();
        try {
            MethodHandle mlock = linker.downcallHandle(libc.find("mlock").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
            int r = (int) mlock.invokeExact(segment, segment.byteSize());
            locked = r == 0;
            detail.append("mlock=").append(r);
        } catch (Throwable t) {
            detail.append("mlock unavailable: ").append(t.getClass().getSimpleName());
        }
        try {
            MethodHandle madvise = linker.downcallHandle(libc.find("madvise").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));
            int r = (int) madvise.invokeExact(segment, segment.byteSize(), MADV_DONTDUMP);
            noDump = r == 0;
            detail.append(" madvise(DONTDUMP)=").append(r);
        } catch (Throwable t) {
            detail.append(" madvise unavailable: ").append(t.getClass().getSimpleName());
        }
        return new LockResult(locked, noDump, detail.toString());
    }
}
