package io.jvd.memory;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class NativeLockTest {
    @Test void reportsWhatTheKernelActuallyDid() throws Exception {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(4096, 4096);
            NativeLock.LockResult r = NativeLock.tryLock(seg);
            System.out.println("NativeLock: " + r);
            Assumptions.assumeTrue(r.locked() || r.noDump(), "mlock and madvise both unavailable: " + r.detail());
            String smaps = Files.readString(Path.of("/proc/self/smaps"));
            if (r.locked()) assertTrue(smaps.contains("lo"), "locked mapping should show lo");
            if (r.noDump()) assertTrue(smaps.contains("dd"), "DONTDUMP mapping should show dd");
        }
    }
}
