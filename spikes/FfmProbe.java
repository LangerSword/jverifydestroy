import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.*;
import java.util.*;

/** Spike H5: can user-space Java mlock and madvise(MADV_DONTDUMP) an FFM arena? */
public class FfmProbe {
    public static void main(String[] args) throws Throwable {
        System.out.println("RLIMIT_MEMLOCK check: run `ulimit -l` externally");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(4096, 4096);
            seg.fill((byte) 0x5A);
            long addr = seg.address();
            System.out.printf("segment at 0x%x%n", addr);
            Linker linker = Linker.nativeLinker();
            SymbolLookup libc = linker.defaultLookup();
            MethodHandle mlock = linker.downcallHandle(libc.find("mlock").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
            MethodHandle madvise = linker.downcallHandle(libc.find("madvise").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));
            int r1 = (int) mlock.invoke(seg, 4096L);
            int r2 = (int) madvise.invoke(seg, 4096L, 16); // MADV_DONTDUMP
            System.out.println("mlock=" + r1 + " madvise(DONTDUMP)=" + r2 + " errno not exposed");
            printSmaps(addr);
            seg.fill((byte) 0);
        }
        System.out.println("after close");
    }

    static void printSmaps(long addr) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get("/proc/self/smaps"));
        String cur = null; boolean in = false;
        for (String l : lines) {
            if (l.matches("^[0-9a-f]+-[0-9a-f]+ .*")) {
                if (in) break;
                String[] r = l.split("\\s+")[0].split("-");
                long s = Long.parseUnsignedLong(r[0], 16), e = Long.parseUnsignedLong(r[1], 16);
                in = addr >= s && addr < e;
                cur = l;
                if (in) System.out.println("VMA: " + cur);
            } else if (in) {
                if (l.startsWith("VmFlags:")) System.out.println(l.trim());
                if (l.startsWith("Locked:")) System.out.println(l.trim());
            }
        }
    }
}
