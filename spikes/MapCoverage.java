import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.*;

/** Measures how much of this JVM's readable-writable mapping is named (skipped by MemoryScanner). */
public final class MapCoverage {
    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempFile("jvd-map", ".bin");
        byte[] one = new byte[1 << 20];
        Files.write(tmp, one);
        try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            ch.map(FileChannel.MapMode.READ_WRITE, 0, one.length);
            byte[] heap = new byte[64 << 20];
            Arrays.fill(heap, (byte) 0x5A);
            long total = 0, named = 0, unnamed = 0, skipped = 0, namedRegions = 0, regions = 0;
            for (String line : Files.readAllLines(Path.of("/proc/self/maps"))) {
                String[] p = line.split("\\s+");
                if (p.length < 2 || !p[1].startsWith("rw")) continue;
                String[] r = p[0].split("-");
                long s = Long.parseUnsignedLong(r[0], 16), e = Long.parseUnsignedLong(r[1], 16);
                long len = e - s;
                regions++;
                total += len;
                String path = p.length > 5 ? p[5] : "";
                if (path.isEmpty() || path.equals("[heap]")) unnamed += len;
                else {
                    named += len;
                    namedRegions++;
                    if (!path.startsWith("/memfd:")) skipped += len;
                }
            }
            System.out.printf("regions=%d total=%d named=%d (%.1f%%) unnamed=%d (%.1f%%) skipped=%d (%.1f%%) namedRegions=%d%n",
                    regions, total, named, 100.0 * named / total, unnamed, 100.0 * unnamed / total,
                    skipped, 100.0 * skipped / total, namedRegions);
            System.out.println("heap held=" + heap.length + " mappedFile=" + tmp);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
