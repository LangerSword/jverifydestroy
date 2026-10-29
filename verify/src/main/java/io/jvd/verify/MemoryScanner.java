package io.jvd.verify;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Scan another process's readable memory for a masked canary. Never scans the current process:
 * a self-scan finds the scanner's own read buffer (H4).
 *
 * <p>Regions: readable+writable anonymous mappings, {@code [heap]}, and {@code /memfd:}
 * (ZGC maps its heap as {@code /memfd:java_heap}). File-backed mappings are skipped.</p>
 */
public final class MemoryScanner {
    private static final int CHUNK = 1 << 20;

    private MemoryScanner() {}

    private record Region(long start, long end) {}

    public static ScanResult scan(long pid, byte[] masked) {
        long t0 = System.nanoTime();
        Path mem = Path.of("/proc/" + pid + "/mem");
        Path maps = Path.of("/proc/" + pid + "/maps");
        if (!Files.isReadable(mem) || !Files.isReadable(maps)) {
            return ScanResult.notCheckable("cannot read /proc/" + pid + " (permission or process gone)", 0, 0, ms(t0));
        }
        List<Region> regions = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(maps)) {
                String[] p = line.split("\\s+");
                if (p.length < 2 || !p[1].startsWith("rw")) continue;
                String path = p.length > 5 ? p[5] : "";
                if (!path.isEmpty() && !path.equals("[heap]") && !path.startsWith("/memfd:")) continue;
                String[] r = p[0].split("-");
                long s = Long.parseUnsignedLong(r[0], 16);
                long e = Long.parseUnsignedLong(r[1], 16);
                if (e > s && e - s <= (1L << 31)) regions.add(new Region(s, e));
            }
        } catch (IOException e) {
            return ScanResult.notCheckable("cannot parse maps: " + e.getMessage(), 0, 0, ms(t0));
        }
        if (regions.isEmpty()) {
            return ScanResult.notCheckable("no readable rw regions", 0, 0, ms(t0));
        }
        long bytes = 0;
        int matches = 0;
        try (FileChannel ch = FileChannel.open(mem, StandardOpenOption.READ)) {
            ByteBuffer buf = ByteBuffer.allocate(CHUNK);
            for (Region r : regions) {
                long len = r.end - r.start;
                bytes += len;
                byte[] carry = new byte[masked.length - 1];
                int carryLen = 0;
                for (long off = 0; off < len; off += CHUNK) {
                    int want = (int) Math.min(CHUNK, len - off);
                    buf.clear();
                    buf.limit(want);
                    int n;
                    try {
                        n = ch.read(buf, r.start + off);
                    } catch (IOException e) {
                        break; // unreadable region; keep scanning the rest
                    }
                    if (n <= 0) break;
                    byte[] data = new byte[carryLen + n];
                    System.arraycopy(carry, 0, data, 0, carryLen);
                    System.arraycopy(buf.array(), 0, data, carryLen, n);
                    matches += Canary.countMasked(data, data.length, masked);
                    if (matches > 16) {
                        Arrays.fill(data, (byte) 0);
                        return ScanResult.found(matches, regions.size(), bytes, ms(t0));
                    }
                    carryLen = Math.min(masked.length - 1, data.length);
                    System.arraycopy(data, data.length - carryLen, carry, 0, carryLen);
                    Arrays.fill(data, (byte) 0);
                }
                Arrays.fill(carry, (byte) 0);
            }
        } catch (IOException e) {
            return ScanResult.notCheckable("read failed: " + e.getMessage(), regions.size(), bytes, ms(t0));
        }
        return matches == 0
                ? ScanResult.notFound(regions.size(), bytes, ms(t0))
                : ScanResult.found(matches, regions.size(), bytes, ms(t0));
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }
}
