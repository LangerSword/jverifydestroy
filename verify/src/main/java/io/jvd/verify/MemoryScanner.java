package io.jvd.verify;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
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
 * <p>P7: every readable writable mapping is included, including named mappings and regions
 * larger than 2 GiB. Resident pages are found with mincore(2); non-resident pages are skipped
 * (they are not live memory and reading them returns EIO). The result records mapped resident
 * bytes, actually read bytes, and read errors. A missing canary is only NOT_FOUND when coverage
 * is at least 90% and no resident page failed to read; otherwise it is NOT_CHECKABLE.</p>
 */
public final class MemoryScanner {
    private static final int PAGE = 4096;
    private static final int CHUNK = 1 << 20;
    private static final double MIN_COVERAGE = 0.90;

    private MemoryScanner() {}

    private record Region(long start, long end, String name) {}

    public static ScanResult scan(long pid, byte[] masked) {
        long t0 = System.nanoTime();
        Path mem = Path.of("/proc/" + pid + "/mem");
        Path maps = Path.of("/proc/" + pid + "/maps");
        if (!Files.isReadable(mem) || !Files.isReadable(maps)) {
            return ScanResult.notCheckable("cannot read /proc/" + pid + " (permission or process gone)",
                    0, 0, 0, 0, ms(t0));
        }
        List<Region> regions = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(maps)) {
                String[] p = line.split("\\s+");
                if (p.length < 2 || !p[1].startsWith("rw")) continue;
                String[] r = p[0].split("-");
                long s = Long.parseUnsignedLong(r[0], 16);
                long e = Long.parseUnsignedLong(r[1], 16);
                if (e > s) regions.add(new Region(s, e, p.length > 5 ? p[5] : ""));
            }
        } catch (IOException e) {
            return ScanResult.notCheckable("cannot parse maps: " + e.getMessage(), 0, 0, 0, 0, ms(t0));
        }
        if (regions.isEmpty()) {
            return ScanResult.notCheckable("no readable rw regions", 0, 0, 0, 0, ms(t0));
        }
        long mapped = 0, read = 0;
        int readErrors = 0;
        int matches = 0;
        try (FileChannel ch = FileChannel.open(mem, StandardOpenOption.READ)) {
            ByteBuffer buf = ByteBuffer.allocate(CHUNK);
            for (Region r : regions) {
                long len = r.end - r.start;
                long pages = (len + PAGE - 1) / PAGE;
                byte[] resident = residentPages(r.start, len, pages);
                if (resident == null) {
                    // mincore unavailable: read page by page so an uncommitted hole does not
                    // hide the rest of the region. Unreadable pages are counted, not guessed.
                    byte[] carry = new byte[masked.length - 1];
                    int carryLen = 0;
                    for (long page = 0; page < pages; page++) {
                        long off = page * PAGE;
                        int want = (int) Math.min(PAGE, len - off);
                        int n = readAt(ch, r.start + off, want, buf);
                        if (n < 0) { readErrors++; carryLen = 0; continue; }
                        if (n == 0) break;
                        read += n;
                        mapped += n;
                        matches += search(buf.array(), n, masked, carry, carryLen);
                        carryLen = carry(buf.array(), n, masked, carry, carryLen);
                        if (matches > 16) {
                            Arrays.fill(carry, (byte) 0);
                            return ScanResult.found(matches, regions.size(), mapped, read, readErrors, ms(t0));
                        }
                    }
                    Arrays.fill(carry, (byte) 0);
                    continue;
                }
                byte[] carry = new byte[masked.length - 1];
                int carryLen = 0;
                for (long page = 0; page < pages; page++) {
                    if ((resident[(int) page] & 1) == 0) {
                        carryLen = 0;
                        continue;
                    }
                    long off = page * PAGE;
                    int want = (int) Math.min(PAGE, len - off);
                    int n = readAt(ch, r.start + off, want, buf);
                    if (n < 0) { readErrors++; carryLen = 0; continue; }
                    if (n == 0) break;
                    read += n;
                    mapped += n;
                    matches += search(buf.array(), n, masked, carry, carryLen);
                    carryLen = carry(buf.array(), n, masked, carry, carryLen);
                    if (matches > 16) {
                        Arrays.fill(carry, (byte) 0);
                        return ScanResult.found(matches, regions.size(), mapped, read, readErrors, ms(t0));
                    }
                }
                Arrays.fill(carry, (byte) 0);
            }
        } catch (IOException e) {
            return ScanResult.notCheckable("read failed: " + e.getMessage(), regions.size(), mapped, read,
                    readErrors, ms(t0));
        }
        if (matches > 0) {
            return ScanResult.found(matches, regions.size(), mapped, read, readErrors, ms(t0));
        }
        double coverage = mapped == 0 ? 0.0 : (double) read / mapped;
        if (mapped == 0) {
            return ScanResult.notCheckable("no resident mapped bytes", regions.size(), mapped, read, readErrors, ms(t0));
        }
        // Unreadable pages are excluded from mapped/read coverage and counted in readErrors;
        // the caller sees the count. A canary cannot be read from a page the kernel refuses.
        if (coverage < MIN_COVERAGE) {
            return ScanResult.notCheckable("coverage " + String.format(java.util.Locale.ROOT, "%.1f%%", coverage * 100)
                    + " below " + (int) (MIN_COVERAGE * 100) + "%",
                    regions.size(), mapped, read, readErrors, ms(t0));
        }
        return ScanResult.notFound(regions.size(), mapped, read, 0, ms(t0));
    }

    private static int readAt(FileChannel ch, long position, int want, ByteBuffer buf) {
        buf.clear();
        buf.limit(want);
        try {
            return ch.read(buf, position);
        } catch (IOException e) {
            return -1;
        }
    }

    private static int search(byte[] data, int n, byte[] masked, byte[] carry, int carryLen) {
        byte[] joined = new byte[carryLen + n];
        System.arraycopy(carry, 0, joined, 0, carryLen);
        System.arraycopy(data, 0, joined, carryLen, n);
        int found = Canary.countMasked(joined, joined.length, masked);
        Arrays.fill(joined, (byte) 0);
        return found;
    }

    private static int carry(byte[] data, int n, byte[] masked, byte[] carry, int carryLen) {
        byte[] joined = new byte[carryLen + n];
        System.arraycopy(carry, 0, joined, 0, carryLen);
        System.arraycopy(data, 0, joined, carryLen, n);
        int keep = Math.min(masked.length - 1, joined.length);
        System.arraycopy(joined, joined.length - keep, carry, 0, keep);
        Arrays.fill(joined, (byte) 0);
        return keep;
    }

    private static byte[] residentPages(long start, long len, long pages) {
        if (pages <= 0 || pages > Integer.MAX_VALUE) return null;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment vec = arena.allocate(pages);
            Linker linker = Linker.nativeLinker();
            MethodHandle mincore = linker.downcallHandle(
                    linker.defaultLookup().find("mincore").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
            int rc = (int) mincore.invokeExact(MemorySegment.ofAddress(start), len, vec);
            if (rc != 0) return null;
            byte[] out = new byte[(int) pages];
            MemorySegment.copy(vec, ValueLayout.JAVA_BYTE, 0, out, 0, (int) pages);
            return out;
        } catch (Throwable t) {
            return null;
        }
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }
}
