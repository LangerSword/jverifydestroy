package io.jvd.verify;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class MemoryScannerTest {
    @Test void seesAKnownCanaryInAChild() throws Exception {
        byte[] seed = Canary.newSeed();
        byte[] raw = Canary.derive(seed, "target");
        byte[] masked = Canary.mask(raw);
        Arrays.fill(raw, (byte) 0);
        try (VictimProcess v = VictimProcess.start(seed, "KEEP", "G1")) {
            ScanResult r = MemoryScanner.scan(v.pid(), masked);
            assertEquals(Verdict.FOUND, r.verdict(), r.toString());
        } finally {
            Arrays.fill(masked, (byte) 0);
        }
    }

    @Test void deadPidIsNotCheckable() {
        ScanResult r = MemoryScanner.scan(999_999_999L, new byte[Canary.LEN]);
        assertEquals(Verdict.NOT_CHECKABLE, r.verdict());
    }

    @Test void missingImageIsNotCheckable(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) {
        ScanResult r = FileScanner.scan(dir.resolve("nope.img"), new byte[Canary.LEN]);
        assertEquals(Verdict.NOT_CHECKABLE, r.verdict());
    }

    @Test void fileScannerFindsAndMisses() throws Exception {
        byte[] raw = Canary.derive(Canary.newSeed(), "file");
        byte[] masked = Canary.mask(raw);
        byte[] image = new byte[8192];
        System.arraycopy(raw, 0, image, 4096, raw.length);
        assertEquals(Verdict.FOUND, FileScanner.scanBytes(image, masked).verdict());
        assertEquals(Verdict.NOT_FOUND, FileScanner.scanBytes(new byte[8192], masked).verdict());
        Arrays.fill(raw, (byte) 0);
    }
}
