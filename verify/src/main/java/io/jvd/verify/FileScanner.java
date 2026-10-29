package io.jvd.verify;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Scan a raw image (or any byte stream) for a canary. This is the only honest file-level
 * validation available without root or device access: the caller must supply the image that
 * contains the blocks. Without an image, file validation is NOT_CHECKABLE.
 */
public final class FileScanner {
    private FileScanner() {}

    public static ScanResult scan(Path file, byte[] masked) {
        long t0 = System.nanoTime();
        if (!Files.isReadable(file)) {
            return ScanResult.notCheckable("raw image not readable: " + file, 0, 0, ms(t0));
        }
        long bytes = 0;
        int matches = 0;
        byte[] carry = new byte[masked.length - 1];
        int carryLen = 0;
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[1 << 20];
            int n;
            while ((n = in.read(buf)) > 0) {
                bytes += n;
                byte[] data = new byte[carryLen + n];
                System.arraycopy(carry, 0, data, 0, carryLen);
                System.arraycopy(buf, 0, data, carryLen, n);
                matches += Canary.countMasked(data, data.length, masked);
                carryLen = Math.min(masked.length - 1, data.length);
                System.arraycopy(data, data.length - carryLen, carry, 0, carryLen);
                Arrays.fill(data, (byte) 0);
            }
            Arrays.fill(buf, (byte) 0);
        } catch (IOException e) {
            return ScanResult.notCheckable("read failed: " + e.getMessage(), 0, bytes, ms(t0));
        } finally {
            Arrays.fill(carry, (byte) 0);
        }
        return matches == 0
                ? ScanResult.notFound(1, bytes, ms(t0))
                : ScanResult.found(matches, 1, bytes, ms(t0));
    }

    public static ScanResult scanBytes(byte[] data, byte[] masked) {
        int m = Canary.countMasked(data, data.length, masked);
        return m == 0 ? ScanResult.notFound(1, data.length, 0) : ScanResult.found(m, 1, data.length, 0);
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }
}
