package io.jvd.file;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

/**
 * Overwrite + fsync + unlink. This is NIST <b>Clear</b>, not Purge: it assumes the storage
 * overwrites in place. Journaling file systems, copy-on-write file systems, compression, and
 * SSD flash translation layers break that assumption. The result says so; it does not claim
 * physical erasure.
 */
public final class FileDestroyer {
    public record Result(long bytes, int passes, boolean deleted, long elapsedMillis, String note) {}

    private FileDestroyer() {}

    public static Result destroy(Path path) throws IOException {
        return destroy(path, 1, true);
    }

    public static Result destroy(Path path, int passes, boolean delete) throws IOException {
        if (passes < 1) throw new IllegalArgumentException("passes must be >= 1");
        long size = Files.size(path);
        long start = System.nanoTime();
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            SecureRandom random = new SecureRandom();
            byte[] buffer = new byte[(int) Math.min(1 << 20, Math.max(1, size))];
            for (int pass = 0; pass < passes; pass++) {
                byte fill = pass == 0 ? (byte) 0 : pass == 1 ? (byte) 0xFF : (byte) 0;
                boolean last = pass == passes - 1;
                long pos = 0;
                while (pos < size) {
                    int n = (int) Math.min(buffer.length, size - pos);
                    if (pass >= 2 && !last) random.nextBytes(buffer);
                    else java.util.Arrays.fill(buffer, fill);
                    ByteBuffer bb = ByteBuffer.wrap(buffer, 0, n);
                    while (bb.hasRemaining()) ch.write(bb, pos + bb.position());
                    pos += n;
                }
                ch.force(true);
            }
            if (delete) {
                ch.truncate(0);
                ch.force(true);
            }
        }
        if (delete) Files.deleteIfExists(path);
        long ms = (System.nanoTime() - start) / 1_000_000;
        return new Result(size, passes, delete, ms,
                "NIST Clear (overwrite); physical media NOT verified; journal/COW/FTL may retain copies");
    }

    public static Result deleteOnly(Path path) throws IOException {
        long size = Files.size(path);
        long start = System.nanoTime();
        Files.deleteIfExists(path);
        return new Result(size, 0, true, (System.nanoTime() - start) / 1_000_000,
                "unlink only; contents may remain in free blocks");
    }
}
