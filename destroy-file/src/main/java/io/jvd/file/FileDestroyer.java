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
    /**
     * What a destruction did.
     *
     * @param bytes         how many bytes were overwritten
     * @param passes        how many overwrite passes were written
     * @param deleted       whether the file is <em>actually</em> gone from the directory now,
     *                      measured after the fact rather than taken from the request
     * @param elapsedMillis how long the work took
     * @param note          the honest scope of the result
     */
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
        if (delete) {
            // The unlink can fail on its own: a directory that cannot be written to is
            // the usual reason. That is not an error in the overwrite — the bytes are
            // already gone — so it is reported as "not deleted" rather than thrown. The
            // caller needs to know the file survived, because a destroyed file and a
            // zeroed file that is still in the directory are different states.
            try {
                Files.deleteIfExists(path);
            } catch (IOException e) {
                return new Result(size, passes, false, (System.nanoTime() - start) / 1_000_000,
                        "overwritten, but the file could not be removed because " + e.getMessage()
                                + "; it is still in the directory, though its contents are zeros");
            }
        }
        long ms = (System.nanoTime() - start) / 1_000_000;
        // Whether the file is really gone is a fact about the filesystem, not about the
        // request that was made. Reporting the request would let a script treat a failed
        // unlink as a successful destruction.
        boolean gone = !Files.exists(path);
        return new Result(size, passes, gone, ms,
                "NIST Clear (overwrite); physical media NOT verified; journal/COW/FTL may retain copies");
    }

    public static Result deleteOnly(Path path) throws IOException {
        long size = Files.size(path);
        long start = System.nanoTime();
        boolean gone;
        try {
            Files.deleteIfExists(path);
            // Measured after the fact, for the same reason as above: the unlink can fail
            // without throwing, and the caller needs to know whether the file survived.
            gone = !Files.exists(path);
        } catch (IOException e) {
            gone = false;
        }
        return new Result(size, 0, gone, (System.nanoTime() - start) / 1_000_000,
                gone ? "unlink only; contents may remain in free blocks"
                        : "the file could not be removed; it is still at " + path);
    }
}
