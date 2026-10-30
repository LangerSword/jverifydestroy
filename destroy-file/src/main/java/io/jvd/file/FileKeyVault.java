package io.jvd.file;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Set;

/** A 32-byte key file with 0600 permissions, wiped and deleted on destroy. */
public final class FileKeyVault {
    private FileKeyVault() {}

    public static void write(Path path, byte[] key) throws IOException {
        if (key.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        try (FileChannel ch = FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW,
                        StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ch.write(ByteBuffer.wrap(key));
            ch.force(true);
        } catch (UnsupportedOperationException e) {
            // Non-POSIX fallback: create exclusively, then set permissions best-effort.
            try (FileChannel ch = FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE))) {
                ch.write(ByteBuffer.wrap(key));
                ch.force(true);
            }
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }
    }

    public static byte[] read(Path path) throws IOException {
        byte[] key = Files.readAllBytes(path);
        if (key.length != 32) throw new IOException("bad key length " + key.length);
        return key;
    }

    /**
     * Overwrite every existing byte in place (no truncate-first), fsync, then unlink.
     * The old blocks are still not guaranteed to be physically gone; see README.
     */
    public static void destroy(Path path) throws IOException {
        if (!Files.exists(path)) return;
        long size = Files.size(path);
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.WRITE)) {
            byte[] zeros = new byte[(int) Math.min(size, 1 << 20)];
            long pos = 0;
            while (pos < size) {
                int n = (int) Math.min(zeros.length, size - pos);
                ByteBuffer bb = ByteBuffer.wrap(zeros, 0, n);
                while (bb.hasRemaining()) ch.write(bb, pos + bb.position());
                pos += n;
            }
            ch.force(true);
            Arrays.fill(zeros, (byte) 0);
        }
        Files.deleteIfExists(path);
    }
}
