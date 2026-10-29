package io.jvd.file;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;

/** A 32-byte key file with 0600 permissions, wiped and deleted on destroy. */
public final class FileKeyVault {
    private FileKeyVault() {}

    public static void write(Path path, byte[] key) throws IOException {
        if (key.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.write(path, key, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Best effort on non-POSIX file systems.
        }
    }

    public static byte[] read(Path path) throws IOException {
        byte[] key = Files.readAllBytes(path);
        if (key.length != 32) throw new IOException("bad key length " + key.length);
        return key;
    }

    /** Overwrite the key file with zeros, fsync, then delete it. */
    public static void destroy(Path path) throws IOException {
        if (!Files.exists(path)) return;
        byte[] zeros = new byte[32];
        try (var ch = java.nio.channels.FileChannel.open(path,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            ch.write(java.nio.ByteBuffer.wrap(zeros));
            ch.force(true);
        }
        Arrays.fill(zeros, (byte) 0);
        Files.deleteIfExists(path);
    }
}
