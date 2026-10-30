package io.jvd.verify;

import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Test-only: put the canary only in a named file-backed mapping. */
public final class MappedVictim {
    static MappedByteBuffer MAPPED;

    public static void main(String[] args) throws Exception {
        byte[] seed = java.util.HexFormat.of().parseHex(args[0]);
        byte[] raw = Canary.derive(seed, "target");
        Path file = Files.createTempFile("jvd-mapped", ".bin");
        byte[] page = new byte[1 << 20];
        System.arraycopy(raw, 0, page, 64, raw.length);
        Files.write(file, page);
        Arrays.fill(page, (byte) 0);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            MAPPED = ch.map(FileChannel.MapMode.READ_WRITE, 0, 1 << 20);
            MAPPED.get(64); // fault the page so mincore reports it resident
        }
        Arrays.fill(raw, (byte) 0);
        System.out.println("READY " + ProcessHandle.current().pid() + " " + file);
        System.out.flush();
        System.in.read();
        Files.deleteIfExists(file);
    }
}
