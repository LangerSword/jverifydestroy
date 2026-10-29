package io.jvd.file;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class FileDestroyerTest {
    @Test void overwriteZerosAndDeletes(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("secret.bin");
        byte[] data = new byte[8192];
        new Random(1).nextBytes(data);
        Files.write(f, data);
        FileDestroyer.Result r = FileDestroyer.destroy(f, 1, false);
        assertEquals(8192, r.bytes());
        assertEquals(1, r.passes());
        assertArrayEquals(new byte[8192], Files.readAllBytes(f));
        assertTrue(r.note().contains("Clear"));
        FileDestroyer.Result d = FileDestroyer.destroy(f, 1, true);
        assertTrue(d.deleted());
        assertFalse(Files.exists(f));
    }

    @Test void threePassesStillEndInZeros(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("secret.bin");
        Files.write(f, "hello world".getBytes());
        FileDestroyer.destroy(f, 3, false);
        assertArrayEquals(new byte[11], Files.readAllBytes(f));
    }

    @Test void deleteOnlyLeavesNoPathButMakesNoClaim(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("x");
        Files.writeString(f, "data");
        FileDestroyer.Result r = FileDestroyer.deleteOnly(f);
        assertFalse(Files.exists(f));
        assertEquals(0, r.passes());
        assertTrue(r.note().contains("may remain"));
    }
}
