package io.jvd.file;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CryptoShredderTest {
    @Test void roundTripThenKeyDestruction(@TempDir Path dir) throws Exception {
        Path src = dir.resolve("secret.txt");
        Path container = dir.resolve("secret.jvd");
        Path keyFile = dir.resolve("secret.key");
        byte[] plain = "attack at dawn".getBytes();
        Files.write(src, plain);

        CryptoShredder.encrypt(src, container, keyFile);
        assertTrue(Files.exists(container));
        assertTrue(Files.exists(keyFile));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(keyFile)));
        byte[] key = FileKeyVault.read(keyFile);
        assertTrue(CryptoShredder.canDecrypt(container, key));

        Path restored = dir.resolve("restored.txt");
        CryptoShredder.decrypt(container, restored, key);
        assertArrayEquals(plain, Files.readAllBytes(restored));

        CryptoShredder.destroyKey(keyFile, key);
        assertFalse(Files.exists(keyFile));
        assertFalse(CryptoShredder.canDecrypt(container, key));
    }

    @Test void wrongKeyAndTamperFail(@TempDir Path dir) throws Exception {
        Path src = dir.resolve("s");
        Path container = dir.resolve("s.jvd");
        Path keyFile = dir.resolve("s.key");
        Files.writeString(src, "data");
        CryptoShredder.encrypt(src, container, keyFile);
        byte[] key = FileKeyVault.read(keyFile);
        byte[] wrong = key.clone();
        wrong[0] ^= 1;
        assertFalse(CryptoShredder.canDecrypt(container, wrong));
        byte[] c = Files.readAllBytes(container);
        c[c.length - 1] ^= 1;
        Files.write(container, c);
        assertFalse(CryptoShredder.canDecrypt(container, key));
        Arrays.fill(key, (byte) 0);
        Arrays.fill(wrong, (byte) 0);
    }
}
