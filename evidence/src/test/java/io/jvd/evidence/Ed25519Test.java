package io.jvd.evidence;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class Ed25519Test {
    @Test void signAndVerify() {
        KeyPair kp = Ed25519.generate();
        byte[] data = "hello".getBytes();
        byte[] sig = Ed25519.sign(data, kp.getPrivate());
        assertTrue(Ed25519.verify(data, sig, kp.getPublic()));
        data[0] ^= 1;
        assertFalse(Ed25519.verify(data, sig, kp.getPublic()));
    }

    @Test void keyFilesRoundTrip(@TempDir Path dir) throws Exception {
        KeyPair kp = Ed25519.generate();
        Path pub = dir.resolve("log.pub");
        Path priv = dir.resolve("log.key");
        Ed25519.writeKey(pub, kp.getPublic());
        Ed25519.writeKey(priv, kp.getPrivate());
        assertEquals("ed25519:", Files.readString(pub).substring(0, 8));
        assertTrue(Ed25519.verify("x".getBytes(), Ed25519.sign("x".getBytes(),
                Ed25519.decodePrivate(Files.readString(priv))),
                Ed25519.decodePublic(Files.readString(pub))));
    }
}
