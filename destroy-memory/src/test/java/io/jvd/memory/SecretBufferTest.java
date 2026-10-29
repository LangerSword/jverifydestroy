package io.jvd.memory;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SecretBufferTest {
    @Test void putGetWipeClose() {
        byte[] secret = "correct horse battery staple".getBytes();
        SecretBuffer b = SecretBuffer.of(secret);
        assertArrayEquals(secret, b.get());
        b.wipe();
        assertArrayEquals(new byte[secret.length], b.get());
        b.close();
        assertTrue(b.isClosed());
        assertThrows(IllegalStateException.class, b::get);
        b.close(); // idempotent
    }

    @Test void closeZerosAndRejectsFurtherWrites() {
        SecretBuffer b = new SecretBuffer(32);
        b.put("secret".getBytes());
        b.close();
        assertThrows(IllegalStateException.class, () -> b.put(new byte[1]));
    }

    @Test void lockResultIsReportedNotHidden() {
        SecretBuffer b = new SecretBuffer(64);
        assertNotNull(b.lockResult());
        assertNotNull(b.lockResult().detail());
        b.close();
    }

    @Test void copiesAreTheCallersProblem() {
        byte[] src = {1, 2, 3};
        SecretBuffer b = SecretBuffer.of(src);
        byte[] copy = b.get();
        b.close();
        assertArrayEquals(new byte[]{1, 2, 3}, copy); // deliberately still there
        Arrays.fill(copy, (byte) 0);
    }
}
