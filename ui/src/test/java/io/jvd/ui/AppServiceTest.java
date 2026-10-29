package io.jvd.ui;

import io.jvd.txn.Method;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class AppServiceTest {
    @Test void destroyCommitVerifyAndRecover(@TempDir Path dir) throws Exception {
        Path target = dir.resolve("secret.txt");
        Path work = dir.resolve("work");
        byte[] data = "ui secret".getBytes();
        Files.write(target, data);

        AppService.DestroyView v = AppService.destroy(target, Method.CRYPTO_SHRED, work, null, null, 0, false);
        assertEquals("COMMITTED", v.state());
        assertFalse(Files.exists(target));
        assertFalse(v.evidenceJson().isBlank());

        AppService.VerifyView verify = AppService.verify(work);
        assertTrue(verify.valid(), verify.summary());

        AppService.RecoverView recover = AppService.recover(work);
        assertFalse(recover.lines().isEmpty());
        assertTrue(recover.lines().get(0).contains("last=COMMITTED"));
    }

    @Test void requireCheckableRollsBack(@TempDir Path dir) throws Exception {
        Path target = dir.resolve("secret.txt");
        Path work = dir.resolve("work");
        byte[] data = "bring me back".getBytes();
        Files.write(target, data);

        AppService.DestroyView v = AppService.destroy(target, Method.CRYPTO_SHRED, work, null, null, 0, true);
        assertEquals("ABORTED", v.state());
        assertTrue(v.restored());
        assertArrayEquals(data, Files.readAllBytes(target));
    }
}
