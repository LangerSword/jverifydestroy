package io.jvd.txn;

import io.jvd.evidence.Ed25519;
import io.jvd.evidence.EvidenceRecord;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;
import io.jvd.log.Witness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 0 reproductions. These tests intentionally assert the CORRECT behaviour, so they fail
 * against the current code. They are the evidence for docs/REPRO.md; fixes must make them pass.
 */
class FindingReproTest {
    private record Ctx(Path work, KeyPair evidence, KeyPair logKey, KeyPair witnessKey,
                       LogStore log, Witness witness) {}

    private Ctx ctx(Path dir) throws Exception {
        Path work = dir.resolve("work");
        KeyPair ev = Ed25519.generate();
        KeyPair lk = Ed25519.generate();
        KeyPair wk = Ed25519.generate();
        LogStore log = new LogStore(work.resolve("log"), "jvd.local/test");
        Witness w = new Witness("w1", wk.getPrivate(), wk.getPublic());
        return new Ctx(work, ev, lk, wk, log, w);
    }

    private DestructionTransaction txn(Ctx c, Path target, Method method) {
        TxnConfig cfg = new TxnConfig(target, method, c.work(), null, null, 0, true);
        return new DestructionTransaction(cfg, c.evidence(), c.log(), c.logKey().getPrivate(), c.witness());
    }

    @Test void f1ConcurrentRecoverDuringGraceMustNotCommitAsA2(@TempDir Path dir) throws Exception {
        Ctx c = ctx(dir);
        Path target = dir.resolve("secret.txt");
        Files.writeString(target, "must not be committed");
        DestructionTransaction t = txn(c, target, Method.CRYPTO_SHRED);
        t.start();
        t.scrub();
        t.validate();

        // Simulate a concurrent `jvd recover` between VALIDATED and COMMIT.
        Recovery.recover(c.work());

        DestructionTransaction.Outcome out = t.commit();
        assertNotEquals(State.COMMITTED, out.state(), "must not commit after an external recovery");
        assertNotEquals("A2", out.record().assurance.name(), "must not claim A2 while target exists");
    }

    @Test void f2FailedRestoreMustKeepVaultAndKey(@TempDir Path dir) throws Exception {
        Ctx c = ctx(dir);
        Path target = dir.resolve("secret.txt");
        Files.writeString(target, "restore material");
        DestructionTransaction t = txn(c, target, Method.CRYPTO_SHRED);
        t.start();
        t.scrub();

        Path parent = target.getParent();
        var original = Files.getPosixFilePermissions(parent);
        try {
            Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("r-x------"));
            DestructionTransaction.Outcome out = t.rollback("restore should fail");
            assertFalse(out.restored());
            Path container = c.work().resolve("containers").resolve(t.txnId() + ".jvd");
            assertTrue(Files.exists(container), "vault/container must survive a failed restore");
            Path key = c.work().resolve("keys").resolve(t.txnId() + ".dek");
            assertTrue(Files.exists(key), "key must survive a failed restore");
        } finally {
            Files.setPosixFilePermissions(parent, original);
        }
    }

    @Test void f5TwoStoresMustNotCreateDuplicateSequenceNumbers(@TempDir Path dir) throws Exception {
        Path logDir = dir.resolve("log");
        LogStore a = new LogStore(logDir, "jvd.local/test");
        LogStore b = new LogStore(logDir, "jvd.local/test");
        EvidenceRecord r = EvidenceRecord.create("x", "CLEAR", "OVERWRITE");
        a.append(r);
        b.append(r);
        assertDoesNotThrow(() -> new LogStore(logDir, "jvd.local/test"),
                "two writers produced a log that cannot be loaded");
    }

    @Test void f6WitnessMustNotCosignAForgedCheckpoint(@TempDir Path dir) throws Exception {
        KeyPair logKey = Ed25519.generate();
        KeyPair witnessKey = Ed25519.generate();
        Witness w = new Witness("w1", witnessKey.getPrivate(), witnessKey.getPublic());
        Checkpoint forged = Checkpoint.create("jvd.local/test", 1, new byte[32], logKey.getPrivate());
        assertThrows(IllegalArgumentException.class, () -> w.cosign(forged),
                "a witness with no consistency proof cosigned a forged checkpoint");
    }
}
