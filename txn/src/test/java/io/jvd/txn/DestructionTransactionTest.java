package io.jvd.txn;

import io.jvd.evidence.Ed25519;
import io.jvd.evidence.Json;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;
import io.jvd.log.LogVerifier;
import io.jvd.log.Witness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DestructionTransactionTest {
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

    private DestructionTransaction txn(Ctx c, Path target, Method method, boolean requireCheckable) {
        TxnConfig cfg = new TxnConfig(target, method, c.work(), null, null, 0, !requireCheckable);
        return new DestructionTransaction(cfg, c.evidence(), c.log(), c.logKey().getPrivate(), c.witness());
    }

    @Test void cryptoCommitDestroysKeyAndLeavesEvidence(@TempDir Path dir) throws Exception {
        Ctx c = ctx(dir);
        Path target = dir.resolve("secret.txt");
        byte[] plain = "attack at dawn".getBytes();
        Files.write(target, plain);
        DestructionTransaction t = txn(c, target, Method.CRYPTO_SHRED, false);
        DestructionTransaction.Outcome out = t.run();

        assertEquals(State.COMMITTED, out.state());
        assertFalse(Files.exists(target), "plaintext path must be gone");
        assertTrue(Files.notExists(c.work().resolve("keys").resolve(t.txnId() + ".dek")),
                "crypto key must be destroyed");
        Path container = c.work().resolve("containers").resolve(t.txnId() + ".jvd");
        assertTrue(Files.exists(container), "ciphertext may remain; it must be unreadable");
        assertFalse(io.jvd.file.CryptoShredder.canDecrypt(container, new byte[32]),
                "a wiped key must not decrypt the container");
        assertTrue(out.record().verification.operationCompleted);
        assertEquals("COMMITTED", out.record().verification.status);

        Path cpFile = c.work().resolve("checkpoints").resolve("latest.json");
        assertTrue(Files.exists(cpFile));
        Checkpoint cp = LogStore.readCheckpoint(cpFile);
        LogVerifier.Result vr = LogVerifier.verify(c.log().logFile(), cp,
                c.logKey().getPublic(), c.witnessKey().getPublic());
        assertTrue(vr.valid, vr.summary());
    }

    @Test void notCheckableRollsBackAndRestoresTheFile(@TempDir Path dir) throws Exception {
        Ctx c = ctx(dir);
        Path target = dir.resolve("secret.txt");
        byte[] plain = "bring me back".getBytes();
        Files.write(target, plain);
        DestructionTransaction t = txn(c, target, Method.CRYPTO_SHRED, true);
        DestructionTransaction.Outcome out = t.run();

        assertEquals(State.ABORTED, out.state());
        assertTrue(out.restored());
        assertTrue(Files.exists(target));
        assertArrayEquals(plain, Files.readAllBytes(target));
        assertTrue(out.record().validation.result.contains("FAIL")
                || out.record().validation.result.contains("NOT_CHECKABLE"));
    }

    @Test void commitIsIrreversible(@TempDir Path dir) throws Exception {
        Ctx c = ctx(dir);
        Path target = dir.resolve("secret.txt");
        Files.writeString(target, "irreversible");
        DestructionTransaction t = txn(c, target, Method.CRYPTO_SHRED, false);
        t.run();
        assertEquals(State.COMMITTED, t.state());
        assertThrows(IllegalStateException.class, () -> t.rollback("too late"));
    }

    @Test void crashBeforeCommitIsRecovered(@TempDir Path dir) throws Exception {
        Ctx c = ctx(dir);
        Path target = dir.resolve("secret.txt");
        byte[] plain = "crash me".getBytes();
        Files.write(target, plain);
        DestructionTransaction t = txn(c, target, Method.CRYPTO_SHRED, false);
        t.start();
        t.scrub();
        // No validate/commit: this is a SCRUBBED crash.
        List<Recovery.Result> rs = Recovery.recover(c.work());
        assertEquals(1, rs.size());
        assertTrue(rs.get(0).restored(), rs.get(0).toString());
        assertArrayEquals(plain, Files.readAllBytes(target));
    }

    @Test void committedTransactionIsNotRestoredByRecovery(@TempDir Path dir) throws Exception {
        Ctx c = ctx(dir);
        Path target = dir.resolve("secret.txt");
        Files.writeString(target, "gone");
        DestructionTransaction t = txn(c, target, Method.CRYPTO_SHRED, false);
        t.run();
        List<Recovery.Result> rs = Recovery.recover(c.work());
        assertEquals(1, rs.size());
        assertFalse(rs.get(0).restored());
        assertFalse(Files.exists(target));
        assertEquals(State.COMMITTED, rs.get(0).lastState());
    }

    @Test void validationChecksAreRecorded(@TempDir Path dir) throws Exception {
        Ctx c = ctx(dir);
        Path target = dir.resolve("secret.txt");
        Files.writeString(target, "evidence");
        DestructionTransaction t = txn(c, target, Method.CRYPTO_SHRED, false);
        t.run();
        String json = t.record().toJson();
        assertTrue(json.contains("NOT_CHECKABLE"));
        assertTrue(json.contains("verification"));
        assertTrue(json.contains("validation"));
        assertTrue(json.contains("physical flash") || json.contains("cannot verify physical"));
    }
}
