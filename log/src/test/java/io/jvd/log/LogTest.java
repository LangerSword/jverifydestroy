package io.jvd.log;

import io.jvd.evidence.EvidenceRecord;
import io.jvd.evidence.Ed25519;
import io.jvd.evidence.Json;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class LogTest {
    private KeyPair evidence = Ed25519.generate();
    private KeyPair logKey = Ed25519.generate();
    private KeyPair witnessKey = Ed25519.generate();

    private LogStore build(Path dir, int n) throws Exception {
        LogStore store = new LogStore(dir, "jvd.local/test");
        for (int i = 0; i < n; i++) {
            EvidenceRecord r = EvidenceRecord.create("/tmp/file-" + i, "CLEAR", "OVERWRITE");
            r.verification.operationCompleted = true;
            r.verification.status = "COMPLETED";
            r.validation.result = "PASS";
            r.validation.dataAbsent = true;
            r.sign(evidence.getPrivate());
            store.append(r);
        }
        return store;
    }

    private Checkpoint signedCheckpoint(LogStore store) {
        Checkpoint cp = store.checkpoint(logKey.getPrivate());
        new Witness("w1", witnessKey.getPrivate(), witnessKey.getPublic()).cosign(cp, store);
        return cp;
    }

    @Test void validLogVerifies(@TempDir Path dir) throws Exception {
        LogStore store = build(dir, 5);
        Checkpoint cp = signedCheckpoint(store);
        LogVerifier.Result r = LogVerifier.verify(store.logFile(), cp, logKey.getPublic(), witnessKey.getPublic());
        assertTrue(r.valid, r.summary());
        assertTrue(LogVerifier.verifyInclusion(store.logFile(), cp, 3, logKey.getPublic(), witnessKey.getPublic()));
        {
            LogVerifier.Parsed p = LogVerifier.parse(store.logFile());
            LogVerifier.Result rr = new LogVerifier.Result();
            rr.valid = true;
            LogVerifier.verifyRecordSignatures(p, evidence.getPublic(), rr);
            assertTrue(rr.valid, rr.summary());
        }
    }

    @Test void editedRecordIsDetected(@TempDir Path dir) throws Exception {
        LogStore store = build(dir, 3);
        Checkpoint cp = signedCheckpoint(store);
        List<String> lines = Files.readAllLines(store.logFile());
        Map<String, Object> line = Json.parseObject(lines.get(1));
        @SuppressWarnings("unchecked")
        Map<String, Object> rec = (Map<String, Object>) line.get("record");
        rec.put("timestamp", "2000-01-01T00:00:00Z");
        lines.set(1, Json.write(line));
        Files.write(store.logFile(), lines);
        LogVerifier.Result r = LogVerifier.verify(store.logFile(), cp, logKey.getPublic(), witnessKey.getPublic());
        assertFalse(r.valid);
        assertTrue(r.errors.stream().anyMatch(e -> e.contains("leaf mismatch")), r.summary());
    }

    @Test void deletedRecordIsDetected(@TempDir Path dir) throws Exception {
        LogStore store = build(dir, 4);
        Checkpoint cp = signedCheckpoint(store);
        List<String> lines = new ArrayList<>(Files.readAllLines(store.logFile()));
        lines.remove(2);
        Files.write(store.logFile(), lines);
        LogVerifier.Result r = LogVerifier.verify(store.logFile(), cp, logKey.getPublic(), witnessKey.getPublic());
        assertFalse(r.valid);
        assertTrue(r.errors.stream().anyMatch(e -> e.contains("gap") || e.contains("size") || e.contains("root")),
                r.summary());
    }

    @Test void backdatedRecordIsDetectedBySignatureOrCheckpoint(@TempDir Path dir) throws Exception {
        LogStore store = build(dir, 3);
        Checkpoint cp = signedCheckpoint(store);
        List<String> lines = new ArrayList<>(Files.readAllLines(store.logFile()));
        Map<String, Object> line = Json.parseObject(lines.get(1));
        @SuppressWarnings("unchecked")
        Map<String, Object> recMap = (Map<String, Object>) line.get("record");
        EvidenceRecord rec = EvidenceRecord.fromJson(Json.write(recMap));
        rec.timestamp = "2000-01-01T00:00:00Z";
        rec.sign(evidence.getPrivate());
        byte[] leaf = Merkle.leafHash(rec.toJson().getBytes(StandardCharsets.UTF_8));
        line.put("record", rec.toMap(true));
        line.put("leaf", Base64.getEncoder().encodeToString(leaf));
        lines.set(1, Json.write(line));
        Files.write(store.logFile(), lines);
        LogVerifier.Result r = LogVerifier.verify(store.logFile(), cp, logKey.getPublic(), witnessKey.getPublic());
        assertFalse(r.valid);
        assertTrue(r.errors.stream().anyMatch(e -> e.contains("root")), r.summary());
    }

    @Test void forkAtSameSizeIsDetected(@TempDir Path dir) throws Exception {
        LogStore store = build(dir, 3);
        Checkpoint cp = signedCheckpoint(store);
        Checkpoint forged = Checkpoint.create("jvd.local/test", 3, new byte[32], logKey.getPrivate());
        assertThrows(IllegalArgumentException.class, () ->
                new Witness("w1", witnessKey.getPrivate(), witnessKey.getPublic()).cosign(forged, store));
        assertTrue(LogVerifier.isFork(cp, forged));
        LogVerifier.Result r = LogVerifier.verify(store.logFile(), forged, logKey.getPublic(), witnessKey.getPublic());
        assertFalse(r.valid);
    }

    @Test void consistencyAcrossCheckpoints(@TempDir Path dir) throws Exception {
        LogStore store = build(dir, 2);
        Checkpoint old = signedCheckpoint(store);
        for (int i = 0; i < 3; i++) {
            EvidenceRecord r = EvidenceRecord.create("/tmp/more-" + i, "CLEAR", "OVERWRITE");
            r.sign(evidence.getPrivate());
            store.append(r);
        }
        Checkpoint newer = signedCheckpoint(store);
        LogVerifier.Result r = LogVerifier.verifyConsistency(store.logFile(), old, newer,
                logKey.getPublic(), witnessKey.getPublic());
        assertTrue(r.valid, r.summary());

        // Truncating the log to the old size makes the newer checkpoint unverifiable.
        List<String> lines = new ArrayList<>(Files.readAllLines(store.logFile()));
        Files.write(store.logFile(), lines.subList(0, 2));
        LogVerifier.Result truncated = LogVerifier.verifyConsistency(store.logFile(), old, newer,
                logKey.getPublic(), witnessKey.getPublic());
        assertFalse(truncated.valid);
    }

    @Test void intentWithoutConfirmationIsUnresolved(@TempDir Path dir) throws Exception {
        LogStore store = new LogStore(dir, "jvd.local/test");
        EvidenceRecord r = EvidenceRecord.create("/tmp/x", "CLEAR", "OVERWRITE");
        r.eventType = "INTENT";
        r.verification.status = "COMMITTING";
        r.sign(evidence.getPrivate());
        store.append(r);
        Checkpoint cp = signedCheckpoint(store);
        LogVerifier.Result result = LogVerifier.verify(store.logFile(), cp,
                logKey.getPublic(), witnessKey.getPublic());
        assertFalse(result.valid);
        assertTrue(result.errors.stream().anyMatch(e -> e.contains("UNRESOLVED")), result.summary());
    }

    @Test void missingWitnessIsRejectedWhenWitnessKeySupplied(@TempDir Path dir) throws Exception {
        LogStore store = build(dir, 2);
        Checkpoint cp = store.checkpoint(logKey.getPrivate()); // no cosignature
        LogVerifier.Result r = LogVerifier.verify(store.logFile(), cp, logKey.getPublic(), witnessKey.getPublic());
        assertFalse(r.valid);
        assertTrue(r.errors.stream().anyMatch(e -> e.contains("witness")), r.summary());
    }
}
