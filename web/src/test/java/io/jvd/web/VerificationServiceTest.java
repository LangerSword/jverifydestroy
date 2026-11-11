package io.jvd.web;

import io.jvd.evidence.Json;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the rules that decide whether evidence is trustworthy, with no server involved.
 *
 * <p>Each fixture is a genuine signed log built with the project's own {@link LogStore}, so
 * these tests exercise the same cryptography the offline verifier exercises. A tamper helper
 * rewrites the log the way an attacker would, because a detector that has never met a real
 * forgery has not been tested.</p>
 */
class VerificationServiceTest {

    @Test void validLogIsAuthentic(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 4);
        Checkpoint cp = f.checkpoint(store);

        VerificationReport report = new VerificationService()
                .verify(f.request(store, cp, true));

        assertTrue(report.valid(), report.summary());
        assertEquals(Outcome.AUTHENTIC, report.outcome());
        assertEquals(4, report.records());
        assertEquals(4L, report.checkpointSize());
        assertTrue(report.witnessChecked(), "the witness co-signature was supplied and must be checked");
        assertEquals(List.of(), report.errors());
        assertEquals(cp.rootHash, report.checkpointRoot());
    }

    @Test void theOutcomeDistinguishesAnAnswerFromNoAnswer(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);
        VerificationService service = new VerificationService();

        // Authentic: the evidence checks out.
        assertTrue(service.verify(f.request(store, cp, true)).outcome().authentic());

        // Tampered: a definite no. It is still not authentic, but it is a real answer.
        String tampered = Fixtures.tamperRecord(Files.readString(store.logFile()), 1,
                Map.of("timestamp", "2000-01-01T00:00:00Z"));
        Outcome tamperedOutcome = service.verify(new VerificationRequest(tampered, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null)).outcome();
        assertFalse(tamperedOutcome.authentic());
        assertEquals(Outcome.TAMPERED, tamperedOutcome);

        // Malformed: no answer at all.
        Outcome malformedOutcome = service.verify(
                new VerificationRequest("{broken", "{}", "")).outcome();
        assertFalse(malformedOutcome.authentic());
        assertEquals(Outcome.MALFORMED, malformedOutcome);
    }

    @Test void witnessCoSignatureIsChecked(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);

        // Without the witness key the check cannot be made, and the report must say so
        // rather than quietly claiming the co-signature was checked.
        VerificationReport without = new VerificationService().verify(f.request(store, cp, false));
        assertTrue(without.valid());
        assertFalse(without.witnessChecked());
        assertTrue(without.warnings().stream().anyMatch(w -> w.contains("witness")),
                without.warnings().toString());

        // With the witness key the co-signature is verified.
        VerificationReport with = new VerificationService().verify(f.request(store, cp, true));
        assertTrue(with.witnessChecked());
    }

    @Test void witnessFromAnotherKeyIsRejected(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);

        // A witness key that did not sign this checkpoint must not be accepted.
        var otherWitness = io.jvd.evidence.Ed25519.generate();
        VerificationRequest request = new VerificationRequest(
                Files.readString(store.logFile()),
                cp.toJson(),
                Fixtures.pub(f.logKey),
                Fixtures.pub(otherWitness),
                null);

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertEquals(Outcome.TAMPERED, report.outcome());
        assertFalse(report.witnessChecked());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("witness")),
                report.errors().toString());
    }

    @Test void tamperedRecordIsDetected(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 3);
        Checkpoint cp = f.checkpoint(store);
        String original = Files.readString(store.logFile());

        String tampered = Fixtures.tamperRecord(original, 1,
                Map.of("timestamp", "2000-01-01T00:00:00Z"));
        VerificationRequest request = new VerificationRequest(tampered, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null);

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertEquals(Outcome.TAMPERED, report.outcome());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("leaf mismatch")),
                report.errors().toString());
    }

    @Test void tamperedAndResignedRecordIsCaughtByTheCheckpoint(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 3);
        Checkpoint cp = f.checkpoint(store);
        String original = Files.readString(store.logFile());

        // A stronger attack: the record is re-signed and its leaf hash is recomputed, so
        // only the checkpoint's root can detect it. This is the case the checkpoint exists for.
        String tampered = Fixtures.tamperAndResign(original, 1, f.evidenceKey,
                Map.of("timestamp", "2000-01-01T00:00:00Z"));
        VerificationRequest request = new VerificationRequest(tampered, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null);

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertEquals(Outcome.TAMPERED, report.outcome());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("root")),
                report.errors().toString());
    }

    @Test void deletedRecordIsDetected(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 4);
        Checkpoint cp = f.checkpoint(store);
        String original = Files.readString(store.logFile());

        String truncated = Fixtures.deleteRecord(original, 2);
        VerificationRequest request = new VerificationRequest(truncated, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null);

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertEquals(Outcome.TAMPERED, report.outcome());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("gap")
                        || e.contains("size") || e.contains("root")),
                report.errors().toString());
    }

    @Test void reorderedRecordIsDetected(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 4);
        Checkpoint cp = f.checkpoint(store);
        String original = Files.readString(store.logFile());

        String reordered = Fixtures.reorderRecords(original, 0, 2);
        VerificationRequest request = new VerificationRequest(reordered, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null);

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertEquals(Outcome.TAMPERED, report.outcome());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("gap")
                        || e.contains("leaf mismatch") || e.contains("root")),
                report.errors().toString());
    }

    @Test void malformedJsonBodyIsRejectedWithAClearMessage(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 1);
        Checkpoint cp = f.checkpoint(store);

        VerificationRequest request = new VerificationRequest(
                "{not json at all", cp.toJson(), Fixtures.pub(f.logKey));

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertEquals(Outcome.MALFORMED, report.outcome());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("line 1")
                        && e.contains("not a valid JSON object")),
                report.errors().toString());
    }

    @Test void missingFieldsAreReported(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 1);
        Checkpoint cp = f.checkpoint(store);

        VerificationRequest request = new VerificationRequest(
                Files.readString(store.logFile()), cp.toJson(), null);

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertEquals(Outcome.MALFORMED, report.outcome());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("logPublicKey")),
                report.errors().toString());
    }

    @Test void badPublicKeyIsReportedAsAFieldProblem(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 1);
        Checkpoint cp = f.checkpoint(store);

        VerificationRequest request = new VerificationRequest(
                Files.readString(store.logFile()), cp.toJson(), "not-a-real-key");

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertEquals(Outcome.MALFORMED, report.outcome());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("logPublicKey")
                        && e.contains("Ed25519")),
                report.errors().toString());
    }

    @Test void schemaViolationIsReportedAsAProblemNotACrash(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);
        String original = Files.readString(store.logFile());

        // A record with an assurance level outside the vocabulary. The record cannot even be
        // read back, so this must be reported, not thrown.
        String bad = Fixtures.tamperRecord(original, 1, Map.of("assurance", "A9"));
        VerificationRequest request = new VerificationRequest(bad, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null);

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("assurance")),
                report.errors().toString());
    }

    @Test void aRecordWithABadEnumIsMarkedSchemaInvalid(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);
        String original = Files.readString(store.logFile());

        // An event type outside the vocabulary still parses as a record, so it is a schema
        // problem rather than an unreadable one. The distinction has to be right because a
        // visitor is told which one it is.
        String bad = Fixtures.tamperRecord(original, 1, Map.of("eventType", "PROBABLY"));
        VerificationRequest request = new VerificationRequest(bad, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null);

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("eventType")
                        && e.contains("PROBABLY")),
                report.errors().toString());
        assertEquals(1, report.recordResults().stream()
                .filter(r -> r.status() == VerificationService.RecordStatus.SCHEMA_INVALID)
                .count(), report.recordResults().toString());
    }

    @Test void recordSignatureIsCheckedWhenTheEvidenceKeyIsSupplied(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);
        String original = Files.readString(store.logFile());

        // Re-sign the edited record with a different evidence key. The log's own leaf hash
        // still matches, so only the record signature check can notice.
        var otherEvidence = io.jvd.evidence.Ed25519.generate();
        String tampered = Fixtures.tamperAndResign(original, 1, otherEvidence,
                Map.of("timestamp", "2000-01-01T00:00:00Z"));
        VerificationRequest request = new VerificationRequest(tampered, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), Fixtures.pub(f.evidenceKey));

        VerificationReport report = new VerificationService().verify(request);

        assertFalse(report.valid());
        assertTrue(report.errors().stream().anyMatch(e -> e.contains("signature does not verify")),
                report.errors().toString());
    }

    @Test void noFilesystemPathLeaksIntoAnyMessage(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);
        String original = Files.readString(store.logFile());

        // Every way a message could end up carrying a path.
        String tampered = Fixtures.tamperRecord(original, 1,
                Map.of("subjectLabel", "/home/someone/secret.txt"));
        String reordered = Fixtures.reorderRecords(original, 0, 1);
        String deleted = Fixtures.deleteRecord(original, 0);

        List<VerificationRequest> requests = new ArrayList<>(List.of(
                f.request(store, cp, true),
                new VerificationRequest(tampered, cp.toJson(), Fixtures.pub(f.logKey)),
                new VerificationRequest(reordered, cp.toJson(), Fixtures.pub(f.logKey)),
                new VerificationRequest(deleted, cp.toJson(), Fixtures.pub(f.logKey)),
                new VerificationRequest("garbage", "garbage", "garbage"),
                new VerificationRequest(null, null, null)));

        // A record whose field holds a path: the path must not survive anywhere in the report.
        String pathRecord = Fixtures.tamperRecord(original, 1,
                Map.of("assurance", "/etc/shadow/leaked"));
        requests.add(new VerificationRequest(pathRecord, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null));

        VerificationService service = new VerificationService();
        for (VerificationRequest request : requests) {
            VerificationReport report = service.verify(request);
            List<String> everyMessage = new ArrayList<>(report.errors());
            everyMessage.addAll(report.warnings());
            // The per-record results are a second door out of the service, so they are checked
            // as carefully as the top-level error list.
            for (VerificationService.RecordResult rr : report.recordResults()) {
                everyMessage.addAll(rr.problems());
            }
            for (String message : everyMessage) {
                assertFalse(message.contains(dir.toString()),
                        "the report leaked the working directory: " + message);
                assertFalse(message.contains("/etc/shadow"),
                        "the report leaked a filesystem path: " + message);
                assertFalse(message.matches(".*(?<![\\w])/[\\w./-]+/.*"),
                        "the report leaked a filesystem path: " + message);
            }
        }
    }

    @Test void reportJsonIsWellFormedAndCarriesTheContractFields(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);

        VerificationReport report = new VerificationService().verify(f.request(store, cp, true));
        Map<String, Object> parsed = Json.parseObject(report.toJson());

        assertEquals(Boolean.TRUE, parsed.get("valid"));
        assertEquals("AUTHENTIC", parsed.get("outcome"));
        assertTrue(parsed.get("summary") instanceof String);
        assertTrue(parsed.get("errors") instanceof List<?>);
        assertEquals(2L, ((Number) parsed.get("records")).longValue());
        assertEquals(2L, ((Number) parsed.get("checkpointSize")).longValue());
        assertEquals(Boolean.TRUE, parsed.get("witnessChecked"));
        assertTrue(parsed.get("checkedAt") instanceof String);
        // The timestamp must be parseable as an instant, not just present.
        assertTrue(java.time.Instant.parse((String) parsed.get("checkedAt")) != null);
    }

    @Test void theServiceHoldsNoStateBetweenCalls(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 3);
        Checkpoint cp = f.checkpoint(store);
        VerificationService service = new VerificationService();

        VerificationReport good = service.verify(f.request(store, cp, true));
        String tampered = Fixtures.tamperRecord(Files.readString(store.logFile()), 1,
                Map.of("timestamp", "2000-01-01T00:00:00Z"));
        VerificationReport bad = service.verify(new VerificationRequest(tampered, cp.toJson(),
                Fixtures.pub(f.logKey), Fixtures.pub(f.witnessKey), null));
        VerificationReport goodAgain = service.verify(f.request(store, cp, true));

        assertTrue(good.valid());
        assertFalse(bad.valid());
        assertTrue(goodAgain.valid(), "a failed check must not poison the next one");
        assertNotEquals(good.checkedAt(), goodAgain.checkedAt());
    }

    @Test void concurrentChecksGiveTheSameAnswers(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 5);
        Checkpoint cp = f.checkpoint(store);
        VerificationService service = new VerificationService();
        VerificationRequest request = f.request(store, cp, true);

        var results = new java.util.concurrent.ConcurrentLinkedQueue<VerificationReport>();
        var threads = new java.util.ArrayList<Thread>();
        for (int i = 0; i < 8; i++) {
            Thread t = new Thread(() -> {
                for (int n = 0; n < 5; n++) results.add(service.verify(request));
            });
            threads.add(t);
            t.start();
        }
        for (Thread t : threads) t.join();

        assertEquals(40, results.size());
        for (VerificationReport r : results) {
            assertTrue(r.valid(), r.summary());
            assertEquals(5, r.records());
        }
    }
}
