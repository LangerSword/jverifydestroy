package io.jvd.web;

import io.jvd.evidence.Ed25519;
import io.jvd.evidence.EvidenceRecord;
import io.jvd.evidence.Json;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;
import io.jvd.log.Merkle;
import io.jvd.log.Witness;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Builds genuine evidence logs for the tests.
 *
 * <p>These fixtures use the project's own {@link LogStore}, {@link Witness}, and
 * {@link Checkpoint}, so a log built here is a real log: the leaves are real RFC 9162 leaf
 * hashes, the checkpoint is really signed, and the witness really co-signed it. A test that
 * passes against these fixtures is testing the same cryptography the offline verifier tests.</p>
 *
 * <p>Nothing here is a mock. The tamper helpers rewrite the log exactly the way an attacker
 * would, which is the only way to know the detector notices.</p>
 */
final class Fixtures {

    /** The evidence key that signs the records. */
    final KeyPair evidenceKey = Ed25519.generate();
    /** The log key that signs the checkpoint. */
    final KeyPair logKey = Ed25519.generate();
    /** The witness key that co-signs the checkpoint. */
    final KeyPair witnessKey = Ed25519.generate();

    /** The origin recorded in the checkpoint. */
    static final String ORIGIN = "jvd.local/test";

    Fixtures() {
    }

    /**
     * Builds a log of {@code count} records plus a witness-cosigned checkpoint.
     *
     * @param dir  where to put the log; the caller owns it
     * @param count how many records to append
     */
    LogStore buildLog(Path dir, int count) throws Exception {
        LogStore store = new LogStore(dir, ORIGIN);
        for (int i = 0; i < count; i++) {
            store.append(record(i));
        }
        return store;
    }

    /** Builds one signed, well-formed record. */
    EvidenceRecord record(int i) {
        EvidenceRecord r = EvidenceRecord.create("/tmp/file-" + i, "CLEAR", "OVERWRITE");
        r.verification.operationCompleted = true;
        r.verification.status = "COMPLETED";
        r.validation.result = "PASS";
        r.validation.dataAbsent = true;
        r.sign(evidenceKey.getPrivate());
        return r;
    }

    /** Signs a checkpoint and co-signs it with the witness. */
    Checkpoint checkpoint(LogStore store) {
        Checkpoint cp = store.checkpoint(logKey.getPrivate());
        new Witness("test-witness", witnessKey.getPrivate(), witnessKey.getPublic()).cosign(cp, store);
        return cp;
    }

    /** The base64 X.509 encoding of a public key, as the API expects it. */
    static String pub(KeyPair pair) {
        return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    }

    /** A request built from a store and a checkpoint, as the API expects it. */
    VerificationRequest request(LogStore store, Checkpoint cp, boolean withWitness) throws Exception {
        return new VerificationRequest(
                Files.readString(store.logFile(), StandardCharsets.UTF_8),
                cp.toJson(),
                pub(logKey),
                withWitness ? pub(witnessKey) : null,
                null);
    }

    /**
     * Rewrites one record in the log without touching its leaf hash.
     *
     * <p>This is the edit an attacker makes: the record changes but the log still claims the
     * old hash, so the leaf no longer matches and the root no longer matches the checkpoint.</p>
     */
    static String tamperRecord(String logContent, int index, Map<String, Object> changes)
            throws Exception {
        List<String> lines = new ArrayList<>(List.of(logContent.split("\n")));
        Map<String, Object> entry = Json.parseObject(lines.get(index));
        @SuppressWarnings("unchecked")
        Map<String, Object> record = (Map<String, Object>) entry.get("record");
        record.putAll(changes);
        lines.set(index, Json.write(entry));
        return String.join("\n", lines);
    }

    /** Deletes one record from the log, leaving the sequence numbers gapped. */
    static String deleteRecord(String logContent, int index) {
        List<String> lines = new ArrayList<>(List.of(logContent.split("\n")));
        lines.remove(index);
        return String.join("\n", lines);
    }

    /**
     * Swaps two records in the log.
     *
     * <p>The sequence numbers travel with the records, so swapping them produces a log whose
     * leaves are in the wrong order. The checkpoint covers the original order, so the root
     * changes and the check fails.</p>
     */
    static String reorderRecords(String logContent, int a, int b) throws Exception {
        List<String> lines = new ArrayList<>(List.of(logContent.split("\n")));
        String first = lines.get(a);
        String second = lines.get(b);
        lines.set(a, second);
        lines.set(b, first);
        return String.join("\n", lines);
    }

    /**
     * Re-signs a record after changing it, and recomputes its leaf hash.
     *
     * <p>This is a stronger attack than {@link #tamperRecord}: the record is internally
     * consistent and its leaf hash is correct, so only the checkpoint's root can catch it.
     * Without the checkpoint it would be undetectable, which is exactly why the checkpoint
     * is what the service insists on.</p>
     */
    static String tamperAndResign(String logContent, int index, KeyPair evidenceKey,
                                  Map<String, Object> changes) throws Exception {
        List<String> lines = new ArrayList<>(List.of(logContent.split("\n")));
        Map<String, Object> entry = Json.parseObject(lines.get(index));
        @SuppressWarnings("unchecked")
        Map<String, Object> record = (Map<String, Object>) entry.get("record");
        record.putAll(changes);

        EvidenceRecord re = EvidenceRecord.fromJson(Json.write(record));
        re.sign(evidenceKey.getPrivate());
        Map<String, Object> signed = re.toMap(true);
        byte[] leaf = Merkle.leafHash(Json.write(signed).getBytes(StandardCharsets.UTF_8));
        entry.put("record", signed);
        entry.put("leaf", Base64.getEncoder().encodeToString(leaf));
        lines.set(index, Json.write(entry));
        return String.join("\n", lines);
    }
}
