package io.jvd.log;

import io.jvd.evidence.EvidenceRecord;
import io.jvd.evidence.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.*;

/**
 * Offline verification of a log, a checkpoint, and (optionally) a witness signature.
 * Detects edited records, deleted/gapped records, a truncated log, a root mismatch, a bad
 * checkpoint signature, a missing/bad witness signature, and a same-size fork between two
 * checkpoints. It cannot detect a rewrite by an operator who holds the log key and withholds
 * every old checkpoint; that limitation is part of the threat model.
 */
public final class LogVerifier {
    public static final class Result {
        public boolean valid;
        public final List<String> errors = new ArrayList<>();
        public final List<String> warnings = new ArrayList<>();
        public long size;
        public String rootHash;

        void error(String s) { errors.add(s); valid = false; }
        void warn(String s) { warnings.add(s); }

        public String summary() {
            return (valid ? "VALID" : "INVALID") + " size=" + size + " root=" + rootHash
                    + (errors.isEmpty() ? "" : " errors=" + errors)
                    + (warnings.isEmpty() ? "" : " warnings=" + warnings);
        }
    }

    public static final class Parsed {
        public final List<byte[]> leaves = new ArrayList<>();
        public final List<Map<String, Object>> records = new ArrayList<>();
        public final List<Long> seqs = new ArrayList<>();
        public final List<String> errors = new ArrayList<>();
        public byte[] root;
    }

    public static Parsed parse(Path logFile) throws IOException {
        Parsed p = new Parsed();
        long expected = 0;
        for (String line : Files.readAllLines(logFile, StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            Map<String, Object> m;
            try {
                m = Json.parseObject(line);
            } catch (RuntimeException e) {
                p.errors.add("unparseable line after seq " + (expected - 1) + ": " + e.getMessage());
                break;
            }
            long seq = Json.asLong(m.get("seq"));
            if (seq != expected) p.errors.add("seq gap: expected " + expected + " got " + seq);
            @SuppressWarnings("unchecked")
            Map<String, Object> record = (Map<String, Object>) m.get("record");
            String recordJson = Json.write(record);
            byte[] leaf = Merkle.leafHash(recordJson.getBytes(StandardCharsets.UTF_8));
            String stored = String.valueOf(m.get("leaf"));
            if (!Base64.getEncoder().encodeToString(leaf).equals(stored)) {
                p.errors.add("leaf mismatch at seq " + seq);
            }
            p.leaves.add(leaf);
            p.records.add(record);
            p.seqs.add(seq);
            expected = seq + 1;
        }
        p.root = Merkle.rootOfHashes(p.leaves);
        return p;
    }

    public static Result verify(Path logFile, Checkpoint cp, PublicKey logKey, PublicKey witnessKey)
            throws IOException {
        Parsed p = parse(logFile);
        Result r = new Result();
        r.valid = true;
        r.size = p.leaves.size();
        r.rootHash = Base64.getEncoder().encodeToString(p.root);
        for (String e : p.errors) r.error(e);
        checkCheckpoint(cp, r, logKey, witnessKey);

        if (cp.size != p.leaves.size()) {
            r.error("checkpoint size " + cp.size + " != log entries " + p.leaves.size()
                    + (cp.size > p.leaves.size() ? " (truncated log)" : " (entries beyond checkpoint)"));
        }
        if (!Arrays.equals(cp.root(), p.root)) {
            r.error("checkpoint root does not match computed root");
        }
        return r;
    }

    public static Result verify(Path logFile, Path checkpointFile, PublicKey logKey, PublicKey witnessKey)
            throws IOException {
        return verify(logFile, LogStore.readCheckpoint(checkpointFile), logKey, witnessKey);
    }

    private static void checkCheckpoint(Checkpoint cp, Result r, PublicKey logKey, PublicKey witnessKey) {
        if (cp.origin == null || cp.size < 0 || cp.rootHash == null) {
            r.error("malformed checkpoint");
            return;
        }
        if (!cp.verifyLog(logKey)) r.error("bad checkpoint log signature");
        if (witnessKey != null) {
            if (cp.witnessName == null || cp.witnessSignature == null) {
                r.error("checkpoint has no witness cosignature");
            } else if (!cp.verifyWitness(witnessKey)) {
                r.error("bad witness cosignature");
            }
        } else {
            r.warn("witness key not supplied; split-view detection not checked");
        }
    }

    /** Verify that the tree at {@code older.size} is a prefix of the tree at {@code newer.size}. */
    public static Result verifyConsistency(Path logFile, Checkpoint older, Checkpoint newer,
                                           PublicKey logKey, PublicKey witnessKey) throws IOException {
        Parsed p = parse(logFile);
        Result r = new Result();
        r.valid = true;
        r.size = p.leaves.size();
        r.rootHash = Base64.getEncoder().encodeToString(p.root);
        for (String e : p.errors) r.error(e);
        checkCheckpoint(older, r, logKey, witnessKey);
        checkCheckpoint(newer, r, logKey, witnessKey);
        if (older.origin != null && newer.origin != null && !older.origin.equals(newer.origin)) {
            r.error("checkpoint origins differ");
        }
        if (older.size > newer.size) r.error("older checkpoint is larger than newer");
        if (older.size > p.leaves.size() || newer.size > p.leaves.size()) {
            r.error("checkpoint size exceeds available log entries (truncated log)");
            return r;
        }
        if (!Arrays.equals(Merkle.rootOfHashes(p.leaves.subList(0, (int) newer.size)), newer.root())) {
            r.error("newer checkpoint root does not match its log prefix");
        }
        List<byte[]> proof = Merkle.consistencyProof((int) older.size, p.leaves.subList(0, (int) newer.size));
        if (!Merkle.verifyConsistency((int) older.size, (int) newer.size, older.root(), newer.root(), proof)) {
            r.error("consistency proof failed (fork or rewrite)");
        }
        return r;
    }

    /** Verify an inclusion proof for one sequence number against a checkpoint. */
    public static boolean verifyInclusion(Path logFile, Checkpoint cp, long seq,
                                          PublicKey logKey, PublicKey witnessKey) throws IOException {
        Parsed p = parse(logFile);
        Result r = new Result();
        r.valid = true;
        checkCheckpoint(cp, r, logKey, witnessKey);
        if (!r.valid) return false;
        if (seq < 0 || seq >= p.leaves.size() || seq >= cp.size) return false;
        if (!Arrays.equals(cp.root(), p.root)) return false;
        List<byte[]> proof = Merkle.inclusionProof((int) seq, p.leaves);
        return Merkle.verifyInclusion(p.leaves.get((int) seq), (int) seq, (int) cp.size, cp.root(), proof);
    }

    /**
     * Same-size fork check. Two checkpoints at the same size with different roots cannot both
     * describe the same append-only log.
     */
    public static boolean isFork(Checkpoint a, Checkpoint b) {
        return a != null && b != null && a.size == b.size
                && !Objects.equals(a.rootHash, b.rootHash)
                && Objects.equals(a.origin, b.origin);
    }

    /** Optional: verify every evidence-record signature with a known evidence public key. */
    public static void verifyRecordSignatures(Parsed p, PublicKey evidenceKey, Result r) {
        for (int i = 0; i < p.records.size(); i++) {
            try {
                EvidenceRecord rec = EvidenceRecord.fromJson(Json.write(p.records.get(i)));
                if (!rec.verifySignature(evidenceKey)) r.error("record signature invalid at seq " + i);
            } catch (RuntimeException e) {
                r.error("record " + i + " cannot be parsed: " + e.getMessage());
            }
        }
    }
}
