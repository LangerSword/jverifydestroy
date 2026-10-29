package io.jvd.txn;

import io.jvd.evidence.AssuranceLevel;
import io.jvd.evidence.EvidenceRecord;
import io.jvd.file.CryptoShredder;
import io.jvd.file.FileDestroyer;
import io.jvd.file.FileKeyVault;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;
import io.jvd.log.Witness;
import io.jvd.verify.FileScanner;
import io.jvd.verify.ScanResult;

import java.io.IOException;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.*;

/**
 * Commit/rollback destruction transaction for one file.
 *
 * <pre>
 * STAGED -> VAULTED -> SCRUBBED -> VALIDATED -> [grace] -> COMMITTED
 *                                   \-> ABORTED (restore)
 * </pre>
 *
 * <p>Before COMMIT the vault (or crypto-shred container + key) can restore the original.
 * At COMMIT the vault and its key are destroyed. There is no restore after COMMIT; that
 * irreversibility is the guarantee, not a missing feature.</p>
 */
public final class DestructionTransaction {
    public record Outcome(String txnId, State state, FileValidation validation,
                          EvidenceRecord record, boolean restored, String detail) {}

    @FunctionalInterface
    public interface CrashHook {
        void after(State state);
    }

    private final TxnConfig cfg;
    private final KeyPair evidenceKey;
    private final LogStore log;
    private final PrivateKey logKey;
    private final Witness witness;
    private final CrashHook crashHook;

    private String txnId;
    private Journal journal;
    private State state;
    private Path payload;
    private Path keyFile;
    private byte[] keyBytes;
    private EvidenceRecord record;
    private FileValidation validation;
    private boolean rawImagePreFound;

    public DestructionTransaction(TxnConfig cfg, KeyPair evidenceKey, LogStore log,
                                  PrivateKey logKey, Witness witness) {
        this(cfg, evidenceKey, log, logKey, witness, state -> {
            if (state.name().equals(System.getProperty("jvd.crashAt"))) {
                Runtime.getRuntime().halt(137);
            }
        });
    }

    public DestructionTransaction(TxnConfig cfg, KeyPair evidenceKey, LogStore log,
                                  PrivateKey logKey, Witness witness, CrashHook crashHook) {
        this.cfg = Objects.requireNonNull(cfg);
        this.evidenceKey = Objects.requireNonNull(evidenceKey);
        this.log = Objects.requireNonNull(log);
        this.logKey = Objects.requireNonNull(logKey);
        this.witness = witness;
        this.crashHook = Objects.requireNonNull(crashHook);
    }

    public String txnId() { return txnId; }

    public State state() { return state; }

    public EvidenceRecord record() { return record; }

    public FileValidation validation() { return validation; }

    public Path journalFile() { return journal == null ? null : journal.file(); }

    public Outcome run() throws IOException {
        try {
            start();
            scrub();
            validation = validate();
            if (validation.failed()) return rollback("validation failed: " + validation.reason());
            if ("NOT_CHECKABLE".equals(validation.result()) && !cfg.allowLogicalOnly()) {
                return rollback("required validation was NOT_CHECKABLE: " + validation.reason());
            }
            if (cfg.graceMillis() > 0) Thread.sleep(cfg.graceMillis());
            return commit();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return rollback("interrupted");
        } catch (Exception e) {
            if (state != null && state != State.COMMITTED && state != State.ABORTED) {
                try { rollback("exception: " + e); } catch (Exception ignored) { }
            }
            throw e;
        }
    }

    public void start() throws IOException {
        if (!Files.isRegularFile(cfg.target())) throw new IOException("not a regular file: " + cfg.target());
        long size = Files.size(cfg.target());
        Files.createDirectories(cfg.workDir());
        txnId = UUID.randomUUID().toString();
        journal = Journal.open(cfg.workDir(), txnId);
        record = EvidenceRecord.create(cfg.target().toString(), cfg.method().nistMethod(), cfg.method().technique());
        record.verification.operationCompleted = false;
        record.verification.status = "STAGED";
        record.validation.result = "NOT_RUN";
        record.assurance = AssuranceLevel.A0;
        state = State.STAGED;
        journal.append(State.STAGED, detail(Map.of("target", cfg.target().toString(),
                "method", cfg.method().name(), "size", size)));
        if (cfg.rawImage() != null && cfg.maskedCanary() != null) {
            ScanResult pre = FileScanner.scan(cfg.rawImage(), cfg.maskedCanary());
            rawImagePreFound = pre.found();
            record.validation.checks.add("raw image pre-check: " + pre.verdict()
                    + (pre.reason() == null ? "" : " (" + pre.reason() + ")"));
        }
        crashHook.after(State.STAGED);

        Path keys = cfg.workDir().resolve("keys");
        Files.createDirectories(keys);
        if (cfg.method() == Method.OVERWRITE) {
            Path vaultDir = cfg.workDir().resolve("vault");
            Files.createDirectories(vaultDir);
            payload = vaultDir.resolve(txnId + ".bin");
            keyFile = keys.resolve(txnId + ".vault.key");
        } else {
            Path containers = cfg.workDir().resolve("containers");
            Files.createDirectories(containers);
            payload = containers.resolve(txnId + ".jvd");
            keyFile = keys.resolve(txnId + ".dek");
        }
        CryptoShredder.encrypt(cfg.target(), payload, keyFile);
        keyBytes = FileKeyVault.read(keyFile);
        if (!CryptoShredder.canDecrypt(payload, keyBytes)) {
            throw new IOException("vault/container does not decrypt after creation");
        }
        state = State.VAULTED;
        record.verification.status = "VAULTED";
        journal.append(State.VAULTED, detail(Map.of("target", cfg.target().toString(),
                "payload", payload.toString(), "keyFile", keyFile.toString(), "size", size)));
        crashHook.after(State.VAULTED);
    }

    public FileDestroyer.Result scrub() throws IOException {
        require(State.VAULTED);
        FileDestroyer.Result d = FileDestroyer.destroy(cfg.target(), 1, true);
        state = State.SCRUBBED;
        record.verification.status = "SCRUBBED";
        journal.append(State.SCRUBBED, detail(Map.of("bytes", d.bytes(), "passes", d.passes(),
                "deleted", d.deleted(), "note", d.note())));
        crashHook.after(State.SCRUBBED);
        return d;
    }

    public FileValidation validate() throws IOException {
        require(State.SCRUBBED);
        List<String> checks = new ArrayList<>();
        boolean ok = true;
        boolean rawCheckable = false;
        String reason = null;

        if (Files.exists(cfg.target())) {
            checks.add("path absent: FAIL");
            ok = false;
        } else {
            checks.add("path absent: PASS");
        }
        if (keyBytes == null || !Files.exists(payload) || !CryptoShredder.canDecrypt(payload, keyBytes)) {
            checks.add("rollback copy decrypts: FAIL");
            ok = false;
        } else {
            checks.add("rollback copy decrypts: PASS");
        }
        if (cfg.rawImage() != null && cfg.maskedCanary() != null) {
            if (!rawImagePreFound) {
                checks.add("raw image: NOT_CHECKABLE (canary not found in the image before destruction; "
                        + "the image is not a witness for this file)");
                reason = "raw image pre-check failed";
            } else {
                ScanResult s = FileScanner.scan(cfg.rawImage(), cfg.maskedCanary());
                checks.add("raw image: " + s.verdict() + (s.reason() == null ? "" : " (" + s.reason() + ")"));
                if (s.found()) {
                    ok = false;
                    reason = "canary found in raw image";
                } else if (s.notFound()) {
                    rawCheckable = true;
                } else {
                    reason = s.reason();
                }
            }
        } else {
            checks.add("raw image: NOT_CHECKABLE (no raw image + canary supplied)");
            reason = "no raw image supplied";
        }

        String result = !ok ? "FAIL" : rawCheckable ? "PASS" : "NOT_CHECKABLE";
        validation = new FileValidation(result, ok && rawCheckable, checks, reason);
        state = State.VALIDATED;
        record.verification.status = "VALIDATED";
        journal.append(State.VALIDATED, detail(Map.of("result", result,
                "checks", checks, "reason", reason == null ? "" : reason)));
        crashHook.after(State.VALIDATED);
        return validation;
    }

    public Outcome commit() throws IOException {
        require(State.VALIDATED);
        if (validation == null || validation.failed()) throw new IllegalStateException("cannot commit a failed validation");
        if ("NOT_CHECKABLE".equals(validation.result()) && !cfg.allowLogicalOnly()) {
            throw new IllegalStateException("cannot commit NOT_CHECKABLE under requireCheckable");
        }

        List<String> postChecks = new ArrayList<>();
        boolean ok = true;
        if (cfg.method() == Method.CRYPTO_SHRED) {
            CryptoShredder.destroyKey(keyFile, keyBytes);
            boolean can = CryptoShredder.canDecrypt(payload, keyBytes);
            postChecks.add("decrypt after key destruction: " + (can ? "FAIL" : "PASS"));
            if (can) ok = false;
        } else {
            FileKeyVault.destroy(keyFile);
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
            Files.deleteIfExists(payload);
            postChecks.add("vault destroyed: " + (Files.exists(payload) ? "FAIL" : "PASS"));
            if (Files.exists(payload)) ok = false;
        }
        if (Files.exists(cfg.target())) {
            postChecks.add("path absent: FAIL");
            ok = false;
        } else {
            postChecks.add("path absent: PASS");
        }
        boolean rawCheckable = false;
        if (cfg.rawImage() != null && cfg.maskedCanary() != null && rawImagePreFound) {
            ScanResult s = FileScanner.scan(cfg.rawImage(), cfg.maskedCanary());
            postChecks.add("raw image after commit: " + s.verdict());
            if (s.found()) ok = false;
            else if (s.notFound()) rawCheckable = true;
        } else if (cfg.rawImage() != null && cfg.maskedCanary() != null) {
            postChecks.add("raw image after commit: NOT_CHECKABLE (pre-check failed)");
        }
        String postResult = !ok ? "FAIL" : rawCheckable ? "PASS" : "NOT_CHECKABLE";

        state = State.COMMITTED;
        record.verification.operationCompleted = true;
        record.verification.status = "COMMITTED";
        record.verification.notes.add("journal=" + journal.file());
        record.validation.result = postResult;
        record.validation.dataAbsent = ok && rawCheckable;
        record.validation.checks.addAll(validation.checks());
        record.validation.checks.addAll(postChecks);
        record.validation.reason = "pre-commit: " + validation.result() + "; post-commit: " + postResult;
        record.validation.positive.applicable = false;
        record.validation.positive.actual = "NOT_APPLICABLE";
        record.validation.positive.detail = "file-level transaction uses path/decrypt checks, not canary controls";
        record.validation.negative.applicable = false;
        record.validation.negative.actual = "NOT_APPLICABLE";
        record.validation.negative.detail = "file-level transaction uses path/decrypt checks, not canary controls";
        // A3 requires an independent process re-validation (the memory verifier). This file
        // transaction has witness cosigning but no such re-validation, so it stays at its ceiling.
        record.assurance = cfg.method().ceiling();
        record.sign(evidenceKey.getPrivate());
        log.append(record);
        Checkpoint cp = log.checkpoint(logKey);
        if (witness != null) witness.cosign(cp);
        Path checkpoints = cfg.workDir().resolve("checkpoints");
        Files.createDirectories(checkpoints);
        LogStore.writeCheckpoint(checkpoints.resolve(txnId + ".json"), cp);
        LogStore.writeCheckpoint(checkpoints.resolve("latest.json"), cp);

        journal.append(State.COMMITTED, detail(Map.of("result", postResult,
                "checks", postChecks, "checkpoint", cp.toJson())));
        crashHook.after(State.COMMITTED);
        return new Outcome(txnId, state, validation, record, false,
                "COMMITTED: no restore is possible after this point");
    }

    public Outcome rollback(String reason) throws IOException {
        if (state == State.COMMITTED) throw new IllegalStateException("cannot roll back after COMMIT");
        if (state == State.ABORTED) return new Outcome(txnId, state, validation, record, false, reason);
        boolean restored = false;
        String detailText = reason;
        if (payload != null && keyBytes != null && Files.exists(payload)) {
            Path tmp = cfg.target().resolveSibling(cfg.target().getFileName() + ".restore-" + txnId);
            try {
                CryptoShredder.decrypt(payload, tmp, keyBytes);
                Files.move(tmp, cfg.target(), StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
                restored = true;
            } catch (Exception e) {
                detailText += "; restore failed: " + e.getMessage();
                Files.deleteIfExists(tmp);
            }
        }
        try { Files.deleteIfExists(payload); } catch (IOException ignored) { }
        try {
            if (keyFile != null) FileKeyVault.destroy(keyFile);
        } catch (IOException ignored) { }
        if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
        state = State.ABORTED;
        record.verification.operationCompleted = false;
        record.verification.status = "ABORTED";
        record.validation.result = restored ? "FAIL" : "NOT_CHECKABLE";
        record.validation.dataAbsent = false;
        record.validation.reason = detailText;
        record.validation.checks.add("rollback requested: " + reason);
        record.validation.checks.add("restored: " + restored);
        record.assurance = AssuranceLevel.A0;
        journal.append(State.ABORTED, detail(Map.of("reason", detailText, "restored", restored)));
        try {
            record.sign(evidenceKey.getPrivate());
            log.append(record);
            Checkpoint cp = log.checkpoint(logKey);
            if (witness != null) witness.cosign(cp);
            Path checkpoints = cfg.workDir().resolve("checkpoints");
            Files.createDirectories(checkpoints);
            LogStore.writeCheckpoint(checkpoints.resolve(txnId + ".json"), cp);
            LogStore.writeCheckpoint(checkpoints.resolve("latest.json"), cp);
        } catch (Exception ignored) {
            // An aborted transaction that cannot log is still aborted; the journal records it.
        }
        return new Outcome(txnId, state, validation, record, restored, detailText);
    }

    private void require(State expected) {
        if (state != expected) throw new IllegalStateException("expected " + expected + " but was " + state);
    }

    private Map<String, Object> detail(Map<String, Object> m) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        out.put("txnId", txnId);
        out.put("method", cfg.method().name());
        return out;
    }
}
