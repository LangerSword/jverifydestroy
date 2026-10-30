package io.jvd.txn;

import io.jvd.evidence.Json;
import io.jvd.file.CryptoShredder;
import io.jvd.file.FileKeyVault;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Crash recovery. A transaction that never reached COMMITTED is restored from its vault or
 * crypto-shred container. A COMMITTED transaction is never restored; that boundary is the
 * security property.
 */
public final class Recovery {
    public record Result(String txnId, State lastState, String action, boolean restored, String detail) {}

    private Recovery() {}

    public static List<Result> recover(Path workDir) throws IOException {
        Path dir = workDir.resolve("journal");
        if (!Files.isDirectory(dir)) return List.of();
        List<Result> results = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.jsonl")) {
            for (Path file : stream) {
                String txnId = file.getFileName().toString().replaceFirst("\\.jsonl$", "");
                results.add(recoverOne(workDir, txnId, file));
            }
        }
        results.sort(Comparator.comparing(Result::txnId));
        return results;
    }

    private static Result recoverOne(Path workDir, String txnId, Path file) throws IOException {
        Journal journal = new Journal(file);
        State last = journal.lastState();
        if (last == null) return new Result(txnId, null, "empty journal", false, "");
        if (last == State.ABORTED) return new Result(txnId, last, "already aborted", false, "");
        if (last == State.RESTORE_FAILED) {
            return new Result(txnId, last, "restore previously failed; recovery material kept", false,
                    "fix permissions/space and retry; do not delete the work directory");
        }
        if (last == State.UNRESOLVED) {
            return new Result(txnId, last, "unresolved; no automatic restore or commit", false,
                    "inspect the journal and log; do not claim destroyed");
        }
        if (last == State.COMMITTED) {
            return new Result(txnId, last, "committed; no restore attempted", false,
                    "COMMITTED is irreversible by design");
        }
        Map<String, Object> vaultDetail = journal.events().stream()
                .filter(e -> e.state() == State.VAULTED)
                .map(Journal.Event::detail)
                .findFirst().orElse(Map.of());
        String target = str(vaultDetail, "target");
        String payload = str(vaultDetail, "payload");
        String keyFile = str(vaultDetail, "keyFile");

        if (last == State.COMMITTING) {
            boolean havePayload = payload != null && Files.exists(Path.of(payload));
            boolean haveKey = keyFile != null && Files.exists(Path.of(keyFile));
            String eventId = journal.events().isEmpty() ? null
                    : str(journal.events().get(journal.events().size() - 1).detail(), "eventId");
            boolean confirmed = logHasConfirmed(workDir, eventId);
            if (confirmed && !haveKey && !Files.exists(Path.of(target))) {
                journal.append(State.COMMITTED, Map.of("reason", "reconciled from CONFIRMED evidence",
                        "restored", false));
                return new Result(txnId, State.COMMITTED, "committed; CONFIRMED evidence recovered",
                        false, "reconciled from log");
            }
            if (confirmed) {
                journal.append(State.UNRESOLVED, Map.of("reason", "CONFIRMED evidence but key/target inconsistent",
                        "restored", false));
                return new Result(txnId, State.UNRESOLVED,
                        "unresolved: CONFIRMED evidence but key or target still present", false,
                        "do not claim committed");
            }
            if (havePayload && haveKey) {
                boolean restored = false;
                String detail = "";
                try {
                    byte[] key = FileKeyVault.read(Path.of(keyFile));
                    Path tmp = Path.of(target).resolveSibling(Path.of(target).getFileName() + ".restore-" + txnId);
                    CryptoShredder.decrypt(Path.of(payload), tmp, key);
                    Files.move(tmp, Path.of(target), StandardCopyOption.REPLACE_EXISTING,
                            StandardCopyOption.ATOMIC_MOVE);
                    Arrays.fill(key, (byte) 0);
                    restored = true;
                    detail = "restored from COMMITTING intent";
                } catch (Exception e) {
                    detail = "restore failed: " + e.getMessage();
                }
                if (restored) {
                    deleteQuietly(payload);
                    deleteQuietly(keyFile);
                    journal.append(State.ABORTED, Map.of("reason", "recovered from COMMITTING",
                            "restored", true, "detail", detail));
                    return new Result(txnId, last, "restored before COMMIT", true, detail);
                }
                journal.append(State.RESTORE_FAILED, Map.of("reason", "recovered from COMMITTING",
                        "restored", false, "detail", detail));
                return new Result(txnId, last, "restore failed; recovery material kept", false, detail);
            }
            journal.append(State.UNRESOLVED, Map.of("reason", "COMMITTING without key/payload",
                    "restored", false));
            return new Result(txnId, State.UNRESOLVED, "unresolved: key/payload missing after COMMITTING", false,
                    "cannot restore and cannot claim COMMITTED");
        }

        if (last == State.STAGED) {
            deleteQuietly(payload);
            deleteQuietly(keyFile);
            journal.append(State.ABORTED, Map.of("reason", "recovered from STAGED; original untouched",
                    "restored", false));
            return new Result(txnId, last, "aborted before vault; original untouched", false,
                    "crash at STAGED");
        }
        if (last == State.VAULTED) {
            deleteQuietly(payload);
            deleteQuietly(keyFile);
            journal.append(State.ABORTED, Map.of("reason", "recovered from VAULTED; original untouched",
                    "restored", false));
            return new Result(txnId, last, "aborted at vault; original untouched", false,
                    "crash at VAULTED");
        }

        // SCRUBBED or VALIDATED: the original may be gone or partially overwritten.
        boolean restored = false;
        String detail = "";
        if (target != null && payload != null && keyFile != null
                && Files.exists(Path.of(payload)) && Files.exists(Path.of(keyFile))) {
            try {
                byte[] key = FileKeyVault.read(Path.of(keyFile));
                Path tmp = Path.of(target).resolveSibling(Path.of(target).getFileName() + ".restore-" + txnId);
                CryptoShredder.decrypt(Path.of(payload), tmp, key);
                Files.move(tmp, Path.of(target), StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
                Arrays.fill(key, (byte) 0);
                restored = true;
                detail = "restored from vault";
            } catch (Exception e) {
                detail = "restore failed: " + e.getMessage();
            }
        } else {
            detail = "restore material missing";
        }
        if (restored) {
            deleteQuietly(payload);
            deleteQuietly(keyFile);
            journal.append(State.ABORTED, Map.of("reason", "recovered from " + last,
                    "restored", true, "detail", detail));
            return new Result(txnId, last, "restored before COMMIT", true, detail);
        }
        if (payload != null && keyFile != null
                && (Files.exists(Path.of(payload)) || Files.exists(Path.of(keyFile)))) {
            journal.append(State.RESTORE_FAILED, Map.of("reason", "recovered from " + last,
                    "restored", false, "detail", detail));
            return new Result(txnId, last, "restore failed; recovery material kept", false, detail);
        }
        journal.append(State.UNRESOLVED, Map.of("reason", "recovered from " + last,
                "restored", false, "detail", detail));
        return new Result(txnId, last, "restore material missing; unresolved", false, detail);
    }

    private static boolean logHasConfirmed(Path workDir, String eventId) {
        if (eventId == null || eventId.isBlank()) return false;
        Path log = workDir.resolve("log").resolve("log.jsonl");
        if (!Files.exists(log)) return false;
        try {
            for (String line : Files.readAllLines(log)) {
                if (line.isBlank()) continue;
                Map<String, Object> m = Json.parseObject(line);
                @SuppressWarnings("unchecked")
                Map<String, Object> record = (Map<String, Object>) m.get("record");
                if (record != null && "CONFIRMED".equals(String.valueOf(record.get("eventType")))
                        && eventId.equals(String.valueOf(record.get("eventId")))) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            return false;
        }
        return false;
    }

    private static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? null : v.toString();
    }

    private static void deleteQuietly(String path) {
        if (path == null) return;
        try {
            Files.deleteIfExists(Path.of(path));
        } catch (IOException ignored) {
        }
    }
}
