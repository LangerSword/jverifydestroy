package io.jvd.web;

import io.jvd.evidence.Ed25519;
import io.jvd.evidence.EvidenceRecord;
import io.jvd.evidence.Json;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogVerifier;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Checks whether an evidence log is authentic.
 *
 * <p>This class holds the logic and nothing else: no HTTP types, no sockets, no state. It takes
 * the submitted material as data and returns a {@link VerificationReport}. That separation is
 * the point — the rules that decide whether evidence is trustworthy can be tested exhaustively
 * without a server, and the server layer cannot quietly change a rule because it had to.</p>
 *
 * <p>The service keeps no state between calls and holds no mutable static state, so a single
 * instance can serve any number of requests concurrently.</p>
 *
 * <p><b>On writing the log to disk.</b> The cryptographic verification lives in
 * {@link LogVerifier}, which takes a {@link Path}, but the caller uploads log <em>content</em>
 * and must never be able to name a file on this machine. The content is therefore written to a
 * freshly created temporary file whose name the service picks, verified through the existing
 * {@code LogVerifier} API, and deleted in a {@code finally} block. Reusing the library's rules
 * rather than re-implementing them matters: a second implementation of Merkle-root comparison
 * is a second thing that can be wrong, and this service exists to answer exactly that question.</p>
 */
public final class VerificationService {

    private static final Logger LOG = System.getLogger(VerificationService.class.getName());

    /**
     * Matches anything that looks like an absolute filesystem path.
     *
     * <p>Applied to every message that leaves the service. The service itself never puts a path
     * in a message, but a library exception might, and an internal path such as a temporary
     * directory tells a stranger something about the host that they have no business knowing.</p>
     */
    private static final Pattern PATH_LIKE = Pattern.compile("/(?:[A-Za-z0-9._+-]+/)+[A-Za-z0-9._+-]*");

    /**
     * How one record fared.
     *
     * <p>The order matters: the first value that applies is the one reported, so a record that
     * is both unreadable and invalid is reported as unreadable, because that is the more
     * fundamental failure.</p>
     */
    public enum RecordStatus {
        /** The record is well formed and, if an evidence key was given, its signature verifies. */
        OK,
        /** The record could not be read as an evidence record at all. */
        UNREADABLE,
        /** The record is readable but does not satisfy the schema. */
        SCHEMA_INVALID,
        /** The record is well formed but its signature does not verify. */
        SIGNATURE_INVALID
    }

    /**
     * What happened to one record in the submitted log.
     *
     * @param seq       the sequence number the record occupies in the log
     * @param eventId   the record's event id, or empty when it could not be read
     * @param eventType the record's event type, or empty when it could not be read
     * @param status    the outcome for this record
     * @param problems  the problems found, empty for {@link RecordStatus#OK}
     */
    public record RecordResult(int seq, String eventId, String eventType,
                                RecordStatus status, List<String> problems) {
        public RecordResult {
            problems = problems == null ? List.of() : List.copyOf(problems);
            eventId = eventId == null ? "" : eventId;
            eventType = eventType == null ? "" : eventType;
        }
    }

    /**
     * Verifies the submitted material.
     *
     * <p>The returned report distinguishes three outcomes, and the distinction is the whole
     * point of the service:</p>
     * <ul>
     *   <li>{@link Outcome#AUTHENTIC} — everything checks out.</li>
     *   <li>{@link Outcome#TAMPERED} — the material was read successfully and does not match
     *       its signatures. This is a <em>successful</em> check with a negative answer, and the
     *       caller reports it as a normal result, not as a failure of the service.</li>
     *   <li>{@link Outcome#MALFORMED} — the material could not be read, so no opinion was
     *       formed. The caller reports this as a bad request.</li>
     * </ul>
     *
     * @param request the material to check; {@code null} is reported as a malformed request
     * @return the report, never {@code null}
     */
    public VerificationReport verify(VerificationRequest request) {
        if (request == null) {
            return malformed(List.of("no verification request was supplied"));
        }
        List<String> problems = new ArrayList<>();

        // ---- The request itself: is it well formed enough to attempt a check? ----
        if (isBlank(request.logContent())) problems.add("field 'log' is missing or empty");
        if (isBlank(request.checkpointContent())) problems.add("field 'checkpoint' is missing or empty");
        if (isBlank(request.logPublicKey())) problems.add("field 'logPublicKey' is missing or empty");

        PublicKey logKey = null;
        PublicKey witnessKey = null;
        PublicKey evidenceKey = null;
        if (!isBlank(request.logPublicKey())) {
            logKey = decodePublicKey(request.logPublicKey(), "logPublicKey", problems);
        }
        if (request.hasWitnessKey()) {
            witnessKey = decodePublicKey(request.witnessPublicKey(), "witnessPublicKey", problems);
        }
        if (request.hasEvidenceKey()) {
            evidenceKey = decodePublicKey(request.evidencePublicKey(), "evidencePublicKey", problems);
        }

        Checkpoint checkpoint = null;
        if (!isBlank(request.checkpointContent())) {
            try {
                checkpoint = Checkpoint.fromJson(request.checkpointContent());
                checkCheckpointShape(checkpoint, problems);
            } catch (RuntimeException e) {
                problems.add("field 'checkpoint' is not a valid checkpoint document");
            }
        }

        // ---- The log: every line must be a well formed log entry ----
        List<Submitted> submitted = List.of();
        if (!isBlank(request.logContent())) {
            submitted = readLog(request.logContent(), problems);
        }
        if (!problems.isEmpty()) {
            return malformed(problems);
        }

        // ---- The check itself ----
        Path temp = null;
        LogVerifier.Result result;
        try {
            temp = writeTemporaryLog(request.logContent());
            result = LogVerifier.verify(temp, checkpoint, logKey, witnessKey);
        } catch (IOException e) {
            // Writing and reading our own temporary file failed: this is a fault of the host,
            // not of the caller. Log it in full and tell the caller nothing about the host.
            LOG.log(Level.ERROR, "could not verify a submitted log", e);
            return malformed(List.of("the submitted log could not be processed"));
        } catch (RuntimeException e) {
            // The verifier met something it did not expect. Same reasoning: the fault is ours,
            // the visitor learns only that the check did not complete.
            LOG.log(Level.ERROR, "unexpected failure while verifying a submitted log", e);
            return malformed(List.of("the submitted log could not be processed"));
        } finally {
            deleteTemporary(temp);
        }

        List<String> errors = new ArrayList<>(result.errors);
        List<String> warnings = new ArrayList<>(result.warnings);

        // ---- Per-record results ----
        List<RecordResult> recordResults = new ArrayList<>(submitted.size());
        for (Submitted s : submitted) {
            RecordResult rr = inspect(s, evidenceKey);
            recordResults.add(rr);
            if (rr.status() == RecordStatus.OK) continue;
            errors.addAll(rr.problems());
        }

        boolean witnessChecked = witnessKey != null && witnessVerifies(checkpoint, witnessKey);
        boolean valid = result.valid && errors.isEmpty();
        Outcome outcome = valid ? Outcome.AUTHENTIC : Outcome.TAMPERED;

        List<String> safeErrors = sanitizeAll(errors);
        List<String> safeWarnings = sanitizeAll(warnings);
        return new VerificationReport(
                valid,
                outcome,
                summary(outcome, submitted.size(), safeErrors.size(), witnessChecked),
                safeErrors,
                safeWarnings,
                submitted.size(),
                recordResults,
                checkpoint.size,
                checkpoint.rootHash,
                witnessChecked,
                Instant.now().toString());
    }

    /**
     * Checks the fields the verifier will read.
     *
     * <p>{@link LogVerifier} assumes a checkpoint has a root and a signature and will throw
     * rather than report a problem if it does not. A request from the internet gets a clear
     * message instead of an exception.</p>
     */
    private void checkCheckpointShape(Checkpoint cp, List<String> problems) {
        if (cp.origin == null || cp.origin.isBlank()) {
            problems.add("field 'checkpoint' has no 'origin'");
        }
        if (cp.size < 0) {
            problems.add("field 'checkpoint' has a negative 'size'");
        }
        if (cp.rootHash == null || cp.rootHash.isBlank()) {
            problems.add("field 'checkpoint' has no 'rootHash'");
        }
        if (cp.logSignature == null || cp.logSignature.isBlank()) {
            problems.add("field 'checkpoint' has no 'logSignature'");
        }
    }

    /**
     * Checks one submitted record and describes what is wrong with it.
     *
     * <p>A record that cannot be read is reported as unreadable rather than thrown, because a
     * single malformed record is a fact about the log the visitor submitted, not a crash of
     * the service. This is what keeps a hostile log from turning into a hostile service.</p>
     */
    private RecordResult inspect(Submitted s, PublicKey evidenceKey) {
        List<String> problems = new ArrayList<>();
        RecordStatus status = RecordStatus.OK;

        EvidenceRecord record;
        try {
            record = EvidenceRecord.fromJson(Json.write(s.record()));
        } catch (RuntimeException e) {
            // The likely cause is a value outside the vocabulary this schema defines. Report
            // the offending value rather than the parser's message about it.
            Object assurance = s.record().get("assurance");
            if (assurance != null && !EvidenceSchema.assuranceLevels().contains(assurance.toString())) {
                problems.add("record " + s.seq() + ": field 'assurance' has value '" + assurance
                        + "' which is not one of " + String.join(", ", EvidenceSchema.assuranceLevels()));
            } else {
                problems.add("record " + s.seq() + ": the record cannot be read as an evidence record");
            }
            return new RecordResult(s.seq(), "", "", RecordStatus.UNREADABLE, sanitizeAll(problems));
        }

        for (String p : EvidenceSchema.validate(record)) {
            problems.add("record " + s.seq() + ": " + p);
        }
        if (!problems.isEmpty() && status == RecordStatus.OK) {
            status = RecordStatus.SCHEMA_INVALID;
        }

        if (evidenceKey != null && !record.verifySignature(evidenceKey)) {
            problems.add("record " + s.seq() + ": the record signature does not verify "
                    + "against the supplied evidence key");
            if (status == RecordStatus.OK) status = RecordStatus.SIGNATURE_INVALID;
        }

        // The problems are sanitised here as well as at the top level, because they are
        // published inside the per-record results. A record can carry a path in any field,
        // and that path must not reach the visitor through either door.
        return new RecordResult(s.seq(), record.eventId, record.eventType, status,
                sanitizeAll(problems));
    }

    /**
     * Reads the submitted log into records, reporting the first problem found.
     *
     * <p>The whole log is parsed here rather than line by line as it is verified, so that a
     * malformed log is rejected before any cryptographic work is attempted on it, and so that
     * the verifier never meets a line it cannot parse.</p>
     */
    private List<Submitted> readLog(String content, List<String> problems) {
        List<Submitted> out = new ArrayList<>();
        String[] lines = content.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].strip();
            if (line.isEmpty()) continue;
            Map<String, Object> entry;
            try {
                entry = Json.parseObject(line);
            } catch (RuntimeException e) {
                problems.add("the log line " + (i + 1) + " is not a valid JSON object");
                return List.of();
            }
            if (!(entry.get("record") instanceof Map<?, ?>)) {
                problems.add("the log line " + (i + 1) + " has no 'record' object");
                return List.of();
            }
            int seq;
            try {
                long parsed = Json.asLong(entry.get("seq"));
                if (parsed < 0 || parsed > Integer.MAX_VALUE) {
                    problems.add("the log line " + (i + 1) + " has a 'seq' number out of range");
                    return List.of();
                }
                seq = (int) parsed;
            } catch (RuntimeException e) {
                problems.add("the log line " + (i + 1) + " has no usable 'seq' number");
                return List.of();
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> record = (Map<String, Object>) entry.get("record");
            out.add(new Submitted(seq, record));
        }
        if (out.isEmpty()) {
            problems.add("the log contains no records");
        }
        return out;
    }

    /**
     * Writes the submitted log to a temporary file so the existing verifier can read it.
     *
     * <p>The file is created by the JDK with a unique name in the system temporary directory
     * and restrictive permissions, and it is deleted as soon as the check is over. The name is
     * chosen here and never comes from the request, so there is no path to traverse.</p>
     */
    private Path writeTemporaryLog(String content) throws IOException {
        Path dir = Path.of(System.getProperty("java.io.tmpdir", "."));
        Files.createDirectories(dir);
        Path temp = Files.createTempFile(dir, "jvd-web-log-", ".jsonl");
        Files.write(temp, content.getBytes(StandardCharsets.UTF_8));
        return temp;
    }

    /** Deletes the temporary file, ignoring failures: the check is already over by then. */
    private void deleteTemporary(Path temp) {
        if (temp == null) return;
        try {
            Files.deleteIfExists(temp);
        } catch (IOException e) {
            LOG.log(Level.WARNING, "could not delete a temporary verification file", e);
        }
    }

    /**
     * Decodes a base64 X.509 Ed25519 public key.
     *
     * <p>The project's own key files carry an {@code ed25519:} prefix; the API takes bare
     * base64. Both are accepted so a visitor can paste either without being told which one
     * this service happens to want.</p>
     */
    private PublicKey decodePublicKey(String material, String field, List<String> problems) {
        String text = material.strip().replaceAll("\\s", "");
        if (!text.startsWith("ed25519:")) text = "ed25519:" + text;
        try {
            return Ed25519.decodePublic(text);
        } catch (RuntimeException e) {
            problems.add("field '" + field + "' is not a base64-encoded X.509 Ed25519 public key");
            return null;
        }
    }

    /**
     * Verifies the witness co-signature without letting a malformed signature escape.
     *
     * <p>{@link Checkpoint#verifyWitness} decodes base64 that came from the internet, so it
     * can throw. The verifier already reports a bad co-signature as a problem; here we only
     * need the yes or no.</p>
     */
    private boolean witnessVerifies(Checkpoint cp, PublicKey witnessKey) {
        try {
            return cp.verifyWitness(witnessKey);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** A plain-English sentence describing the result, for a reader who is not a cryptographer. */
    private String summary(Outcome outcome, int records, int problemCount, boolean witnessChecked) {
        return switch (outcome) {
            case AUTHENTIC -> "The log matches its checkpoint and its signatures. "
                    + records + " record" + (records == 1 ? "" : "s") + " checked"
                    + (witnessChecked ? ", and the witness co-signature verified." : ".");
            case TAMPERED -> "The log does not match its checkpoint or its signatures. "
                    + problemCount + " problem" + (problemCount == 1 ? "" : "s") + " found.";
            case MALFORMED -> "The material could not be checked. "
                    + problemCount + " problem" + (problemCount == 1 ? "" : "s") + " found.";
        };
    }

    /** Builds the report for material that could not be read well enough to check. */
    private VerificationReport malformed(List<String> problems) {
        List<String> clean = sanitizeAll(problems);
        return new VerificationReport(false, Outcome.MALFORMED,
                summary(Outcome.MALFORMED, 0, clean.size(), false),
                clean, List.of(), 0, List.of(), 0, "", false, Instant.now().toString());
    }

    /**
     * Removes anything that looks like a filesystem path from every message.
     *
     * <p>Applied to every message the service returns. A visitor learns what is wrong with
     * their evidence; they never learn the layout of the machine that checked it.</p>
     */
    private static List<String> sanitizeAll(List<String> messages) {
        List<String> out = new ArrayList<>(messages.size());
        for (String m : messages) out.add(sanitize(m));
        return out;
    }

    /** Removes anything that looks like a filesystem path from one message. */
    private static String sanitize(String message) {
        if (message == null) return "";
        return PATH_LIKE.matcher(message).replaceAll("[path removed]");
    }

    /** Whether a string is absent, empty, or only whitespace. */
    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /** One record as it was submitted, before any interpretation. */
    private record Submitted(int seq, Map<String, Object> record) {
    }
}
