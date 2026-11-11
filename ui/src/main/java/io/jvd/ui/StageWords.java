package io.jvd.ui;

import io.jvd.txn.State;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The plain-language vocabulary of the desktop app.
 *
 * <p>Two rules govern every string here, and both exist because the app deals with a
 * destructive operation that a person cannot undo:
 *
 * <ol>
 *   <li><b>Never overstate.</b> The technique is real, but user-space Java cannot verify
 *       physical flash (NIST SP 800-88 Rev.2 puts user-space tools at the logical level).
 *       The limit is therefore never more than one line away from a success message.</li>
 *   <li><b>Never merge verification with validation.</b> Rev.2 keeps them apart: a machine
 *       result is not a decision. "We checked" and "a person signed off" are different
 *       lines, always.</li>
 * </ol>
 *
 * <p>Centralising the wording means a reviewer can audit the whole user-facing language in
 * one file, and a test can assert that no internal term leaks into it.
 */
final class StageWords {

    /**
     * The stages of a destruction, in the order the transaction performs them.
     *
     * <p>The order matches the transaction exactly. The names are what the user reads, so
     * they describe the <em>effect</em> rather than the mechanism.
     */
    static final List<StageTimeline.Stage> DESTRUCTION_STAGES = List.of(
            new StageTimeline.Stage("Checking your file",
                    "We look at the file and work out how to destroy it."),
            new StageTimeline.Stage("Making a protected copy",
                    "We keep an encrypted copy, so a failed run can put the file back."),
            new StageTimeline.Stage("Destroying the original",
                    "We overwrite the original with zeros, then delete it."),
            new StageTimeline.Stage("Checking what is left",
                    "We look for the file and try to read the copy we kept."),
            new StageTimeline.Stage("Making it final",
                    "We destroy the key that opens the copy. From here it cannot be undone."),
            new StageTimeline.Stage("Writing the receipt",
                    "We write a signed record, so you can prove what happened later."));

    private static final Map<String, String> POINT_WORDS = new LinkedHashMap<>();

    static {
        POINT_WORDS.put("STAGED", "Checking your file");
        POINT_WORDS.put("VAULTED", "Making a protected copy");
        POINT_WORDS.put("SCRUBBED", "Destroying the original");
        POINT_WORDS.put("VALIDATED", "Checking what is left");
        POINT_WORDS.put("COMMITTING", "Making it final");
        POINT_WORDS.put("KEY_DESTROYED", "Making it final");
        POINT_WORDS.put("CONFIRMED", "Writing the receipt");
        POINT_WORDS.put("COMMITTED", "Writing the receipt");
        POINT_WORDS.put("UNRESOLVED", "We could not finish");
    }

    private StageWords() {}

    /**
     * Maps a transaction stage point onto the index of the user-facing stage list.
     *
     * <p>Returns -1 when the point has no user-facing stage, which happens for the
     * internal points the user never needs to see.
     */
    static int stageIndex(String point) {
        return switch (point) {
            case "STAGED" -> 0;
            case "VAULTED" -> 1;
            case "SCRUBBED" -> 2;
            case "VALIDATED" -> 3;
            case "COMMITTING", "KEY_DESTROYED" -> 4;
            case "CONFIRMED", "COMMITTED" -> 5;
            default -> -1;
        };
    }

    /** The short label for a transaction state, in the user's words. */
    static String state(State state) {
        if (state == null) return "—";
        return switch (state) {
            case STAGED -> "Checking";
            case VAULTED -> "Copy made";
            case SCRUBBED -> "Original gone";
            case VALIDATED -> "Checked";
            case COMMITTING -> "Making it final";
            case COMMITTED -> "Done";
            case ABORTED -> "Put back";
            case RESTORE_FAILED -> "Needs help";
            case UNRESOLVED -> "Unclear";
        };
    }
}
