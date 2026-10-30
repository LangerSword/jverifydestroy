package io.jvd.presenter;

import java.util.List;

/**
 * Maps a structured Result to plain user copy. Default sentences never contain engine jargon;
 * technical facts live in details (or --details).
 */
public final class Presenter {
    public static final List<String> BANNED = List.of(
            "committed", "aborted", "not_checkable", "invalid", "canary", "assurance",
            "journal", "vault", "dek", "transaction", "merkle", "ed25519", "hash");

    private Presenter() {}

    public static UserMessage present(Result result) {
        if (result == null || result.outcome() == null) {
            return new UserMessage(Tone.RED,
                    "Nothing was changed. Details explain what went wrong.",
                    "No result was produced.");
        }
        String sentence = switch (result.outcome()) {
            case SUCCESS -> "The file is gone, and the receipt is saved.";
            case SUCCESS_WITH_LIMITS -> "The file is gone. We couldn't check the physical disk, so this is a software-level result.";
            case RESTORE_FAILED -> "We couldn't put the file back. Keep the recovery folder and try again.";
            case INVALID -> "The safety check didn't run correctly, so we can't confirm the file is gone.";
            case UNRESOLVED -> "The file might not be deleted. Do not rely on it.";
            case ERROR -> "Nothing was changed. Details explain what went wrong.";
            case CANCELLED -> "Nothing was changed.";
        };
        Tone tone = switch (result.outcome()) {
            case SUCCESS -> Tone.GREEN;
            case SUCCESS_WITH_LIMITS, CANCELLED, UNRESOLVED -> Tone.AMBER;
            case RESTORE_FAILED, INVALID, ERROR -> Tone.RED;
        };
        for (String banned : BANNED) {
            if (sentence.toLowerCase(java.util.Locale.ROOT).contains(banned)) {
                throw new IllegalStateException("user sentence contains internal term: " + banned);
            }
        }
        return new UserMessage(tone, sentence, details(result));
    }

    private static String details(Result r) {
        StringBuilder sb = new StringBuilder();
        if (r.details() != null && !r.details().isBlank()) sb.append(r.details().trim()).append('\n');
        if (!r.facts().isEmpty()) {
            sb.append("Technical facts:\n");
            r.facts().forEach((k, v) -> sb.append("  ").append(k).append(": ").append(v).append('\n'));
        }
        if (!r.limits().isEmpty()) {
            sb.append("Limits:\n");
            for (String l : r.limits()) sb.append("  ").append(l).append('\n');
        }
        return sb.isEmpty() ? "No extra details." : sb.toString().trim();
    }
}
