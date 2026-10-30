package io.jvd.txn;

import io.jvd.presenter.Outcome;
import io.jvd.presenter.Result;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Maps a transaction outcome to the structured result the presenter consumes. */
public final class ResultMapper {
    private ResultMapper() {}

    public static Result toResult(DestructionTransaction.Outcome out) {
        if (out == null) {
            return Result.of(Outcome.ERROR, Map.of(), List.of("No result was produced."),
                    "No transaction result.");
        }
        String state = out.state() == null ? "UNKNOWN" : out.state().name();
        String validation = out.record() == null ? "NOT_RUN" : out.record().validation.result;
        String assurance = out.record() == null ? "A0" : out.record().assurance.name();
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("state", state);
        facts.put("validation", validation);
        facts.put("assurance", assurance);
        if (out.record() != null) {
            facts.put("eventId", out.record().eventId);
            facts.put("method", String.valueOf(out.record().method));
        }
        List<String> limits = new ArrayList<>();
        if ("NOT_CHECKABLE".equals(validation)) limits.add("Physical media was not verified.");
        if ("A1".equals(assurance)) limits.add("This was an overwrite, which is weak on flash storage.");
        if ("A2".equals(assurance)) limits.add("This is a software-level result, not physical erasure.");

        Outcome outcome = switch (out.state()) {
            case COMMITTED -> "PASS".equals(validation) ? Outcome.SUCCESS
                    : "NOT_CHECKABLE".equals(validation) ? Outcome.SUCCESS_WITH_LIMITS
                    : Outcome.UNRESOLVED;
            case RESTORE_FAILED -> Outcome.RESTORE_FAILED;
            case UNRESOLVED -> Outcome.UNRESOLVED;
            case ABORTED -> out.restored() ? Outcome.CANCELLED : Outcome.ERROR;
            default -> Outcome.ERROR;
        };
        String details = out.detail();
        if (out.validation() != null && out.validation().checks() != null) {
            details = details + "\nChecks: " + out.validation().checks();
        }
        return Result.of(outcome, facts, limits, details);
    }
}
