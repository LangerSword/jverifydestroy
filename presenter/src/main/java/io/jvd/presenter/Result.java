package io.jvd.presenter;

import java.util.List;
import java.util.Map;

/** Structured engine result. Facts and limits are technical; Presenter owns the user copy. */
public record Result(Outcome outcome, Map<String, String> facts, List<String> limits, String details) {
    public Result {
        facts = facts == null ? Map.of() : Map.copyOf(facts);
        limits = limits == null ? List.of() : List.copyOf(limits);
    }

    public static Result of(Outcome outcome, Map<String, String> facts, List<String> limits, String details) {
        return new Result(outcome, facts, limits, details);
    }
}
