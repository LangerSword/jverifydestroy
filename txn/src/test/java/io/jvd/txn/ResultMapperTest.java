package io.jvd.txn;

import io.jvd.evidence.EvidenceRecord;
import io.jvd.presenter.Outcome;
import io.jvd.presenter.Presenter;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ResultMapperTest {
    private static DestructionTransaction.Outcome outcome(State state, String validation, boolean restored) {
        EvidenceRecord r = EvidenceRecord.create("x", "CLEAR", "OVERWRITE");
        r.validation.result = validation;
        return new DestructionTransaction.Outcome("id", state,
                new FileValidation(validation, false, List.of(), ""), r, restored, "detail");
    }

    @Test void mapsTheUserFacingOutcomes() {
        assertEquals(Outcome.SUCCESS, ResultMapper.toResult(outcome(State.COMMITTED, "PASS", false)).outcome());
        assertEquals(Outcome.SUCCESS_WITH_LIMITS,
                ResultMapper.toResult(outcome(State.COMMITTED, "NOT_CHECKABLE", false)).outcome());
        assertEquals(Outcome.RESTORE_FAILED,
                ResultMapper.toResult(outcome(State.RESTORE_FAILED, "RESTORE_FAILED", false)).outcome());
        assertEquals(Outcome.UNRESOLVED,
                ResultMapper.toResult(outcome(State.UNRESOLVED, "FAIL", false)).outcome());
        assertEquals(Outcome.CANCELLED,
                ResultMapper.toResult(outcome(State.ABORTED, "FAIL", true)).outcome());
        assertEquals(Outcome.ERROR,
                ResultMapper.toResult(outcome(State.ABORTED, "NOT_CHECKABLE", false)).outcome());
    }

    @Test void presenterCopyHasNoInternalTerms() {
        for (State s : State.values()) {
            String validation = s == State.COMMITTED ? "NOT_CHECKABLE" : "FAIL";
            var m = Presenter.present(ResultMapper.toResult(outcome(s, validation, s == State.ABORTED)));
            for (String banned : Presenter.BANNED) {
                assertFalse(m.sentence().toLowerCase().contains(banned), s + " -> " + m.sentence());
            }
        }
    }
}
