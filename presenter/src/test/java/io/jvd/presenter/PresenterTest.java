package io.jvd.presenter;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PresenterTest {
    @Test void everyOutcomeHasAPlainSentenceAndATone() {
        for (Outcome o : Outcome.values()) {
            UserMessage m = Presenter.present(Result.of(o, Map.of("state", o.name()),
                    List.of("physical media not verified"), "technical detail"));
            assertNotNull(m.tone());
            assertFalse(m.sentence().isBlank());
            assertFalse(m.details().isBlank());
            for (String banned : Presenter.BANNED) {
                assertFalse(m.sentence().toLowerCase(java.util.Locale.ROOT).contains(banned),
                        o + " sentence contains " + banned + ": " + m.sentence());
            }
        }
    }

    @Test void tonesMatchTheMappingTable() {
        assertEquals(Tone.GREEN, Presenter.present(Result.of(Outcome.SUCCESS, Map.of(), List.of(), "")).tone());
        assertEquals(Tone.AMBER, Presenter.present(Result.of(Outcome.SUCCESS_WITH_LIMITS, Map.of(), List.of(), "")).tone());
        assertEquals(Tone.AMBER, Presenter.present(Result.of(Outcome.CANCELLED, Map.of(), List.of(), "")).tone());
        assertEquals(Tone.RED, Presenter.present(Result.of(Outcome.RESTORE_FAILED, Map.of(), List.of(), "")).tone());
        assertEquals(Tone.RED, Presenter.present(Result.of(Outcome.INVALID, Map.of(), List.of(), "")).tone());
        assertEquals(Tone.AMBER, Presenter.present(Result.of(Outcome.UNRESOLVED, Map.of(), List.of(), "")).tone());
        assertEquals(Tone.RED, Presenter.present(Result.of(Outcome.ERROR, Map.of(), List.of(), "")).tone());
    }

    @Test void restoreFailedKeepsTheRecoveryInstruction() {
        UserMessage m = Presenter.present(Result.of(Outcome.RESTORE_FAILED, Map.of(), List.of(), ""));
        assertTrue(m.sentence().contains("recovery folder"));
        assertFalse(m.sentence().toLowerCase().contains("deleted"));
    }

    @Test void nullResultIsRedAndActionable() {
        assertEquals(Tone.RED, Presenter.present(null).tone());
    }
}
