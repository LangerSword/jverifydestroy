package io.jvd.ui;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the parts of the desktop app that can be exercised without a display.
 *
 * <p>The window itself is not constructed here: instantiating Swing components needs a
 * graphics environment, and this suite must run in CI where there is none. What is
 * checked instead is the behaviour that matters for a headless build — the stage
 * vocabulary stays jargon-free, the stage mapping matches the transaction, and the
 * service layer reports every stage of a real destruction.
 */
class StageWordsTest {

    @Test
    void theUserFacingStagesContainNoInternalTerms() {
        // The rule of the desktop app: the operator never has to think about the
        // machinery. This is the mechanical guard for that rule.
        List<String> forbidden = List.of("AES", "GCM", "DEK", "KEK", "wrapping key",
                "Merkle", "canary", "nonce", "ciphertext", "vault", "journal",
                "transaction", "NIST", "SP 800-88", "Ed25519", "checkpoint",
                "A0", "A1", "A2", "A3", "NOT_CHECKABLE", "COMMITTED", "ABORTED");
        for (StageTimeline.Stage stage : StageWords.DESTRUCTION_STAGES) {
            String text = (stage.title() + " " + stage.detail()).toLowerCase(java.util.Locale.ROOT);
            for (String term : forbidden) {
                assertFalse(text.contains(term.toLowerCase(java.util.Locale.ROOT)),
                        "user-facing stage text must not leak '" + term + "': " + stage);
            }
        }
    }

    @Test
    void everyStageHasATitleAndADetail() {
        for (StageTimeline.Stage stage : StageWords.DESTRUCTION_STAGES) {
            assertFalse(stage.title().isBlank(), "a stage needs a title: " + stage);
            assertFalse(stage.detail().isBlank(), "a stage needs a detail line: " + stage);
        }
    }

    @Test
    void theStageOrderMatchesTheOrderTheTransactionPerforms() {
        // The timeline is a promise about what will happen. It has to match the
        // transaction, or the app lies about its own progress.
        assertEquals(0, StageWords.stageIndex("STAGED"));
        assertEquals(1, StageWords.stageIndex("VAULTED"));
        assertEquals(2, StageWords.stageIndex("SCRUBBED"));
        assertEquals(3, StageWords.stageIndex("VALIDATED"));
        assertEquals(4, StageWords.stageIndex("COMMITTING"));
        assertEquals(5, StageWords.stageIndex("CONFIRMED"));
        assertEquals(5, StageWords.stageIndex("COMMITTED"));
    }

    @Test
    void unknownStagePointsMapToNothing() {
        // An internal point with no user-facing stage must not crash the lookup and
        // must not silently land on a wrong stage.
        assertEquals(-1, StageWords.stageIndex("SOMETHING_ELSE"));
        assertEquals(-1, StageWords.stageIndex(""));
    }

    @Test
    void theStateNamesArePlainLanguage() {
        assertEquals("Done", StageWords.state(io.jvd.txn.State.COMMITTED));
        assertEquals("Put back", StageWords.state(io.jvd.txn.State.ABORTED));
        assertEquals("Needs help", StageWords.state(io.jvd.txn.State.RESTORE_FAILED));
        assertEquals("Unclear", StageWords.state(io.jvd.txn.State.UNRESOLVED));
    }
}

/**
 * Tests for the service layer's stage reporting.
 *
 * <p>These run a real destruction against a real temporary file. Nothing is mocked,
 * because the thing worth testing is that the stages the app shows are the stages the
 * transaction really performs.
 */
class AppServiceStageTest {

    @Test
    void aDestructionReportsEveryStageInOrder(@TempDir Path tmp) throws Exception {
        Path target = tmp.resolve("victim.txt");
        Files.writeString(target, "sensitive content");
        Path work = tmp.resolve("work");

        List<Integer> seen = new CopyOnWriteArrayList<>();
        List<String> titles = new ArrayList<>();

        AppService.DestroyView view = AppService.destroy(target,
                io.jvd.txn.Method.CRYPTO_SHRED, work, null, "", 0, false,
                event -> {
                    seen.add(event.index());
                    titles.add(event.title());
                });

        assertEquals(io.jvd.txn.State.COMMITTED, io.jvd.txn.State.valueOf(view.state()));
        assertFalse(Files.exists(target), "the target must really be gone");

        // The user-facing stages are six; the transaction reports the points that map
        // onto them. Every user-facing stage must be reached, and in order.
        assertEquals(List.of(0, 1, 2, 3, 4, 5), seen, "stages must be reported in order");
        assertEquals("Destroying the original", titles.get(2));
        assertEquals("Making it final", titles.get(4));
    }

    @Test
    void aDestructionWithoutAStageCallbackStillWorks(@TempDir Path tmp) throws Exception {
        // The command line path passes no callback. That must not change the outcome.
        Path target = tmp.resolve("victim2.txt");
        Files.writeString(target, "sensitive content");
        Path work = tmp.resolve("work2");

        AppService.DestroyView view = AppService.destroy(target,
                io.jvd.txn.Method.CRYPTO_SHRED, work, null, "", 0, false);

        assertEquals("COMMITTED", view.state());
        assertFalse(Files.exists(target));
    }

    @Test
    void theReceiptIsProducedAndSigned(@TempDir Path tmp) throws Exception {
        Path target = tmp.resolve("victim3.txt");
        Files.writeString(target, "sensitive content");
        Path work = tmp.resolve("work3");

        AppService.DestroyView view = AppService.destroy(target,
                io.jvd.txn.Method.CRYPTO_SHRED, work, null, "", 0, false);

        assertTrue(view.evidenceJson().contains("\"signature\""),
                "the receipt must carry a signature");
        assertTrue(view.evidenceJson().contains("\"eventId\""));
    }
}
