package io.jvd.verify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CanaryVerifierTest {
    @Test void untouchedTargetIsFoundAndRunFails() {
        ValidationResult r = CanaryVerifier.validate(Mode.KEEP, "G1");
        assertEquals("FAIL", r.result(), r.checks().toString());
        assertTrue(r.target().found());
        assertTrue(r.positive().found());
        assertFalse(r.negative().found());
    }

    @Test void wipedTargetPasses() {
        ValidationResult r = CanaryVerifier.validate(Mode.WIPE, "G1");
        assertEquals("PASS", r.result(), r.checks().toString());
        assertTrue(r.dataAbsent());
    }

    @Test void gcAfterWipeStillPassesOnG1() {
        ValidationResult r = CanaryVerifier.validate(Mode.WIPEGC, "G1");
        assertEquals("PASS", r.result(), r.checks().toString());
    }

    @Test void serialMoveLeavesAStaleCopy() {
        // H2: Serial is a copying collector. After a move, wiping the live array can leave the
        // canary in from-space. If this ever stops reproducing, the test is the place to notice.
        ValidationResult r = CanaryVerifier.validate(Mode.MOVE, "Serial");
        assertEquals("FAIL", r.result(), r.checks().toString());
        assertTrue(r.target().found());
    }

    @Test void hotLoopWipePasses() {
        ValidationResult r = CanaryVerifier.validate(Mode.HOT, "G1");
        assertEquals("PASS", r.result(), r.checks().toString());
    }

    @Test void controlLogicRejectsUncheckableAndInvalidRuns() {
        ScanResult found = ScanResult.found(1, 1, 1, 0);
        ScanResult absent = ScanResult.notFound(1, 1, 0);
        ScanResult nc = ScanResult.notCheckable("no permission", 0, 0, 0);

        assertEquals("INVALID", CanaryVerifier.evaluate(absent, absent, absent, 0).result());
        assertEquals("INVALID", CanaryVerifier.evaluate(absent, found, found, 0).result());
        assertEquals("NOT_CHECKABLE", CanaryVerifier.evaluate(nc, found, absent, 0).result());
        assertEquals("FAIL", CanaryVerifier.evaluate(found, found, absent, 0).result());
        assertEquals("PASS", CanaryVerifier.evaluate(absent, found, absent, 0).result());
    }
}
