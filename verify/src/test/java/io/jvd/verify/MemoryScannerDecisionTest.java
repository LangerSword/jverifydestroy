package io.jvd.verify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the scanner's control logic, without a child process.
 *
 * <p>The scanner is the part of the tool that says a secret is gone. A scanner that can
 * miss a canary that is really there does not report a clean result — it reports a
 * false one, because the run is discarded as INVALID and the residue is never noticed.
 * These tests pin the decisions that make that impossible.
 */
class MemoryScannerDecisionTest {

    @Test
    void aRunWithAFailedPositiveControlIsInvalidNotClean() {
        // The positive control is a canary that IS in memory. If it is not found, the
        // scanner cannot see what is there, so the run must not be reported as a clean
        // result. It must be INVALID, which is the difference between "we checked and
        // found nothing" and "we could not check".
        ScanResult target = ScanResult.notFound(10, 1000, 5);
        ScanResult positive = ScanResult.notFound(10, 1000, 5);
        ScanResult negative = ScanResult.notFound(10, 1000, 5);

        ValidationResult r = CanaryVerifier.evaluate(target, positive, negative, true, 1);

        assertEquals("INVALID", r.result());
        assertFalse(r.passed(), "a run whose positive control was not found has not passed");
    }

    @Test
    void aRunWithAFailedNegativeControlIsInvalid() {
        ScanResult target = ScanResult.notFound(10, 1000, 5);
        ScanResult positive = ScanResult.found(1, 10, 1000, 5);
        // The negative control is a value that was never written. Finding it means the
        // scanner is matching something it should not.
        ScanResult negative = ScanResult.found(1, 10, 1000, 5);

        ValidationResult r = CanaryVerifier.evaluate(target, positive, negative, true, 1);

        assertEquals("INVALID", r.result());
    }

    @Test
    void aCleanRunWithValidControlsPasses() {
        ScanResult target = ScanResult.notFound(10, 1000, 5);
        ScanResult positive = ScanResult.found(1, 10, 1000, 5);
        ScanResult negative = ScanResult.notFound(10, 1000, 5);

        ValidationResult r = CanaryVerifier.evaluate(target, positive, negative, true, 1);

        assertEquals("PASS", r.result());
        assertTrue(r.passed());
    }

    @Test
    void aFoundTargetIsAFailureNotAnInvalid() {
        // The residue was found: that is a real FAIL. It must not be reported as
        // INVALID, which would mean "we could not tell" instead of "it is still there".
        ScanResult target = ScanResult.found(1, 10, 1000, 5);
        ScanResult positive = ScanResult.found(1, 10, 1000, 5);
        ScanResult negative = ScanResult.notFound(10, 1000, 5);

        ValidationResult r = CanaryVerifier.evaluate(target, positive, negative, true, 1);

        assertEquals("FAIL", r.result());
        assertFalse(r.passed());
    }

    @Test
    void anUnfrozenSnapshotIsNotCheckable() {
        // Without SIGSTOP the victim can move the canary between the region list and
        // the read, so a NOT_FOUND means nothing. The run must be NOT_CHECKABLE.
        ScanResult target = ScanResult.notFound(10, 1000, 5);
        ScanResult positive = ScanResult.found(1, 10, 1000, 5);
        ScanResult negative = ScanResult.notFound(10, 1000, 5);

        ValidationResult r = CanaryVerifier.evaluate(target, positive, negative, false, 1);

        assertEquals("NOT_CHECKABLE", r.result());
    }

    @Test
    void aNotCheckableTargetIsNotCheckable() {
        ScanResult target = ScanResult.notCheckable("could not read", 10, 0, 0, 0, 1);
        ScanResult positive = ScanResult.found(1, 10, 1000, 5);
        ScanResult negative = ScanResult.notFound(10, 1000, 5);

        ValidationResult r = CanaryVerifier.evaluate(target, positive, negative, true, 1);

        assertEquals("NOT_CHECKABLE", r.result());
    }

    @Test
    void theChecksAlwaysNameBothControls() {
        // A reader of the result has to be able to see which control failed, without
        // reading the source. The check list is part of the evidence.
        ScanResult target = ScanResult.notFound(10, 1000, 5);
        ScanResult positive = ScanResult.notFound(10, 1000, 5);
        ScanResult negative = ScanResult.notFound(10, 1000, 5);

        ValidationResult r = CanaryVerifier.evaluate(target, positive, negative, true, 1);

        assertTrue(r.checks().stream().anyMatch(c -> c.startsWith("positive control:")), r.checks().toString());
        assertTrue(r.checks().stream().anyMatch(c -> c.startsWith("negative control:")), r.checks().toString());
        assertTrue(r.checks().stream().anyMatch(c -> c.startsWith("snapshot:")), r.checks().toString());
    }
}
