package io.jvd.verify;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Runs a destruction mode in a child JVM and scans that child. Every run carries:
 * <ul>
 *   <li>a positive control (an unwiped canary that MUST be found);</li>
 *   <li>a negative control (a value that was never written and MUST NOT be found).</li>
 * </ul>
 * If either control fails, the run is INVALID and is not counted as a pass.
 */
public final class CanaryVerifier {
    private CanaryVerifier() {}

    public static ValidationResult validate(Mode mode, String gc) {
        long t0 = System.nanoTime();
        byte[] seed = Canary.newSeed();
        byte[] targetRaw = Canary.derive(seed, "target");
        byte[] controlRaw = Canary.derive(seed, "control");
        byte[] negativeRaw = Canary.derive(seed, "negative");
        byte[] targetMasked = Canary.mask(targetRaw);
        byte[] controlMasked = Canary.mask(controlRaw);
        byte[] negativeMasked = Canary.mask(negativeRaw);
        Arrays.fill(targetRaw, (byte) 0);
        Arrays.fill(controlRaw, (byte) 0);
        Arrays.fill(negativeRaw, (byte) 0);

        ScanResult target;
        ScanResult positive;
        ScanResult negative;
        try (VictimProcess victim = VictimProcess.start(seed, mode.name(), gc)) {
            target = MemoryScanner.scan(victim.pid(), targetMasked);
            positive = MemoryScanner.scan(victim.pid(), controlMasked);
            negative = MemoryScanner.scan(victim.pid(), negativeMasked);
        } catch (Exception e) {
            ScanResult nc = ScanResult.notCheckable("victim failed: " + e.getMessage(), 0, 0, ms(t0));
            return new ValidationResult("NOT_CHECKABLE", false, nc, nc, nc,
                    List.of("victim did not start"), e.getMessage(), ms(t0));
        } finally {
            Arrays.fill(targetMasked, (byte) 0);
            Arrays.fill(controlMasked, (byte) 0);
            Arrays.fill(negativeMasked, (byte) 0);
            Arrays.fill(seed, (byte) 0);
        }

        return evaluate(target, positive, negative, ms(t0));
    }

    /** Pure control logic, separated so it can be tested without a child process. */
    public static ValidationResult evaluate(ScanResult target, ScanResult positive, ScanResult negative, long ms) {
        List<String> checks = new ArrayList<>();
        checks.add("positive control: " + positive.verdict() + " (expected FOUND)");
        checks.add("negative control: " + negative.verdict() + " (expected NOT_FOUND)");
        checks.add("target: " + target.verdict() + " (expected NOT_FOUND)");

        if (!positive.found()) {
            return new ValidationResult("INVALID", false, target, positive, negative, checks,
                    "positive control was not found; the scanner cannot see a known-present canary", ms);
        }
        if (negative.found()) {
            return new ValidationResult("INVALID", false, target, positive, negative, checks,
                    "negative control was found; the scanner is matching something it should not", ms);
        }
        if (target.verdict() == Verdict.NOT_CHECKABLE) {
            return new ValidationResult("NOT_CHECKABLE", false, target, positive, negative, checks,
                    target.reason(), ms);
        }
        if (target.found()) {
            return new ValidationResult("FAIL", false, target, positive, negative, checks,
                    "target canary is still present in process memory", ms);
        }
        return new ValidationResult("PASS", true, target, positive, negative, checks, null, ms);
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }
}
