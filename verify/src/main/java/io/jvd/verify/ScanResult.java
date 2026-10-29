package io.jvd.verify;

import java.util.Objects;

/** Result of one scan. NOT_CHECKABLE is not a pass; it is a refusal to guess. */
public record ScanResult(Verdict verdict, int matches, long regions, long bytes,
                         String reason, long elapsedMillis) {
    public ScanResult {
        Objects.requireNonNull(verdict, "verdict");
    }

    public static ScanResult found(int matches, long regions, long bytes, long ms) {
        return new ScanResult(Verdict.FOUND, matches, regions, bytes, null, ms);
    }

    public static ScanResult notFound(long regions, long bytes, long ms) {
        return new ScanResult(Verdict.NOT_FOUND, 0, regions, bytes, null, ms);
    }

    public static ScanResult notCheckable(String reason, long regions, long bytes, long ms) {
        return new ScanResult(Verdict.NOT_CHECKABLE, 0, regions, bytes, reason, ms);
    }

    public boolean found() { return verdict == Verdict.FOUND; }
    public boolean notFound() { return verdict == Verdict.NOT_FOUND; }
    public boolean checkable() { return verdict != Verdict.NOT_CHECKABLE; }
}
