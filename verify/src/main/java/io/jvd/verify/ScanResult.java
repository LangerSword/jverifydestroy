package io.jvd.verify;

import java.util.Objects;

/** Result of one scan. NOT_CHECKABLE is not a pass; it is a refusal to guess. */
public record ScanResult(Verdict verdict, int matches, long regions,
                         long bytesRead, long bytesMapped, int readErrors,
                         String reason, long elapsedMillis) {
    public ScanResult {
        Objects.requireNonNull(verdict, "verdict");
    }

    /** Backward-compatible factory: mapped and read are the same, no errors. */
    public static ScanResult found(int matches, long regions, long bytes, long ms) {
        return found(matches, regions, bytes, bytes, 0, ms);
    }

    public static ScanResult found(int matches, long regions, long mapped, long read, int errors, long ms) {
        return new ScanResult(Verdict.FOUND, matches, regions, read, mapped, errors, null, ms);
    }

    public static ScanResult notFound(long regions, long bytes, long ms) {
        return notFound(regions, bytes, bytes, 0, ms);
    }

    public static ScanResult notFound(long regions, long mapped, long read, int errors, long ms) {
        String reason = errors == 0 ? null : errors + " unreadable page(s) skipped";
        return new ScanResult(Verdict.NOT_FOUND, 0, regions, read, mapped, errors, reason, ms);
    }

    public static ScanResult notCheckable(String reason, long regions, long bytes, long ms) {
        return notCheckable(reason, regions, bytes, bytes, 0, ms);
    }

    public static ScanResult notCheckable(String reason, long regions, long mapped, long read,
                                          int errors, long ms) {
        return new ScanResult(Verdict.NOT_CHECKABLE, 0, regions, read, mapped, errors, reason, ms);
    }

    public boolean found() { return verdict == Verdict.FOUND; }
    public boolean notFound() { return verdict == Verdict.NOT_FOUND; }
    public boolean checkable() { return verdict != Verdict.NOT_CHECKABLE; }

    /** Compatibility for callers that only need the read byte count. */
    public long bytes() { return bytesRead; }

    public double coverage() {
        return bytesMapped == 0 ? 0.0 : (double) bytesRead / bytesMapped;
    }
}
