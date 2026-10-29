package io.jvd.verify;

import java.util.List;

/** The outcome of one control-validated run. INVALID is never a pass. */
public record ValidationResult(String result, boolean dataAbsent,
                               ScanResult target, ScanResult positive, ScanResult negative,
                               List<String> checks, String reason, long elapsedMillis) {
    public boolean passed() { return "PASS".equals(result); }
    public boolean invalid() { return "INVALID".equals(result); }
}
