package io.jvd.txn;

import java.util.List;

/** File-level validation. NOT_CHECKABLE is a refusal to claim raw-media erasure. */
public record FileValidation(String result, boolean dataAbsent, List<String> checks, String reason) {
    public boolean passed() { return "PASS".equals(result); }
    public boolean failed() { return "FAIL".equals(result); }
}
