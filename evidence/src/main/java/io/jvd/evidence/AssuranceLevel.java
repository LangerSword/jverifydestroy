package io.jvd.evidence;

/**
 * Assurance levels are logical-level only. None of them asserts physical media sanitization.
 * A3 adds witness-cosigned evidence and an independent process re-validation, not hardware
 * attestation.
 */
public enum AssuranceLevel {
    A0("deletion only; no overwrite, no validation"),
    A1("best-effort overwrite; logical checks only; physical media NOT verified"),
    A2("crypto-shred committed; key destroyed and decrypt fails; required checks pass; logical level only (canary controls apply only to memory subjects)"),
    A3("A2 plus witness-cosigned checkpoint and independent process re-validation; logical level only");

    private final String description;

    AssuranceLevel(String description) { this.description = description; }

    public String description() { return description; }

    public boolean physicalMediaVerified() { return false; }
}
