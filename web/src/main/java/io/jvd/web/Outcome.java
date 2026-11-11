package io.jvd.web;

/**
 * The outcome of a verification run.
 *
 * <p>The distinction that matters to a visitor is between "the log is authentic" and "the log
 * is broken". A tampered log is a <em>successful</em> check that found a problem, so it maps to
 * {@link #TAMPERED} and not to an error. Only {@link #MALFORMED} means the service could not
 * even attempt the check, which is a client-side problem and not a statement about the evidence.
 * Keeping these apart stops a visitor from reading "invalid" as "the tool failed".</p>
 */
public enum Outcome {
    /** The log, the checkpoint, and (if supplied) the witness co-signature all check out. */
    AUTHENTIC,
    /** The log or the checkpoint does not match its signatures; something was changed. */
    TAMPERED,
    /** The submitted material could not be parsed; the check could not be performed. */
    MALFORMED;

    /**
     * Whether this outcome means the evidence is trustworthy.
     *
     * <p>Only {@link #AUTHENTIC} does. {@link #TAMPERED} is a definite answer ("no") and
     * {@link #MALFORMED} is "no answer"; collapsing them would lose information the visitor
     * needs, so this method exists rather than a bare {@code == AUTHENTIC} at call sites.</p>
     */
    public boolean authentic() {
        return this == AUTHENTIC;
    }
}
