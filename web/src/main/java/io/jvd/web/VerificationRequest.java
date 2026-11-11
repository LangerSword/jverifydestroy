package io.jvd.web;

/**
 * The material to verify, as plain data.
 *
 * <p>Everything the service needs arrives as content, never as a filesystem path. That is a
 * deliberate security decision, not a convenience: a service that accepts a path from the
 * internet is a service that can be pointed at {@code /etc/shadow}. Here the caller uploads
 * the log and the checkpoint as text and hands over the public keys to check them against, so
 * there is no request field that can name a file on this machine.</p>
 *
 * <p>Keys are X.509-encoded Ed25519 public keys, base64 encoded. The project's own key files
 * carry an {@code ed25519:} prefix, so both forms are accepted.</p>
 *
 * @param logContent       the log as JSON Lines, one {@code {seq, leaf, record}} object per line
 * @param checkpointContent the checkpoint as a single JSON object
 * @param logPublicKey     base64 X.509 Ed25519 public key that signed the checkpoint
 * @param witnessPublicKey base64 X.509 Ed25519 public key of the co-signer, or {@code null}
 * @param evidencePublicKey base64 X.509 Ed25519 public key that signed the records, or {@code null}
 */
public record VerificationRequest(String logContent,
                                   String checkpointContent,
                                   String logPublicKey,
                                   String witnessPublicKey,
                                   String evidencePublicKey) {

    /**
     * A request with no optional keys.
     *
     * <p>Most callers have a log key and a checkpoint, and no witness. Keeping this constructor
     * short means the common case stays readable at the call site.</p>
     */
    public VerificationRequest(String logContent, String checkpointContent, String logPublicKey) {
        this(logContent, checkpointContent, logPublicKey, null, null);
    }

    /** Whether the witness key was supplied, which decides whether the co-signature is checked. */
    public boolean hasWitnessKey() {
        return witnessPublicKey != null && !witnessPublicKey.isBlank();
    }

    /** Whether the evidence key was supplied, which decides whether record signatures are checked. */
    public boolean hasEvidenceKey() {
        return evidencePublicKey != null && !evidencePublicKey.isBlank();
    }
}
