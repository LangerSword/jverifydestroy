package io.jvd.txn;

public enum State {
    STAGED, VAULTED, SCRUBBED, VALIDATED, COMMITTED, ABORTED
}
