package io.jvd.txn;

import io.jvd.evidence.AssuranceLevel;

public enum Method {
    OVERWRITE("CLEAR", "OVERWRITE", AssuranceLevel.A1),
    CRYPTO_SHRED("PURGE", "CRYPTO_ERASE", AssuranceLevel.A2);

    private final String nistMethod;
    private final String technique;
    private final AssuranceLevel ceiling;

    Method(String nistMethod, String technique, AssuranceLevel ceiling) {
        this.nistMethod = nistMethod;
        this.technique = technique;
        this.ceiling = ceiling;
    }

    public String nistMethod() { return nistMethod; }
    public String technique() { return technique; }
    public AssuranceLevel ceiling() { return ceiling; }
}
