package io.jvd.txn;

import java.nio.file.Path;
import java.util.Arrays;

/** Configuration for one file-destruction transaction. */
public record TxnConfig(Path target, Method method, Path workDir, Path rawImage,
                        byte[] maskedCanary, long graceMillis, boolean allowLogicalOnly) {
    public TxnConfig {
        target = target.toAbsolutePath().normalize();
        workDir = workDir.toAbsolutePath().normalize();
        if (rawImage != null) rawImage = rawImage.toAbsolutePath().normalize();
    }

    public static TxnConfig of(Path target, Method method, Path workDir) {
        return new TxnConfig(target, method, workDir, null, null, 0, true);
    }

    public TxnConfig withRawImage(Path image, byte[] masked) {
        return new TxnConfig(target, method, workDir, image, masked, graceMillis, allowLogicalOnly);
    }

    public TxnConfig withGrace(long millis) {
        return new TxnConfig(target, method, workDir, rawImage, maskedCanary, millis, allowLogicalOnly);
    }

    public TxnConfig requireCheckable() {
        return new TxnConfig(target, method, workDir, rawImage, maskedCanary, graceMillis, false);
    }

    public void wipe() {
        if (maskedCanary != null) Arrays.fill(maskedCanary, (byte) 0);
    }
}
