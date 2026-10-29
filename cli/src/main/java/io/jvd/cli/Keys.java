package io.jvd.cli;

import io.jvd.evidence.Ed25519;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

/** Loads or creates the evidence, log, and witness key pairs under {@code work/keys}. */
record Keys(KeyPair evidence, KeyPair log, KeyPair witness) {
    static Keys loadOrCreate(Path work) throws Exception {
        Path dir = work.resolve("keys");
        return new Keys(
                pair(dir.resolve("evidence.key"), dir.resolve("evidence.key.pub")),
                pair(dir.resolve("log.key"), dir.resolve("log.key.pub")),
                pair(dir.resolve("witness.key"), dir.resolve("witness.key.pub")));
    }

    private static KeyPair pair(Path priv, Path pub) throws Exception {
        if (Files.exists(priv) && Files.exists(pub)) {
            return new KeyPair(Ed25519.decodePublic(Files.readString(pub)),
                    Ed25519.decodePrivate(Files.readString(priv)));
        }
        KeyPair kp = Ed25519.generate();
        Ed25519.writeKey(priv, kp.getPrivate());
        Ed25519.writeKey(pub, kp.getPublic());
        return kp;
    }
}
