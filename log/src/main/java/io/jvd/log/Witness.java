package io.jvd.log;

import io.jvd.evidence.Ed25519;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;

/**
 * A local independent witness. It is a second key on the same machine, not a remote party;
 * the README states that limitation. Its value is that a log operator who rewrites history
 * must also forge this signature, and a verifier that retained the old checkpoint can tell.
 */
public final class Witness {
    private final String name;
    private final PrivateKey key;
    private final PublicKey publicKey;

    public Witness(String name, PrivateKey key, PublicKey publicKey) {
        this.name = name;
        this.key = key;
        this.publicKey = publicKey;
    }

    public static Witness load(String name, Path privateKeyFile) throws Exception {
        String text = Files.readString(privateKeyFile);
        PrivateKey priv = Ed25519.decodePrivate(text);
        // Derive the public key from the private key is not possible with the JDK Ed25519 API,
        // so a sidecar .pub file is required.
        Path pubFile = privateKeyFile.resolveSibling(privateKeyFile.getFileName() + ".pub");
        PublicKey pub = Ed25519.decodePublic(Files.readString(pubFile));
        return new Witness(name, priv, pub);
    }

    public static Witness generate(String name, Path dir) throws Exception {
        KeyPair kp = Ed25519.generate();
        Files.createDirectories(dir);
        Path priv = dir.resolve(name + ".key");
        Path pub = dir.resolve(name + ".key.pub");
        Ed25519.writeKey(priv, kp.getPrivate());
        Ed25519.writeKey(pub, kp.getPublic());
        return new Witness(name, kp.getPrivate(), kp.getPublic());
    }

    public String name() { return name; }

    public PublicKey publicKey() { return publicKey; }

    /** A witness must never sign a checkpoint it cannot tie to a log. */
    public Checkpoint cosign(Checkpoint c) {
        throw new IllegalArgumentException("cosign requires a consistency-checked log");
    }

    /** Verify the checkpoint is exactly the current log head before cosigning it. */
    public Checkpoint cosign(Checkpoint c, LogStore log) {
        if (c == null || log == null) throw new IllegalArgumentException("checkpoint and log are required");
        if (c.origin == null || !c.origin.equals(log.origin())) {
            throw new IllegalArgumentException("checkpoint origin does not match the log");
        }
        if (c.size != log.size()) {
            throw new IllegalArgumentException("checkpoint size does not match the log");
        }
        if (!MessageDigest.isEqual(c.root(), log.root())) {
            throw new IllegalArgumentException("checkpoint root does not match the log");
        }
        c.cosign(name, key);
        return c;
    }
}
