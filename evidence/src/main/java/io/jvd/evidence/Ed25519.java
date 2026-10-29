package io.jvd.evidence;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Ed25519 signatures and key files. Key files are text: {@code ed25519:<base64>}, mode 0600. */
public final class Ed25519 {
    private Ed25519() {}

    public static KeyPair generate() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    public static byte[] sign(byte[] data, PrivateKey key) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(key);
            s.update(data);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("sign failed", e);
        }
    }

    public static boolean verify(byte[] data, byte[] sig, PublicKey key) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(data);
            return s.verify(sig);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static String encode(Key key) {
        return "ed25519:" + Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey decodePublic(String text) {
        try {
            String b64 = strip(text);
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("bad Ed25519 public key", e);
        }
    }

    public static PrivateKey decodePrivate(String text) {
        try {
            String b64 = strip(text);
            return KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("bad Ed25519 private key", e);
        }
    }

    private static String strip(String text) {
        String t = text.trim();
        if (!t.startsWith("ed25519:")) throw new IllegalArgumentException("not an ed25519 key file");
        return t.substring("ed25519:".length());
    }

    public static void writeKey(Path path, Key key) throws java.io.IOException {
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.writeString(path, encode(key) + "\n", StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        try {
            Files.setPosixFilePermissions(path, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX file system: permissions are best effort.
        }
    }

    public static String sha256Base64(byte[] data) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
