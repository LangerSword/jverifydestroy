package io.jvd.file;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Per-file AES-256-GCM crypto-shred. The ciphertext container is {@code JVD1 || IV || ct||tag}.
 * The key is a separate 32-byte file. Destroying the key makes the ciphertext unreadable; that
 * is the shred. Nothing here claims the ciphertext or the old plaintext blocks are physically
 * gone.
 */
public final class CryptoShredder {
    public static final byte[] MAGIC = {'J', 'V', 'D', '1'};
    public static final int IV_LEN = 12;

    private CryptoShredder() {}

    public static byte[] newKey() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        return k;
    }

    public static long encrypt(Path src, Path container, Path keyFile) throws IOException {
        byte[] key = newKey();
        FileKeyVault.write(keyFile, key);
        try {
            return encrypt(src, container, key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    public static long encrypt(Path src, Path container, byte[] key) throws IOException {
        if (key.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        byte[] iv = new byte[IV_LEN];
        new SecureRandom().nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(MAGIC);
            Path parent = container.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            long total = 0;
            try (InputStream in = Files.newInputStream(src);
                 OutputStream out = Files.newOutputStream(container,
                         StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                out.write(MAGIC);
                out.write(iv);
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) {
                    byte[] c = cipher.update(buf, 0, n);
                    if (c != null) out.write(c);
                    total += n;
                }
                out.write(cipher.doFinal());
            }
            try (FileChannel ch = FileChannel.open(container, StandardOpenOption.WRITE)) {
                ch.force(true);
            }
            return total;
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("encrypt failed", e);
        }
    }

    public static void decrypt(Path container, Path dest, byte[] key) throws IOException {
        if (key.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        try (InputStream in = Files.newInputStream(container)) {
            byte[] magic = in.readNBytes(4);
            if (!Arrays.equals(magic, MAGIC)) throw new IOException("not a JVD1 container");
            byte[] iv = in.readNBytes(IV_LEN);
            if (iv.length != IV_LEN) throw new IOException("truncated IV");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(MAGIC);
            Path parent = dest.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            try (OutputStream out = Files.newOutputStream(dest,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) {
                    byte[] p = cipher.update(buf, 0, n);
                    if (p != null) out.write(p);
                }
                out.write(cipher.doFinal());
            }
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("decrypt failed (key destroyed, wrong key, or tampered ciphertext)", e);
        }
    }

    /** Decrypt without writing a plaintext file. */
    public static boolean canDecrypt(Path container, byte[] key) {
        try {
            decrypt(container, OutputStream.nullOutputStream(), key);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static void decrypt(Path container, OutputStream sink, byte[] key) throws IOException {
        try (InputStream in = Files.newInputStream(container)) {
            byte[] magic = in.readNBytes(4);
            if (!Arrays.equals(magic, MAGIC)) throw new IOException("not a JVD1 container");
            byte[] iv = in.readNBytes(IV_LEN);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(MAGIC);
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                byte[] p = cipher.update(buf, 0, n);
                if (p != null) sink.write(p);
            }
            sink.write(cipher.doFinal());
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("decrypt failed", e);
        }
    }

    public static void destroyKey(Path keyFile) throws IOException {
        FileKeyVault.destroy(keyFile);
    }

    /** Destroy the key file and wipe the in-memory copy. File deletion alone is not key destruction. */
    public static void destroyKey(Path keyFile, byte[] key) throws IOException {
        destroyKey(keyFile);
        if (key != null) Arrays.fill(key, (byte) 0);
    }
}
