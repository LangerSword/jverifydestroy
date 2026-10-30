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
 * Per-file AES-256-GCM crypto-shred.
 *
 * <p>JVD2 is chunked: a 4-byte magic, original size, chunk size, 8-byte nonce prefix, then
 * independently authenticated chunks. Each chunk has a unique nonce (prefix + counter) and an
 * AAD binding its index and final flag. A chunk can be verified and released without holding
 * the whole plaintext in the Java heap; this avoids the SunJCE GCM decrypt buffer limit.</p>
 *
 * <p>JVD1 is kept read-only for old containers. It uses a single GCM stream and therefore
 * buffers all plaintext until doFinal on SunJCE; do not create new JVD1 files.</p>
 *
 * <p>The key is a separate 32-byte file. Destroying the key makes the ciphertext unreadable;
 * that is the shred. Nothing here claims the ciphertext or old plaintext blocks are physically
 * gone.</p>
 */
public final class CryptoShredder {
    public static final byte[] MAGIC = {'J', 'V', 'D', '1'};
    public static final byte[] MAGIC_V2 = {'J', 'V', 'D', '2'};
    public static final int IV_LEN = 12;
    public static final int CHUNK = 1 << 20;

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
        long size = Files.size(src);
        byte[] prefix = new byte[8];
        new SecureRandom().nextBytes(prefix);
        Path parent = container.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        long total = 0;
        try (InputStream in = Files.newInputStream(src);
             DataOutputStream out = new DataOutputStream(Files.newOutputStream(container,
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                     StandardOpenOption.WRITE))) {
            out.write(MAGIC_V2);
            out.writeLong(size);
            out.writeInt(CHUNK);
            out.write(prefix);
            byte[] buf = new byte[CHUNK];
            long remaining = size;
            int index = 0;
            while (remaining > 0) {
                int n = in.read(buf, 0, (int) Math.min(CHUNK, remaining));
                if (n <= 0) throw new IOException("source ended early");
                boolean last = remaining - n == 0;
                byte[] ct = cryptChunk(buf, n, key, prefix, index, last, Cipher.ENCRYPT_MODE);
                out.write(ct);
                remaining -= n;
                index++;
                total += n;
            }
        }
        try (FileChannel ch = FileChannel.open(container, StandardOpenOption.WRITE)) {
            ch.force(true);
        }
        return total;
    }

    private static byte[] cryptChunk(byte[] input, int len, byte[] key, byte[] prefix,
                                     int index, boolean last, int mode) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = ByteBuffer.allocate(IV_LEN).put(prefix).putInt(index).array();
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            byte[] aad = ByteBuffer.allocate(9).put(MAGIC_V2).putInt(index).put((byte) (last ? 1 : 0)).array();
            cipher.updateAAD(aad);
            return cipher.doFinal(input, 0, len);
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("chunk " + index + " failed", e);
        }
    }

    public static void decrypt(Path container, Path dest, byte[] key) throws IOException {
        if (key.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        Path parent = dest.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        try (OutputStream out = Files.newOutputStream(dest, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            decryptTo(container, out, key);
        }
    }

    /** Decrypt without writing a plaintext file. */
    public static boolean canDecrypt(Path container, byte[] key) {
        try {
            decryptTo(container, OutputStream.nullOutputStream(), key);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static void decryptTo(Path container, OutputStream sink, byte[] key) throws IOException {
        try (InputStream in = Files.newInputStream(container)) {
            byte[] magic = in.readNBytes(4);
            if (Arrays.equals(magic, MAGIC_V2)) {
                decryptV2(in, sink, key);
            } else if (Arrays.equals(magic, MAGIC)) {
                decryptV1(in, sink, key);
            } else {
                throw new IOException("not a JVD container");
            }
        }
    }

    private static void decryptV2(InputStream in, OutputStream sink, byte[] key) throws IOException {
        DataInputStream data = new DataInputStream(in);
        long size = data.readLong();
        int chunkSize = data.readInt();
        if (size < 0 || chunkSize <= 0 || chunkSize > (64 << 20)) throw new IOException("bad JVD2 header");
        byte[] prefix = data.readNBytes(8);
        if (prefix.length != 8) throw new IOException("truncated JVD2 header");
        long remaining = size;
        int index = 0;
        while (remaining > 0) {
            int plainLen = (int) Math.min(chunkSize, remaining);
            byte[] ct = data.readNBytes(plainLen + 16);
            if (ct.length != plainLen + 16) throw new IOException("truncated chunk " + index);
            byte[] pt = cryptChunk(ct, ct.length, key, prefix, index, remaining - plainLen == 0, Cipher.DECRYPT_MODE);
            sink.write(pt);
            remaining -= plainLen;
            index++;
        }
    }

    private static void decryptV1(InputStream in, OutputStream sink, byte[] key) throws IOException {
        try {
            byte[] iv = in.readNBytes(IV_LEN);
            if (iv.length != IV_LEN) throw new IOException("truncated IV");
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
            throw new IOException("JVD1 decrypt failed (large JVD1 files may exhaust the heap)", e);
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
