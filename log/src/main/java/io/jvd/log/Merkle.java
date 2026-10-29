package io.jvd.log;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 9162 / RFC 6962 Merkle tree hashing and proofs.
 *
 * <p>Leaf hash = SHA-256(0x00 || data); node hash = SHA-256(0x01 || left || right);
 * an empty tree is SHA-256(""). Proofs are lists of sibling hashes, bottom-up.</p>
 */
public final class Merkle {
    private Merkle() {}

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] leafHash(byte[] data) {
        return sha256(concat(new byte[]{0x00}, data));
    }

    public static byte[] nodeHash(byte[] left, byte[] right) {
        return sha256(concat(new byte[]{0x01}, left, right));
    }

    public static byte[] emptyRoot() {
        return sha256(new byte[0]);
    }

    /** Root over raw leaf data. */
    public static byte[] root(List<byte[]> leaves) {
        List<byte[]> hashes = new ArrayList<>(leaves.size());
        for (byte[] leaf : leaves) hashes.add(leafHash(leaf));
        return rootOfHashes(hashes);
    }

    /** Root over already-hashed leaves. */
    public static byte[] rootOfHashes(List<byte[]> hashes) {
        int n = hashes.size();
        if (n == 0) return emptyRoot();
        if (n == 1) return hashes.get(0);
        int k = largestPowerOfTwoLessThan(n);
        return nodeHash(rootOfHashes(hashes.subList(0, k)), rootOfHashes(hashes.subList(k, n)));
    }

    /** Inclusion proof for {@code index} in a tree of {@code hashes.size()} leaves. */
    public static List<byte[]> inclusionProof(int index, List<byte[]> hashes) {
        int n = hashes.size();
        if (index < 0 || index >= n) throw new IndexOutOfBoundsException("index " + index + " of " + n);
        List<byte[]> proof = new ArrayList<>();
        inclusion(index, hashes, proof);
        return proof;
    }

    private static void inclusion(int index, List<byte[]> hashes, List<byte[]> proof) {
        int n = hashes.size();
        if (n == 1) return;
        int k = largestPowerOfTwoLessThan(n);
        if (index < k) {
            inclusion(index, hashes.subList(0, k), proof);
            proof.add(rootOfHashes(hashes.subList(k, n)));
        } else {
            inclusion(index - k, hashes.subList(k, n), proof);
            proof.add(rootOfHashes(hashes.subList(0, k)));
        }
    }

    /**
     * Verify an inclusion proof. {@code index} is zero-based, {@code size} is the tree size,
     * {@code leafHash} is the leaf being proven, {@code root} is the signed root.
     */
    public static boolean verifyInclusion(byte[] leafHash, int index, int size, byte[] root, List<byte[]> proof) {
        if (index < 0 || index >= size) return false;
        if (size == 1) return proof.isEmpty() && java.util.Arrays.equals(leafHash, root);
        int fn = index;
        int sn = size - 1;
        byte[] r = leafHash;
        for (byte[] p : proof) {
            if ((fn & 1) == 1 || fn == sn) {
                r = nodeHash(p, r);
                while ((fn & 1) == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else {
                r = nodeHash(r, p);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && java.util.Arrays.equals(r, root);
    }

    /**
     * Consistency proof that the tree at {@code m} is a prefix of the tree at
     * {@code hashes.size()}. Requires 0 &lt; m &lt;= n.
     */
    public static List<byte[]> consistencyProof(int m, List<byte[]> hashes) {
        int n = hashes.size();
        if (m <= 0 || m > n) throw new IllegalArgumentException("m=" + m + " n=" + n);
        if (m == n) return List.of();
        List<byte[]> proof = new ArrayList<>();
        subproof(m, hashes, true, proof);
        return proof;
    }

    private static void subproof(int m, List<byte[]> hashes, boolean b, List<byte[]> proof) {
        int n = hashes.size();
        if (m == n) {
            if (!b) proof.add(rootOfHashes(hashes));
            return;
        }
        int k = largestPowerOfTwoLessThan(n);
        if (m <= k) {
            subproof(m, hashes.subList(0, k), b, proof);
            proof.add(rootOfHashes(hashes.subList(k, n)));
        } else {
            subproof(m - k, hashes.subList(k, n), false, proof);
            proof.add(rootOfHashes(hashes.subList(0, k)));
        }
    }

    /** Verify a consistency proof between two signed roots. */
    public static boolean verifyConsistency(int m, int n, byte[] rootM, byte[] rootN, List<byte[]> proof) {
        if (m <= 0 || m > n) return false;
        if (m == n) return proof.isEmpty() && java.util.Arrays.equals(rootM, rootN);
        int fn = m - 1;
        int sn = n - 1;
        while ((fn & 1) == 1) {
            fn >>= 1;
            sn >>= 1;
        }
        byte[] fr;
        byte[] sr;
        int i;
        if (fn == 0) {
            fr = rootM;
            sr = rootM;
            i = 0;
        } else {
            if (proof.isEmpty()) return false;
            fr = proof.get(0);
            sr = proof.get(0);
            i = 1;
        }
        for (; i < proof.size(); i++) {
            if (sn == 0) return false;
            byte[] p = proof.get(i);
            if ((fn & 1) == 1 || fn == sn) {
                fr = nodeHash(p, fr);
                sr = nodeHash(p, sr);
                while ((fn & 1) == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else {
                sr = nodeHash(sr, p);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && java.util.Arrays.equals(fr, rootM) && java.util.Arrays.equals(sr, rootN);
    }

    public static int largestPowerOfTwoLessThan(int n) {
        if (n < 2) throw new IllegalArgumentException("n must be >= 2");
        int k = 1;
        while ((k << 1) < n) k <<= 1;
        return k;
    }

    static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] a : arrays) out.writeBytes(a);
        return out.toByteArray();
    }
}
