package io.jvd.log;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MerkleTest {
    private static List<byte[]> leaves(int n) {
        List<byte[]> l = new ArrayList<>();
        for (int i = 0; i < n; i++) l.add(("leaf-" + i).getBytes(StandardCharsets.UTF_8));
        return l;
    }

    private static List<byte[]> hashes(List<byte[]> leaves) {
        List<byte[]> h = new ArrayList<>();
        for (byte[] l : leaves) h.add(Merkle.leafHash(l));
        return h;
    }

    @Test void leafAndNodeHashUseDomainSeparation() {
        byte[] data = "x".getBytes();
        byte[] expectedLeaf = Merkle.sha256(new byte[]{0, 'x'});
        assertArrayEquals(expectedLeaf, Merkle.leafHash(data));
        byte[] a = Merkle.leafHash("a".getBytes());
        byte[] b = Merkle.leafHash("b".getBytes());
        assertArrayEquals(Merkle.sha256(Merkle.concat(new byte[]{1}, a, b)), Merkle.nodeHash(a, b));
    }

    @Test void inclusionProofsVerifyForEveryIndexAndSize() {
        for (int n = 1; n <= 50; n++) {
            List<byte[]> h = hashes(leaves(n));
            byte[] root = Merkle.rootOfHashes(h);
            for (int i = 0; i < n; i++) {
                List<byte[]> proof = Merkle.inclusionProof(i, h);
                assertTrue(Merkle.verifyInclusion(h.get(i), i, n, root, proof), "n=" + n + " i=" + i);
                if (!proof.isEmpty()) assertFalse(Merkle.verifyInclusion(h.get(i), i, n, root, proof.subList(0, proof.size() - 1)));
            }
        }
    }

    @Test void consistencyProofsVerifyForEveryPrefixAndSize() {
        for (int n = 2; n <= 40; n++) {
            List<byte[]> h = hashes(leaves(n));
            byte[] rootN = Merkle.rootOfHashes(h);
            for (int m = 1; m < n; m++) {
                byte[] rootM = Merkle.rootOfHashes(h.subList(0, m));
                List<byte[]> proof = Merkle.consistencyProof(m, h);
                assertTrue(Merkle.verifyConsistency(m, n, rootM, rootN, proof), "m=" + m + " n=" + n);
                if (!proof.isEmpty()) {
                    List<byte[]> bad = new ArrayList<>(proof);
                    byte[] first = bad.get(0).clone();
                    first[0] ^= 0x01;
                    bad.set(0, first);
                    assertFalse(Merkle.verifyConsistency(m, n, rootM, rootN, bad), "mutated m=" + m + " n=" + n);
                }
                assertFalse(Merkle.verifyConsistency(m, n, new byte[32], rootN, proof));
            }
        }
    }

    @Test void emptyTreeRootIsSha256OfEmpty() {
        assertArrayEquals(Merkle.sha256(new byte[0]), Merkle.emptyRoot());
        assertArrayEquals(Merkle.emptyRoot(), Merkle.rootOfHashes(List.of()));
    }
}
