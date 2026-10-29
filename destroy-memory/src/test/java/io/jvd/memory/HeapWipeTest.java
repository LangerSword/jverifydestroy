package io.jvd.memory;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HeapWipeTest {
    @Test void wipesBytes() {
        byte[] b = new byte[128];
        java.util.Arrays.fill(b, (byte) 0x5A);
        HeapWipe.wipeBestEffort(b);
        assertArrayEquals(new byte[128], b);
    }

    @Test void wipesCharsAndInts() {
        char[] c = {'s', 'e', 'c'};
        HeapWipe.wipeBestEffort(c);
        assertArrayEquals(new char[3], c);
        int[] i = {1, 2, 3};
        HeapWipe.wipeBestEffort(i);
        assertArrayEquals(new int[3], i);
    }

    @Test void nullIsSafe() {
        HeapWipe.wipeBestEffort((byte[]) null);
        HeapWipe.wipeBestEffort((char[]) null);
    }

    @Test void stringCannotBeWiped() {
        String s = new String("secret");
        StringMisuseDemo.Report r = StringMisuseDemo.run(s);
        assertEquals("secret", r.valueAfterAttempt());
        assertTrue(r.sameReference());
        assertTrue(r.recommendation().contains("cannot be wiped"));
    }
}
