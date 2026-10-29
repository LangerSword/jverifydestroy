import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.*;

/** Minimal: allocate, wipe, null, scan own memory for the pattern. */
public class MinimalSelf {
    static final byte MASK = 0x5A;
    public static void main(String[] a) throws Exception {
        byte[] p = new byte[64];
        for (int i = 0; i < p.length; i++) p[i] = (byte) (0xA0 + i);
        byte[] m = new byte[64];
        for (int i = 0; i < 64; i++) m[i] = (byte) (p[i] ^ MASK);
        System.out.println("before wipe, naive=" + scan(0, p, false) + " masked=" + scan(0, m, true));
        Arrays.fill(p, (byte) 0);
        java.lang.ref.Reference.reachabilityFence(p);
        p = null;
        for (int i = 0; i < 3; i++) { System.gc(); Thread.sleep(50); }
        System.out.println("after wipe, masked=" + scan(0, m, true));
        // Deliberately keep a copy in a static field as a positive control.
        KEEP = new byte[64]; System.arraycopy(m, 0, KEEP, 0, 64);
        System.out.println("positive control (masked copy held), masked=" + scan(0, m, true));
    }
    static byte[] KEEP;
    static boolean scan(long pid, byte[] needle, boolean masked) {
        try (FileChannel ch = FileChannel.open(Paths.get(pid == 0 ? "/proc/self/mem" : "/proc/" + pid + "/mem"), StandardOpenOption.READ)) {
            String maps = pid == 0 ? "/proc/self/maps" : "/proc/" + pid + "/maps";
            for (String l : Files.readAllLines(Paths.get(maps))) {
                String[] q = l.split("\\s+");
                if (q.length < 2 || !q[1].startsWith("rw")) continue;
                String path = q.length > 5 ? q[5] : "";
                if (!path.isEmpty() && !path.equals("[heap]")) continue;
                String[] r = q[0].split("-");
                long s = Long.parseUnsignedLong(r[0], 16), e = Long.parseUnsignedLong(r[1], 16);
                if (e - s <= 0 || e - s > (1L << 31)) continue;
                ByteBuffer b = ByteBuffer.allocate(1 << 20);
                for (long off = 0; off < e - s; off += b.capacity()) {
                    int want = (int) Math.min(b.capacity(), e - s - off);
                    b.clear(); b.limit(want);
                    try {
                        int n = ch.read(b, s + off);
                        if (n <= 0) break;
                        byte[] d = b.array();
                        for (int i = 0; i + 64 <= n; i++) {
                            boolean ok = true;
                            for (int j = 0; j < 64; j++) {
                                byte x = masked ? (byte) (d[i + j] ^ MASK) : d[i + j];
                                if (x != needle[j]) { ok = false; break; }
                            }
                            if (ok) { StringBuilder sb=new StringBuilder(); for(int k=0;k<8;k++) sb.append(String.format("%02x", d[i+k])); System.out.println("  match at " + Long.toHexString(s + off + i) + " bytes=" + sb + " region=" + path); return true; }
                        }
                    } catch (Exception ex) { break; }
                }
            }
        } catch (Exception e) { System.out.println("err " + e); }
        return false;
    }
}
