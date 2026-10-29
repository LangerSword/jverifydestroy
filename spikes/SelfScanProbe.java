import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Spike H4: a scanner that holds the raw canary finds itself. Masked scanning avoids the self-match. */
public final class SelfScanProbe {
    static final int LEN = 32;
    static final byte MASK = 0x5A;

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }
        byte[] seed = new byte[16]; new Random(11).nextBytes(seed);
        byte[] raw = derive(seed);
        // Naive scanner: keep raw canary, scan own memory.
        System.out.println("naive self-scan (raw held): " + (scan(0, raw, false) ? "FOUND (self-match)" : "NOT_FOUND"));
        // Masked scanner: derive masked needle, wipe every raw copy, then scan self.
        byte[] masked = new byte[LEN];
        for (int i = 0; i < LEN; i++) masked[i] = (byte) (raw[i] ^ MASK);
        Arrays.fill(raw, (byte) 0);
        java.lang.ref.Reference.reachabilityFence(raw);
        raw = null;
        System.gc();
        System.out.println("masked self-scan (raw wiped): " + (scan(0, masked, true) ? "FOUND (bad)" : "NOT_FOUND (good)"));
        // Now prove the masked scanner still sees a raw canary held by another process.
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-Xmx32m", "-cp", System.getProperty("java.class.path"),
                "SelfScanProbe", "child", HexFormat.of().formatHex(seed)).redirectErrorStream(true).start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        long pid = Long.parseLong(br.readLine().split(" ")[1]);
        System.out.println("masked child scan: " + (scan(pid, masked, true) ? "FOUND (good)" : "NOT_FOUND (bad)"));
        p.getOutputStream().write('\n'); p.getOutputStream().flush(); p.waitFor();
    }

    static byte[] derive(byte[] seed) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] in = new byte[seed.length + 4];
        System.arraycopy(seed, 0, in, 0, seed.length);
        System.arraycopy("self".getBytes(StandardCharsets.UTF_8), 0, in, seed.length, 4);
        byte[] out = md.digest(in);
        Arrays.fill(in, (byte) 0);
        byte[] copy = Arrays.copyOf(out, LEN);
        Arrays.fill(out, (byte) 0);
        return copy;
    }

    static boolean scan(long pid, byte[] needle, boolean masked) {
        try (FileChannel ch = FileChannel.open(Paths.get(pid == 0 ? "/proc/self/mem" : "/proc/" + pid + "/mem"), StandardOpenOption.READ)) {
            String mapsPath = pid == 0 ? "/proc/self/maps" : "/proc/" + pid + "/maps";
            for (String l : Files.readAllLines(Paths.get(mapsPath))) {
                String[] parts = l.split("\\s+");
                if (parts.length < 2 || !parts[1].startsWith("rw")) continue;
                String path = parts.length > 5 ? parts[5] : "";
                if (!path.isEmpty() && !path.equals("[heap]")) continue;
                String[] range = parts[0].split("-");
                long start = Long.parseUnsignedLong(range[0], 16), end = Long.parseUnsignedLong(range[1], 16);
                long len = end - start;
                if (len <= 0 || len > (1L << 31)) continue;
                ByteBuffer buf = ByteBuffer.allocate(1 << 20);
                for (long off = 0; off < len; off += buf.capacity()) {
                    int want = (int) Math.min(buf.capacity(), len - off);
                    buf.clear(); buf.limit(want);
                    try {
                        int n = ch.read(buf, start + off);
                        if (n <= 0) break;
                        byte[] d = buf.array();
                        for (int i = 0; i + needle.length <= n; i++) {
                            boolean ok = true;
                            for (int j = 0; j < needle.length; j++) {
                                byte b = masked ? (byte) (d[i + j] ^ MASK) : d[i + j];
                                if (b != needle[j]) { ok = false; break; }
                            }
                            if (ok) return true;
                        }
                    } catch (Exception e) { break; }
                }
            }
        } catch (Exception e) { System.out.println("scan error: " + e); }
        return false;
    }

    static void child(String[] args) throws Exception {
        byte[] seed = HexFormat.of().parseHex(args[1]);
        byte[] raw = derive(seed);
        System.out.println("READY " + ProcessHandle.current().pid()); System.out.flush();
        System.in.read();
        Arrays.fill(raw, (byte) 0);
    }
}
