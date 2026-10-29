import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Spike H1: which heap-wipe idioms actually remove the bytes from process memory? */
public final class WipeModes {
    static final int LEN = 48;
    static final byte MASK = 0x5A;
    static volatile byte[] VOL;
    static volatile int SINK;
    static byte[] STRONG;

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }
        String javaBin = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        for (String mode : List.of("plain", "fence", "volatile", "read", "strong")) {
            byte[] seed = new byte[16]; new Random(mode.hashCode()).nextBytes(seed);
            byte[] raw = derive(seed);
            Process p = new ProcessBuilder(javaBin, "-Xmx64m", "-XX:+UseG1GC", "-cp", System.getProperty("java.class.path"),
                    "WipeModes", "child", HexFormat.of().formatHex(seed), mode).redirectErrorStream(true).start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            long pid = Long.parseLong(line.split(" ")[1]);
            byte[] masked = new byte[LEN];
            for (int i = 0; i < LEN; i++) masked[i] = (byte) (raw[i] ^ MASK);
            Arrays.fill(raw, (byte) 0); java.lang.ref.Reference.reachabilityFence(raw); raw = null;
            boolean found = scan(pid, masked);
            System.out.printf(Locale.ROOT, "%-9s %s%n", mode, found ? "FOUND (residue)" : "NOT_FOUND");
            p.getOutputStream().write('\n'); p.getOutputStream().flush(); p.waitFor();
        }
    }

    static byte[] derive(byte[] seed) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] in = new byte[seed.length + 4];
        System.arraycopy(seed, 0, in, 0, seed.length);
        System.arraycopy("wipe".getBytes(StandardCharsets.UTF_8), 0, in, seed.length, 4);
        byte[] out = md.digest(in);
        Arrays.fill(in, (byte) 0);
        byte[] copy = Arrays.copyOf(out, LEN);
        Arrays.fill(out, (byte) 0);
        return copy;
    }

    static void child(String[] args) throws Exception {
        byte[] seed = HexFormat.of().parseHex(args[1]);
        String mode = args[2];
        byte[] raw = derive(seed);
        byte[] p = new byte[4096];
        System.arraycopy(raw, 0, p, 777, LEN);
        byte[] deriv = raw; Arrays.fill(deriv, (byte) 0); deriv = null;
        switch (mode) {
            case "plain" -> { Arrays.fill(p, (byte) 0); p = null; }
            case "fence" -> { Arrays.fill(p, (byte) 0); java.lang.ref.Reference.reachabilityFence(p); p = null; }
            case "volatile" -> { Arrays.fill(p, (byte) 0); VOL = p; VOL = null; p = null; }
            case "read" -> { Arrays.fill(p, (byte) 0); SINK = p[0]; p = null; }
            case "strong" -> { Arrays.fill(p, (byte) 0); STRONG = p; p = null; }
            default -> throw new IllegalArgumentException(mode);
        }
        for (int i = 0; i < 3; i++) { System.gc(); Thread.sleep(30); }
        System.out.println("READY " + ProcessHandle.current().pid()); System.out.flush();
        System.in.read();
    }

    static boolean scan(long pid, byte[] masked) {
        try (FileChannel ch = FileChannel.open(Paths.get("/proc/" + pid + "/mem"), StandardOpenOption.READ)) {
            for (String l : Files.readAllLines(Paths.get("/proc/" + pid + "/maps"))) {
                String[] q = l.split("\\s+");
                if (q.length < 2 || !q[1].startsWith("rw")) continue;
                String path = q.length > 5 ? q[5] : "";
                if (!path.isEmpty() && !path.equals("[heap]") && !path.startsWith("/memfd:")) continue;
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
                        for (int i = 0; i + LEN <= n; i++) {
                            boolean ok = true;
                            for (int j = 0; j < LEN; j++) if ((byte) (d[i+j] ^ MASK) != masked[j]) { ok = false; break; }
                            if (ok) return true;
                        }
                    } catch (Exception ex) { break; }
                }
            }
        } catch (Exception e) { System.out.println("scan err " + e); }
        return false;
    }
}
