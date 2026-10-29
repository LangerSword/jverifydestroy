import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Spike probe: can a parent JVM read a child JVM's /proc/<pid>/mem (yama ptrace_scope=1)?
 * Canary is derived from a seed passed on the command line, so the raw canary is never in argv.
 */
public final class ScanProbe {
    static final int CANARY_LEN = 24;

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) {
            child(args);
        } else {
            parent(args);
        }
    }

    static byte[] derive(byte[] seed) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(seed, "HmacSHA256"));
        return Arrays.copyOf(mac.doFinal("jvd-canary-v1".getBytes(StandardCharsets.UTF_8)), CANARY_LEN);
    }

    static void child(String[] args) throws Exception {
        byte[] seed = HexFormat.of().parseHex(args[1]);
        boolean wipe = args.length > 2 && args[2].equals("wipe");
        byte[] canary = derive(seed);
        byte[] secret = new byte[128];
        System.arraycopy(canary, 0, secret, 32, CANARY_LEN);
        Arrays.fill(canary, (byte) 0);
        canary = null;
        if (wipe) {
            Arrays.fill(secret, (byte) 0);
            secret = null;
            System.gc();
        }
        System.out.println("READY " + ProcessHandle.current().pid());
        System.out.flush();
        // Hold until the parent writes a line.
        System.in.read();
        Thread.sleep(200);
    }

    static void parent(String[] args) throws Exception {
        byte[] seed = new byte[16];
        new Random(42).nextBytes(seed);
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-Xmx64m", "-cp", System.getProperty("java.class.path"),
                "ScanProbe", "child", HexFormat.of().formatHex(seed), args.length > 0 ? args[0] : "wipe")
                .redirectErrorStream(true).start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = br.readLine();
        System.out.println("child says: " + line);
        long pid = Long.parseLong(line.split(" ")[1]);
        byte[] canary = derive(seed);
        ScanResult raw = scan(pid, canary, false, true);
        System.out.println("raw scan: " + raw);
        ScanResult masked = scan(pid, canary, true, true);
        System.out.println("masked scan: " + masked);
        p.getOutputStream().write('\n');
        p.getOutputStream().flush();
        p.waitFor();
    }

    record ScanResult(long regions, long bytes, boolean found, int matches, String error) {}

    static ScanResult scan(long pid, byte[] pattern, boolean masked, boolean skipGuardPages) {
        long regions = 0, bytes = 0; int matches = 0;
        byte[] needle = pattern.clone();
        if (masked) for (int i = 0; i < needle.length; i++) needle[i] ^= 0x5A;
        try {
            List<String[]> maps = new ArrayList<>();
            for (String l : Files.readAllLines(Paths.get("/proc/" + pid + "/maps"))) {
                String[] parts = l.split("\\s+");
                if (parts.length < 2 || !parts[1].startsWith("r")) continue;
                String[] range = parts[0].split("-");
                long start = Long.parseUnsignedLong(range[0], 16), end = Long.parseUnsignedLong(range[1], 16);
                maps.add(new String[]{Long.toString(start), Long.toString(end), parts.length > 5 ? parts[5] : ""});
            }
            try (FileChannel ch = FileChannel.open(Paths.get("/proc/" + pid + "/mem"), StandardOpenOption.READ)) {
                ByteBuffer buf = ByteBuffer.allocate(1 << 20);
                for (String[] m : maps) {
                    long start = Long.parseLong(m[0]), end = Long.parseLong(m[1]);
                    long len = end - start;
                    if (len <= 0 || len > (1L << 32)) continue;
                    regions++; bytes += len;
                    byte[] carry = new byte[needle.length - 1];
                    int carryLen = 0;
                    for (long off = 0; off < len; off += buf.capacity()) {
                        int want = (int) Math.min(buf.capacity(), len - off);
                        buf.clear(); buf.limit(want);
                        try {
                            int n = ch.read(buf, start + off);
                            if (n <= 0) break;
                            byte[] data = new byte[carryLen + n];
                            System.arraycopy(carry, 0, data, 0, carryLen);
                            System.arraycopy(buf.array(), 0, data, carryLen, n);
                            for (int i = 0; i + needle.length <= data.length; i++) {
                                boolean ok = true;
                                for (int j = 0; j < needle.length; j++) if (data[i + j] != needle[j]) { ok = false; break; }
                                if (ok) { matches++; if (matches > 4) return new ScanResult(regions, bytes, true, matches, null); }
                            }
                            carryLen = Math.min(needle.length - 1, data.length);
                            System.arraycopy(data, data.length - carryLen, carry, 0, carryLen);
                        } catch (IOException e) {
                            // Skip an unreadable region.
                            break;
                        }
                    }
                }
            }
            return new ScanResult(regions, bytes, matches > 0, matches, null);
        } catch (Exception e) {
            return new ScanResult(regions, bytes, false, matches, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
