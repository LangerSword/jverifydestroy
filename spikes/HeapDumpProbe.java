import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Spike H3: hprof default vs -all, and whether a heap dump is a faithful memory image. */
public final class HeapDumpProbe {
    static byte[] sink;
    static final int LEN = 32;

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }
        String mode = args.length > 0 ? args[0] : "drop";
        boolean xint = args.length > 1 && args[1].equals("xint");
        byte[] seed = new byte[16]; new Random(7).nextBytes(seed);
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java, "-Xmx64m", "-XX:+UseG1GC"));
        if (xint) cmd.add("-Xint");
        cmd.addAll(List.of("-cp", System.getProperty("java.class.path"), "HeapDumpProbe", "child",
                HexFormat.of().formatHex(seed), mode));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = br.readLine(); System.out.println("child: " + line);
        long pid = Long.parseLong(line.split(" ")[1]);
        byte[] canary = derive(seed);
        System.out.println("/proc before dump: " + scanProc(pid, canary));
        String jcmd = Paths.get(System.getProperty("java.home"), "bin", "jcmd").toString();
        String dumpMode = args.length > 2 ? args[2] : "both";
        Path d1 = Files.createTempDirectory("jvd-hprof").resolve("live.hprof");
        Path d2 = Files.createTempDirectory("jvd-hprof").resolve("all.hprof");
        if (!dumpMode.equals("all")) {
            run(jcmd, Long.toString(pid), "GC.heap_dump", d1.toString());
            System.out.println("hprof default: " + scanFile(d1, canary) + " size=" + Files.size(d1));
        }
        if (!dumpMode.equals("default")) {
            run(jcmd, Long.toString(pid), "GC.heap_dump", "-all", d2.toString());
            System.out.println("hprof -all   : " + scanFile(d2, canary) + " size=" + Files.size(d2));
        }
        System.out.println("/proc after  : " + scanProc(pid, canary));
        p.getOutputStream().write('\n'); p.getOutputStream().flush(); p.waitFor();
        Files.deleteIfExists(d1); Files.deleteIfExists(d2);
    }

    static void run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        int rc = p.waitFor();
        System.out.println("$ jcmd " + String.join(" ", Arrays.copyOfRange(cmd, 1, cmd.length)) + " -> " + rc + " " + out.trim().replace('\n',' '));
    }

    static byte[] derive(byte[] seed) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(seed, "HmacSHA256"));
        return Arrays.copyOf(m.doFinal("jvd-canary-v1".getBytes(StandardCharsets.UTF_8)), LEN);
    }

    static void child(String[] args) throws Exception {
        byte[] seed = HexFormat.of().parseHex(args[1]);
        String mode = args[2];
        byte[] canary = derive(seed);
        byte[] arr = new byte[4096];
        System.arraycopy(canary, 0, arr, 100, LEN);
        Arrays.fill(canary, (byte) 0); canary = null;
        sink = arr;
        arr = null;
        if (mode.startsWith("drop")) sink = null;
        if (mode.endsWith("gc")) { for (int i = 0; i < 3; i++) { System.gc(); Thread.sleep(50); } }
        System.out.println("READY " + ProcessHandle.current().pid()); System.out.flush();
        System.in.read();
    }

    static String scanFile(Path f, byte[] needle) throws IOException {
        byte[] d = Files.readAllBytes(f);
        return search(d, needle) >= 0 ? "FOUND" : "NOT_FOUND";
    }

    static int search(byte[] d, byte[] needle) {
        outer: for (int i = 0; i + needle.length <= d.length; i++) {
            for (int j = 0; j < needle.length; j++) if (d[i+j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    static String scanProc(long pid, byte[] needle) {
        int matches = 0;
        try (FileChannel ch = FileChannel.open(Paths.get("/proc/" + pid + "/mem"), StandardOpenOption.READ)) {
            for (String l : Files.readAllLines(Paths.get("/proc/" + pid + "/maps"))) {
                String[] parts = l.split("\\s+");
                if (parts.length < 2 || !parts[1].startsWith("rw")) continue;
                String path = parts.length > 5 ? parts[5] : "";
                if (!path.isEmpty() && !path.equals("[heap]")) continue;
                String[] range = parts[0].split("-");
                long start = Long.parseUnsignedLong(range[0], 16), end = Long.parseUnsignedLong(range[1], 16);
                long len = end - start;
                if (len <= 0 || len > (1L << 31)) continue;
                ByteBuffer buf = ByteBuffer.allocate(1 << 20);
                byte[] carry = new byte[needle.length - 1]; int carryLen = 0;
                for (long off = 0; off < len; off += buf.capacity()) {
                    int want = (int) Math.min(buf.capacity(), len - off);
                    buf.clear(); buf.limit(want);
                    try {
                        int n = ch.read(buf, start + off);
                        if (n <= 0) break;
                        byte[] data = new byte[carryLen + n];
                        System.arraycopy(carry, 0, data, 0, carryLen);
                        System.arraycopy(buf.array(), 0, data, carryLen, n);
                        if (search(data, needle) >= 0) matches++;
                        carryLen = Math.min(needle.length - 1, data.length);
                        System.arraycopy(data, data.length - carryLen, carry, 0, carryLen);
                    } catch (IOException e) { break; }
                }
            }
        } catch (Exception e) { return "ERR " + e; }
        return matches == 0 ? "NOT_FOUND" : "FOUND(" + matches + ")";
    }
}
