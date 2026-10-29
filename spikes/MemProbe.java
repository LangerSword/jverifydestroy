import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Spike H1/H2/H4: after a claimed wipe, is the canary still present in a child JVM's memory?
 * Every trial carries a positive control (an unwiped copy that MUST be found) and a negative
 * control (a value never written that MUST NOT be found). A failed control invalidates the trial.
 */
public final class MemProbe {
    static final int CANARY_LEN = 32;
    static byte[] controlSink;
    static byte[] hotSink;
    static volatile byte[] VOL;
    static volatile int VSINK;

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }
        String mode = args.length > 0 ? args[0] : "wipe";
        String gc = args.length > 1 ? args[1] : "G1";
        int trials = args.length > 2 ? Integer.parseInt(args[2]) : 1;
        String extra = args.length > 3 ? args[3] : "";
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        int valid = 0, invalid = 0, found = 0;
        for (int t = 0; t < trials; t++) {
            byte[] seed = new byte[16];
            new Random(1000 + t).nextBytes(seed);
            List<String> cmd = new ArrayList<>(List.of(java, "-Xmx128m", "-XX:+Use" + gc + (gc.endsWith("GC") ? "" : "GC")));
            if (extra.equals("xint")) cmd.add("-Xint");
            if (extra.equals("xcomp")) cmd.add("-Xcomp");
            cmd.addAll(List.of("-cp", System.getProperty("java.class.path"), "MemProbe", "child",
                    HexFormat.of().formatHex(seed), mode));
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line; StringBuilder seen = new StringBuilder();
            do { line = br.readLine(); if (line != null && !line.startsWith("READY ")) seen.append(line).append(" | "); }
            while (line != null && !line.startsWith("READY "));
            if (line == null) { System.out.println("trial " + t + " no READY: " + seen); p.destroyForcibly(); continue; }
            long pid = Long.parseLong(line.split(" ")[1]);
            byte[] target = derive(seed, "target"), control = derive(seed, "control"), neg = derive(seed, "negative");
            Scan sTarget = scan(pid, target), sControl = scan(pid, control), sNeg = scan(pid, neg);
            boolean ok = sControl.found && !sNeg.found && sTarget.error == null;
            if (ok) valid++; else invalid++;
            if (sTarget.found) found++;
            System.out.printf(Locale.ROOT, "%s,%s,%s,%d,%s,%s,%s,%s,%d%n", mode, gc, extra, t,
                    sTarget.found ? "FOUND" : "NOT_FOUND", sControl.found ? "FOUND" : "NOT_FOUND",
                    sNeg.found ? "FOUND" : "NOT_FOUND", ok ? "VALID" : "INVALID", sTarget.matches);
            p.getOutputStream().write('\n'); p.getOutputStream().flush();
            if (!p.waitFor(5, TimeUnit.SECONDS)) p.destroyForcibly();
        }
        System.out.printf(Locale.ROOT, "SUMMARY,%s,%s,%s,valid=%d,invalid=%d,found=%d,rate=%.4f%n",
                mode, gc, extra, valid, invalid, found, valid == 0 ? -1 : (double) found / valid);
    }

    static byte[] derive(byte[] seed, String label) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] l = label.getBytes(StandardCharsets.UTF_8);
        byte[] in = new byte[seed.length + l.length];
        System.arraycopy(seed, 0, in, 0, seed.length);
        System.arraycopy(l, 0, in, seed.length, l.length);
        byte[] out = md.digest(in);
        Arrays.fill(in, (byte) 0);
        byte[] copy = Arrays.copyOf(out, CANARY_LEN);
        Arrays.fill(out, (byte) 0);
        return copy;
    }

    static void child(String[] args) throws Exception {
        byte[] seed = HexFormat.of().parseHex(args[1]);
        String mode = args[2];
        byte[] tc = derive(seed, "target");
        byte[] cc = derive(seed, "control");
        byte[] control = new byte[512];
        System.arraycopy(cc, 0, control, 128, CANARY_LEN);
        controlSink = control;
        Arrays.fill(cc, (byte) 0);
        byte[] target = new byte[4096];
        System.arraycopy(tc, 0, target, 512, CANARY_LEN);
        Arrays.fill(tc, (byte) 0);
        switch (mode) {
            case "hold" -> hotSink = target;
            case "wipe" -> { Arrays.fill(target, (byte) 0); target = null; }
            case "wipegc" -> { Arrays.fill(target, (byte) 0); target = null; System.gc(); }
            case "move" -> { System.gc(); Thread.sleep(20); Arrays.fill(target, (byte) 0); target = null; System.gc(); }
            case "hot" -> {
                for (int i = 0; i < 2_000_000; i++) Arrays.fill(target, (byte) 0);
                hotSink = target;
            }
            case "publish" -> { VOL = target; Arrays.fill(target, (byte) 0); VOL = null; target = null; }
            case "publishAfter" -> { Arrays.fill(target, (byte) 0); VOL = target; VOL = null; target = null; }
            case "publishRead" -> { VOL = target; Arrays.fill(target, (byte) 0); VSINK = target[0]; VOL = null; target = null; }
            default -> throw new IllegalArgumentException(mode);
        }
        System.out.println("READY " + ProcessHandle.current().pid());
        System.out.flush();
        System.in.read();
        Thread.sleep(100);
    }

    record Scan(int matches, boolean found, String error) {}

    static Scan scan(long pid, byte[] needle) {
        int matches = 0;
        try (FileChannel ch = FileChannel.open(Paths.get("/proc/" + pid + "/mem"), StandardOpenOption.READ)) {
            for (String l : Files.readAllLines(Paths.get("/proc/" + pid + "/maps"))) {
                String[] parts = l.split("\\s+");
                if (parts.length < 2 || !parts[1].startsWith("rw")) continue;
                String path = parts.length > 5 ? parts[5] : "";
                if (!path.isEmpty() && !path.equals("[heap]") && !path.startsWith("/memfd:")) continue;
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
                        int m = count(data, needle);
                        matches += m;
                        if (matches > 8) return new Scan(matches, true, null);
                        carryLen = Math.min(needle.length - 1, data.length);
                        System.arraycopy(data, data.length - carryLen, carry, 0, carryLen);
                    } catch (IOException e) { break; }
                }
            }
            return new Scan(matches, matches > 0, null);
        } catch (Exception e) {
            return new Scan(matches, matches > 0, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    static int count(byte[] data, byte[] needle) {
        int n = 0;
        outer: for (int i = 0; i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) if (data[i+j] != needle[j]) continue outer;
            n++;
        }
        return n;
    }
}
