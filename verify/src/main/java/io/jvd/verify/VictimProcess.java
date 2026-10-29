package io.jvd.verify;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Starts and stops the child JVM that the verifier scans. */
public final class VictimProcess implements AutoCloseable {
    private final Process process;
    private final long pid;
    private final BufferedReader out;

    private VictimProcess(Process process, long pid, BufferedReader out) {
        this.process = process;
        this.pid = pid;
        this.out = out;
    }

    public static VictimProcess start(byte[] seed, String mode, String gc) throws IOException {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String cp = classpath();
        List<String> cmd = new ArrayList<>();
        cmd.add(java);
        cmd.add("-Xmx128m");
        if (gc != null && !gc.isBlank()) cmd.add("-XX:+Use" + gc + (gc.endsWith("GC") ? "" : "GC"));
        cmd.add("-cp");
        cmd.add(cp);
        cmd.add("io.jvd.verify.CanaryVictim");
        cmd.add(Canary.hex(seed));
        cmd.add(mode);
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder seen = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            if (line.startsWith("READY ")) {
                long pid = Long.parseLong(line.substring(6).trim());
                return new VictimProcess(p, pid, br);
            }
            seen.append(line).append(" | ");
            if (seen.length() > 2000) break;
        }
        p.destroyForcibly();
        throw new IOException("victim did not become ready: " + seen);
    }

    public long pid() { return pid; }

    public Process process() { return process; }

    /** A classpath that works both for the CLI (full java.class.path) and under Surefire. */
    static String classpath() {
        String explicit = System.getProperty("jvd.victim.classpath");
        if (explicit != null && !explicit.isBlank()) return explicit;
        List<String> parts = new ArrayList<>();
        String base = System.getProperty("java.class.path", "");
        if (!base.isBlank()) parts.add(base);
        for (String candidate : List.of("target/classes", "../verify/target/classes")) {
            Path p = Path.of(candidate).toAbsolutePath().normalize();
            String s = p.toString();
            if (java.nio.file.Files.isDirectory(p) && !parts.contains(s)) parts.add(s);
        }
        return String.join(File.pathSeparator, parts);
    }

    @Override
    public void close() {
        try {
            process.getOutputStream().write('\n');
            process.getOutputStream().flush();
        } catch (IOException ignored) {
            // Process may already be gone.
        }
        try {
            if (!process.waitFor(10, TimeUnit.SECONDS)) process.destroyForcibly();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }
}
