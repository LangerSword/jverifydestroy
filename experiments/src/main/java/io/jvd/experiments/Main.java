package io.jvd.experiments;

import io.jvd.evidence.EvidenceRecord;
import io.jvd.evidence.Ed25519;
import io.jvd.evidence.Json;
import io.jvd.file.CryptoShredder;
import io.jvd.file.FileDestroyer;
import io.jvd.file.FileKeyVault;
import io.jvd.log.*;
import io.jvd.verify.CanaryVerifier;
import io.jvd.verify.Mode;
import io.jvd.verify.ValidationResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.*;

/**
 * Runs the evaluation matrices against the real library and writes CSV plus RESULTS.md.
 * Numbers in the document come from this run; nothing is hand-entered.
 *
 * <pre>
 * java -cp ... io.jvd.experiments.Main [--trials N] [--threads T] [--out DIR]
 * </pre>
 */
public final class Main {
    static final String[] GCS = {"Serial", "Parallel", "G1", "ZGC", "Shenandoah"};
    static final Mode[] MODES = {Mode.WIPE, Mode.MOVE, Mode.HOT};

    public static void main(String[] args) throws Exception {
        int trials = 200, threads = 8;
        Path out = Path.of("experiments/out");
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--trials" -> trials = Integer.parseInt(args[++i]);
                case "--threads" -> threads = Integer.parseInt(args[++i]);
                case "--out" -> out = Path.of(args[++i]);
            }
        }
        Files.createDirectories(out);
        Path csv = out.resolve("results.csv");
        if (Arrays.asList(args).contains("--render-only")) {
            writeResults(out, csv, trials);
            System.out.println("re-rendered " + csv + " into docs/RESULTS.md");
            return;
        }
        Files.deleteIfExists(csv);
        header(csv);
        System.out.println("jdk=" + System.getProperty("java.runtime.version") + " trials=" + trials);
        memoryMatrix(csv, trials, threads);
        fileMatrix(csv, trials);
        tamperMatrix(csv, trials);
        overhead(csv);
        writeResults(out, csv, trials);
        System.out.println("wrote " + csv + " and docs/RESULTS.md");
    }

    static void header(Path csv) throws Exception {
        Files.writeString(csv, "matrix,collector,mode,trial,result,target,positive,negative,elapsed_ms,note\n");
    }

    static void row(Path csv, Object... v) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < v.length; i++) {
            if (i > 0) sb.append(',');
            String s = String.valueOf(v[i]);
            if (s.contains(",") || s.contains("\"")) s = "\"" + s.replace("\"", "\"\"") + "\"";
            sb.append(s);
        }
        Files.writeString(csv, sb.append('\n').toString(), StandardOpenOption.APPEND);
    }

    static void memoryMatrix(Path csv, int trials, int threads) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<?>> futures = new ArrayList<>();
        for (String gc : GCS) {
            for (Mode mode : MODES) {
                for (int t = 0; t < trials; t++) {
                    final int trial = t;
                    futures.add(pool.submit(() -> {
                        ValidationResult r = CanaryVerifier.validate(mode, gc);
                        synchronized (Main.class) {
                            try {
                                row(csv, "memory", gc, mode, trial, r.result(),
                                        r.target().verdict(), r.positive().verdict(),
                                        r.negative().verdict(), r.elapsedMillis(),
                                        r.reason() == null ? "" : r.reason());
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                        return null;
                    }));
                }
            }
        }
        for (Future<?> f : futures) f.get();
        pool.shutdown();
        System.out.println("memory matrix done");
    }

    static void fileMatrix(Path csv, int trials) throws Exception {
        for (int t = 0; t < trials; t++) {
            Path dir = Files.createTempDirectory("jvd-file-");
            try {
                Path f = dir.resolve("secret.bin");
                byte[] data = new byte[4096];
                new Random(t).nextBytes(data);
                Files.write(f, data);
                long t0 = System.nanoTime();
                FileDestroyer.Result d = FileDestroyer.deleteOnly(f);
                row(csv, "file", "delete-only", "delete", t, Files.exists(f) ? "FAIL" : "PASS",
                        "NOT_CHECKABLE", "N/A", "N/A", (System.nanoTime() - t0) / 1_000_000,
                        "raw residue not measured: no image");
            } finally {
                deleteTree(dir);
            }
            dir = Files.createTempDirectory("jvd-file-");
            try {
                Path f = dir.resolve("secret.bin");
                Files.write(f, new byte[4096]);
                long t0 = System.nanoTime();
                FileDestroyer.destroy(f, 1, true);
                row(csv, "file", "overwrite", "overwrite", t, Files.exists(f) ? "FAIL" : "PASS",
                        "NOT_CHECKABLE", "N/A", "N/A", (System.nanoTime() - t0) / 1_000_000,
                        "raw residue not measured: no image");
            } finally {
                deleteTree(dir);
            }
            dir = Files.createTempDirectory("jvd-crypto-");
            try {
                Path f = dir.resolve("secret.bin");
                Path c = dir.resolve("secret.jvd");
                Path k = dir.resolve("secret.key");
                Files.write(f, new byte[4096]);
                CryptoShredder.encrypt(f, c, k);
                FileDestroyer.destroy(f, 1, true);
                byte[] key = FileKeyVault.read(k);
                boolean before = CryptoShredder.canDecrypt(c, key);
                CryptoShredder.destroyKey(k, key);
                boolean after = CryptoShredder.canDecrypt(c, key);
                row(csv, "file", "crypto", "commit", t,
                        before && !after ? "PASS" : "FAIL",
                        "decrypt-before=" + before, "decrypt-after=" + after,
                        "wrong-key=" + CryptoShredder.canDecrypt(c, new byte[32]), 0,
                        "logical crypto-shred; no physical claim");
            } finally {
                deleteTree(dir);
            }
        }
        System.out.println("file matrix done");
    }

    static void tamperMatrix(Path csv, int trials) throws Exception {
        Path dir = Files.createTempDirectory("jvd-tamper-");
        try {
            KeyPair evidence = Ed25519.generate(), logKey = Ed25519.generate(), witnessKey = Ed25519.generate();
            LogStore log = new LogStore(dir.resolve("log"), "jvd.local/tamper");
            for (int i = 0; i < trials; i++) {
                EvidenceRecord r = EvidenceRecord.create("/tmp/f" + i, "CLEAR", "OVERWRITE");
                r.sign(evidence.getPrivate());
                log.append(r);
            }
            Checkpoint cp = log.checkpoint(logKey.getPrivate());
            new Witness("w", witnessKey.getPrivate(), witnessKey.getPublic()).cosign(cp, log);
            Path logFile = log.logFile();
            List<String> original = new ArrayList<>(Files.readAllLines(logFile));
            for (int i = 0; i < trials; i++) {
                // edited record
                List<String> lines = new ArrayList<>(original);
                Map<String, Object> line = Json.parseObject(lines.get(i));
                @SuppressWarnings("unchecked")
                Map<String, Object> rec = (Map<String, Object>) line.get("record");
                rec.put("timestamp", "2000-01-01T00:00:00Z");
                lines.set(i, Json.write(line));
                Files.write(logFile, lines);
                boolean detected = !LogVerifier.verify(logFile, cp, logKey.getPublic(), witnessKey.getPublic()).valid;
                row(csv, "tamper", "edit", "record", i, detected ? "DETECTED" : "MISSED", "", "", "", 0, "");

                // deleted record
                lines = new ArrayList<>(original);
                lines.remove(i);
                Files.write(logFile, lines);
                detected = !LogVerifier.verify(logFile, cp, logKey.getPublic(), witnessKey.getPublic()).valid;
                row(csv, "tamper", "delete", "record", i, detected ? "DETECTED" : "MISSED", "", "", "", 0, "");

                // backdated + re-signed record
                lines = new ArrayList<>(original);
                line = Json.parseObject(lines.get(i));
                @SuppressWarnings("unchecked")
                Map<String, Object> rm = (Map<String, Object>) line.get("record");
                EvidenceRecord rr = EvidenceRecord.fromJson(Json.write(rm));
                rr.timestamp = "2000-01-01T00:00:00Z";
                rr.sign(evidence.getPrivate());
                byte[] leaf = Merkle.leafHash(rr.toJson().getBytes(StandardCharsets.UTF_8));
                line.put("record", rr.toMap(true));
                line.put("leaf", Base64.getEncoder().encodeToString(leaf));
                lines.set(i, Json.write(line));
                Files.write(logFile, lines);
                detected = !LogVerifier.verify(logFile, cp, logKey.getPublic(), witnessKey.getPublic()).valid;
                row(csv, "tamper", "backdate", "record", i, detected ? "DETECTED" : "MISSED", "", "", "", 0, "");

                // same-size fork
                Checkpoint fork = Checkpoint.create("jvd.local/tamper", cp.size, new byte[32], logKey.getPrivate());
                boolean cosigned;
                try {
                    new Witness("w", witnessKey.getPrivate(), witnessKey.getPublic()).cosign(fork, log);
                    cosigned = true;
                } catch (IllegalArgumentException expected) {
                    cosigned = false;
                }
                detected = !cosigned || !LogVerifier.verify(logFile, fork, logKey.getPublic(), witnessKey.getPublic()).valid;
                row(csv, "tamper", "fork", "checkpoint", i, detected ? "DETECTED" : "MISSED", "", "", "", 0, "");
            }
            Files.write(logFile, original);
        } finally {
            deleteTree(dir);
        }
        System.out.println("tamper matrix done");
    }

    static void overhead(Path csv) throws Exception {
        for (int mb : new int[]{1, 16, 64}) {
            for (String method : new String[]{"overwrite", "crypto"}) {
                long[] times = new long[5];
                for (int i = 0; i < 5; i++) {
                    Path dir = Files.createTempDirectory("jvd-over-");
                    try {
                        Path f = dir.resolve("big.bin");
                        byte[] b = new byte[mb << 20];
                        new Random(i).nextBytes(b);
                        Files.write(f, b);
                        long t0 = System.nanoTime();
                        if (method.equals("overwrite")) {
                            FileDestroyer.destroy(f, 1, true);
                        } else {
                            CryptoShredder.encrypt(f, dir.resolve("big.jvd"), dir.resolve("big.key"));
                            FileDestroyer.destroy(f, 1, true);
                        }
                        times[i] = (System.nanoTime() - t0) / 1_000_000;
                    } finally {
                        deleteTree(dir);
                    }
                }
                Arrays.sort(times);
                row(csv, "overhead", method, mb + "MiB", 0, "OK", "", "", "", times[2],
                        "median of 5; p95=" + times[4]);
            }
        }
        System.out.println("overhead done");
    }

    static void writeResults(Path out, Path csv, int trials) throws Exception {
        List<String> lines = Files.readAllLines(csv);
        StringBuilder md = new StringBuilder();
        md.append("# RESULTS — generated from `").append(csv).append("`\n\n");
        md.append("JDK: ").append(System.getProperty("java.runtime.version"))
          .append("  \nOS: ").append(System.getProperty("os.name")).append(' ')
          .append(System.getProperty("os.version")).append("  \nTrials per memory cell: ")
          .append(trials).append("\n\n");
        md.append("Every memory trial carries a positive control (unwiped canary) and a negative control. ")
          .append("An INVALID trial is not a pass. `NOT_CHECKABLE` is not a pass.\n\n");
        md.append("## Memory matrix\n\n");
        md.append("| collector | mode | valid | target FOUND (false assurance) | rate | Wilson 95% CI | positive control FOUND |\n");
        md.append("|---|---|---|---|---|---|---|\n");
        Map<String, int[]> cells = new TreeMap<>();
        for (String line : lines) {
            String[] c = split(line);
            if (c.length < 9 || !c[0].equals("memory")) continue;
            String key = c[1] + "|" + c[2];
            int[] a = cells.computeIfAbsent(key, k -> new int[3]);
            boolean valid = !c[4].equals("INVALID");
            if (valid) a[0]++;
            if (c[4].equals("FAIL")) a[1]++;
            if (c[6].equals("FOUND")) a[2]++;
        }
        for (var e : cells.entrySet()) {
            String[] k = e.getKey().split("\\|");
            int[] a = e.getValue();
            md.append("| ").append(k[0]).append(" | ").append(k[1]).append(" | ").append(a[0])
              .append(" | ").append(a[1]).append(" | ").append(rate(a[1], a[0])).append(" | ")
              .append(wilson(a[1], a[0])).append(" | ").append(rate(a[2], a[0])).append(" |\n");
        }
        md.append("\n## File matrix\n\n");
        md.append("| method | trials | logical result | note |\n|---|---|---|---|\n");
        Map<String, int[]> files = new TreeMap<>();
        for (String line : lines) {
            String[] c = split(line);
            if (c.length < 6 || !c[0].equals("file")) continue;
            int[] a = files.computeIfAbsent(c[1], k -> new int[2]);
            a[0]++;
            if (c[4].equals("PASS")) a[1]++;
        }
        for (var e : files.entrySet()) {
            md.append("| ").append(e.getKey()).append(" | ").append(e.getValue()[0]).append(" | ")
              .append(e.getValue()[1]).append("/").append(e.getValue()[0])
              .append(" | raw-media residue NOT_CHECKABLE without an image |\n");
        }
        md.append("\n## Tamper matrix\n\n");
        md.append("| mutation | trials | detected | rate |\n|---|---|---|---|\n");
        Map<String, int[]> tam = new TreeMap<>();
        for (String line : lines) {
            String[] c = split(line);
            if (c.length < 6 || !c[0].equals("tamper")) continue;
            int[] a = tam.computeIfAbsent(c[1], k -> new int[2]);
            a[0]++;
            if (c[4].equals("DETECTED")) a[1]++;
        }
        for (var e : tam.entrySet()) {
            md.append("| ").append(e.getKey()).append(" | ").append(e.getValue()[0]).append(" | ")
              .append(e.getValue()[1]).append(" | ").append(rate(e.getValue()[1], e.getValue()[0])).append(" |\n");
        }
        md.append("\n## Overhead\n\n| method | size | median ms |\n|---|---|---|\n");
        for (String line : lines) {
            String[] c = split(line);
            if (c.length < 10 || !c[0].equals("overhead")) continue;
            md.append("| ").append(c[1]).append(" | ").append(c[2]).append(" | ").append(c[8]).append(" |\n");
        }
        md.append("\n## Limits\n\n");
        md.append("User-space Java cannot verify the SSD flash translation layer, bad-block pools, ")
          .append("controller-held copies, journal copies, snapshots, or backups. These are logical-level ")
          .append("results. The witness is a local key, not an independent party. No result here is a ")
          .append("physical-erasure guarantee.\n");
        Files.writeString(Path.of("docs/RESULTS.md"), md.toString());
    }

    static String rate(int k, int n) {
        if (n == 0) return "n/a";
        return String.format(Locale.ROOT, "%.3f", (double) k / n);
    }

    static String wilson(int k, int n) {
        if (n == 0) return "n/a";
        double p = (double) k / n, z = 1.959963984540054;
        double den = 1 + z * z / n;
        double centre = (p + z * z / (2.0 * n)) / den;
        double margin = z * Math.sqrt(p * (1 - p) / n + z * z / (4.0 * n * n)) / den;
        return String.format(Locale.ROOT, "[%.3f, %.3f]", Math.max(0, centre - margin), Math.min(1, centre + margin));
    }

    static String[] split(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        boolean q = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (q) {
                if (c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') { sb.append('"'); i++; }
                else if (c == '"') q = false;
                else sb.append(c);
            } else if (c == '"') q = true;
            else if (c == ',') { out.add(sb.toString()); sb.setLength(0); }
            else sb.append(c);
        }
        out.add(sb.toString());
        return out.toArray(new String[0]);
    }

    static void deleteTree(Path dir) {
        try (var s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (Exception ignored) { }
            });
        } catch (Exception ignored) { }
    }
}
