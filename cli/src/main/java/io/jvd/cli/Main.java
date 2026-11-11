package io.jvd.cli;

import io.jvd.evidence.Ed25519;
import io.jvd.evidence.Json;
import io.jvd.file.FileDestroyer;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;
import io.jvd.log.LogVerifier;
import io.jvd.log.Witness;
import io.jvd.memory.SecretBuffer;
import io.jvd.txn.*;
import io.jvd.presenter.Presenter;
import io.jvd.presenter.UserMessage;
import io.jvd.verify.Canary;
import io.jvd.verify.CanaryVerifier;
import io.jvd.verify.Mode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/** jvd: the user-facing CLI. */
public final class Main {
    public static void main(String[] args) {
        System.exit(run(args));
    }

    public static int run(String[] args) {
        if (args.length == 0) return usage();
        try {
            return switch (args[0]) {
                case "version" -> version();
                case "mem" -> mem();
                case "file" -> file(args);
                case "shred" -> txn(args, true);
                case "txn" -> txn(args, false);
                case "verify" -> verify(args);
                case "recover" -> recover(args);
                case "explain" -> explain(args);
                case "selftest" -> selftest();
                default -> usage();
            };
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            return 2;
        }
    }

    /**
     * Prints the version.
     *
     * <p>A released tool has to be able to say which version it is. A user reads that
     * line and puts it in a bug report; a hosting site reads it to decide which
     * artifact to offer; and a support question about "is this the version with the
     * fix" is unanswerable without it.
     *
     * <p>The version comes from the manifest of the jar the code is running in, so it
     * cannot drift from the build. When the classes are run from a directory rather
     * than a jar, there is no manifest, and the build version is reported instead.
     */
    private static int version() {
        String v = versionFromManifest();
        System.out.println("jvd " + v);
        System.out.println("jvm  " + System.getProperty("java.vm.name") + " "
                + System.getProperty("java.version"));
        System.out.println("os   " + System.getProperty("os.name") + " "
                + System.getProperty("os.arch"));
        return 0;
    }

    /** The implementation version, read from the jar manifest when there is one. */
    private static String versionFromManifest() {
        try {
            var pkg = Main.class.getPackage();
            if (pkg != null) {
                String v = pkg.getImplementationVersion();
                if (v != null && !v.isBlank()) return v;
            }
        } catch (RuntimeException ignored) {
            // Fall through to the build version.
        }
        return io.jvd.evidence.Env.VERSION;
    }

    private static int usage() {
        System.err.println("""
                jvd commands:
                  version
                  mem
                  file <path> [--passes N] [--delete-only] [--keep]
                  shred <path> [--work DIR] [--details]
                  txn <path> [--mode overwrite|crypto] [--work DIR] [--image RAW]
                             [--canary HEX] [--grace MS] [--require-checkable] [--details]
                  verify [--work DIR]
                  recover [--work DIR]
                  explain [--work DIR]
                  selftest
                """);
        return 2;
    }

    private static int mem() {
        try (SecretBuffer b = new SecretBuffer(32)) {
            b.put("demo secret".getBytes());
            System.out.println("lock=" + b.lockResult());
            b.wipe();
            byte[] after = b.get();
            int zeros = 0;
            for (byte x : after) if (x == 0) zeros++;
            System.out.println("wiped " + zeros + "/" + after.length + " bytes");
            java.util.Arrays.fill(after, (byte) 0);
            System.out.println("note: a JVM helper or the collector may retain copies; this is best effort");
            return zeros == after.length ? 0 : 1;
        }
    }

    private static int file(String[] args) throws Exception {
        Opts o = Opts.parse(args);
        if (o.pos.isEmpty()) return usage();
        Path p = Path.of(o.pos.get(0));
        FileDestroyer.Result r;
        if (o.flags.contains("--delete-only")) {
            r = FileDestroyer.deleteOnly(p);
        } else {
            int passes = Integer.parseInt(o.val("--passes", "1"));
            r = FileDestroyer.destroy(p, passes, !o.flags.contains("--keep"));
        }
        System.out.println("bytes=" + r.bytes() + " passes=" + r.passes() + " deleted=" + r.deleted()
                + " ms=" + r.elapsedMillis());
        System.out.println(r.note());
        // The exit code has to reflect what happened, not what was asked for. A file that
        // was overwritten but could not be unlinked is not a successful destruction, and
        // a script that checks the exit code would otherwise believe it was.
        if (!r.deleted() && !o.flags.contains("--keep")) {
            System.err.println("error: the file was overwritten but could not be removed; "
                    + "it is still at " + p);
            return 1;
        }
        return 0;
    }

    private static int txn(String[] args) throws Exception {
        return txn(args, false);
    }

    private static int txn(String[] args, boolean friendly) throws Exception {
        Opts o = Opts.parse(args);
        if (o.pos.isEmpty()) return usage();
        Path target = Path.of(o.pos.get(0)).toAbsolutePath();
        Path work = Path.of(o.val("--work", ".jvd-work")).toAbsolutePath();
        Method method = "overwrite".equals(o.val("--mode", "crypto")) ? Method.OVERWRITE : Method.CRYPTO_SHRED;
        Path image = o.vals.containsKey("--image") ? Path.of(o.vals.get("--image")) : null;
        long grace = Long.parseLong(o.val("--grace", "0"));
        boolean require = o.flags.contains("--require-checkable");

        byte[] masked = null;
        if (o.vals.containsKey("--canary")) {
            byte[] raw = HexFormat.of().parseHex(o.vals.get("--canary"));
            masked = Canary.mask(raw);
            Arrays.fill(raw, (byte) 0);
        }
        TxnConfig cfg = new TxnConfig(target, method, work, image, masked, grace, !require);
        Keys keys = Keys.loadOrCreate(work);
        LogStore log = new LogStore(work.resolve("log"), "jvd.local/cli");
        Witness witness = new Witness("local-witness", keys.witness().getPrivate(), keys.witness().getPublic());
        DestructionTransaction t = new DestructionTransaction(cfg, keys.evidence(), log,
                keys.log().getPrivate(), witness);
        DestructionTransaction.Outcome out = t.run();
        if (friendly) {
            UserMessage msg = Presenter.present(ResultMapper.toResult(out));
            System.out.println(msg.sentence());
            if (o.flags.contains("--details")) {
                System.out.println();
                System.out.println(msg.details());
            }
        } else {
            System.out.println("state=" + out.state() + " txn=" + out.txnId());
            System.out.println("validation=" + out.validation().result() + " dataAbsent="
                    + out.validation().dataAbsent() + " restored=" + out.restored());
            System.out.println("checks=" + out.validation().checks());
            System.out.println("assurance=" + out.record().assurance + " (" + out.record().assurance.description() + ")");
            System.out.println("journal=" + t.journalFile());
            System.out.println("checkpoint=" + work.resolve("checkpoints").resolve("latest.json"));
            System.out.println("detail=" + out.detail());
        }
        return out.state() == State.COMMITTED ? 0 : 1;
    }

    private static int explain(String[] args) throws Exception {
        Opts o = Opts.parse(args);
        Path work = Path.of(o.val("--work", ".jvd-work")).toAbsolutePath();
        Path logFile = work.resolve("log").resolve("log.jsonl");
        if (!Files.exists(logFile)) {
            System.err.println("no log under " + work);
            return 2;
        }
        var lines = Files.readAllLines(logFile);
        if (lines.isEmpty()) {
            System.err.println("empty log under " + work);
            return 2;
        }
        var line = io.jvd.evidence.Json.parseObject(lines.get(lines.size() - 1));
        @SuppressWarnings("unchecked")
        var recordMap = (java.util.Map<String, Object>) line.get("record");
        var r = io.jvd.evidence.EvidenceRecord.fromJson(io.jvd.evidence.Json.write(recordMap));
        System.out.println("event=" + r.eventType + " id=" + r.eventId);
        System.out.println("method=" + r.method + " technique=" + r.technique);
        System.out.println("operation=" + r.verification.status + " completed=" + r.verification.operationCompleted);
        System.out.println("validation=" + r.validation.result + " dataAbsent=" + r.validation.dataAbsent);
        System.out.println("assurance=" + r.assurance + " (" + r.assurance.description() + ")");
        System.out.println("residualRisk=" + r.residualRisk);
        System.out.println();
        System.out.println(r.toJson());
        return 0;
    }

    private static int verify(String[] args) throws Exception {
        Opts o = Opts.parse(args);
        Path work = Path.of(o.val("--work", ".jvd-work")).toAbsolutePath();
        Path logFile = work.resolve("log").resolve("log.jsonl");
        Path cpFile = work.resolve("checkpoints").resolve("latest.json");
        if (!Files.exists(logFile) || !Files.exists(cpFile)) {
            System.err.println("no log or checkpoint under " + work);
            return 2;
        }
        Checkpoint cp = LogStore.readCheckpoint(cpFile);
        Keys keys = Keys.loadOrCreate(work);
        LogVerifier.Result r = LogVerifier.verify(logFile, cp, keys.log().getPublic(),
                keys.witness().getPublic());
        LogVerifier.verifyRecordSignatures(LogVerifier.parse(logFile), keys.evidence().getPublic(), r);
        System.out.println(r.summary());
        return r.valid ? 0 : 1;
    }

    private static int recover(String[] args) throws Exception {
        Opts o = Opts.parse(args);
        Path work = Path.of(o.val("--work", ".jvd-work")).toAbsolutePath();
        List<Recovery.Result> rs = Recovery.recover(work);
        if (rs.isEmpty()) {
            System.out.println("nothing to recover under " + work);
            return 0;
        }
        for (Recovery.Result r : rs) {
            System.out.println(r.txnId() + " last=" + r.lastState() + " action=" + r.action()
                    + " restored=" + r.restored() + " " + r.detail());
        }
        return 0;
    }

    private static int selftest() {
        var r = CanaryVerifier.validate(Mode.WIPE, "G1");
        System.out.println("result=" + r.result() + " checks=" + r.checks());
        return r.passed() ? 0 : 1;
    }

    record Opts(List<String> pos, Map<String, String> vals, Set<String> flags) {
        static Opts parse(String[] args) {
            List<String> pos = new ArrayList<>();
            Map<String, String> vals = new LinkedHashMap<>();
            Set<String> flags = new LinkedHashSet<>();
            for (int i = 1; i < args.length; i++) {
                String a = args[i];
                if (a.startsWith("--")) {
                    int eq = a.indexOf('=');
                    if (eq > 0) {
                        vals.put(a.substring(0, eq), a.substring(eq + 1));
                    } else if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                        vals.put(a, args[++i]);
                    } else {
                        flags.add(a);
                    }
                } else {
                    pos.add(a);
                }
            }
            return new Opts(pos, vals, flags);
        }

        String val(String k, String def) { return vals.getOrDefault(k, def); }
    }
}
