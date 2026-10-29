package io.jvd.verifycli;

import io.jvd.evidence.Ed25519;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;
import io.jvd.log.LogVerifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;

/**
 * Offline verifier. Exit codes: 0 valid, 1 invalid/tamper, 2 usage or I/O error.
 *
 * <pre>
 * jvd-verify --log log.jsonl --checkpoint latest.json --log-key log.pub
 *            [--witness-key witness.pub] [--evidence-key evidence.pub]
 *            [--old old-checkpoint.json] [--include SEQ]
 * </pre>
 */
public final class Main {
    public static void main(String[] args) {
        System.exit(run(args));
    }

    public static int run(String[] args) {
        try {
            String logPath = null, cpPath = null, logKeyPath = null, witnessKeyPath = null;
            String evidenceKeyPath = null, oldPath = null;
            Long include = null;
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--log" -> logPath = args[++i];
                    case "--checkpoint" -> cpPath = args[++i];
                    case "--log-key" -> logKeyPath = args[++i];
                    case "--witness-key" -> witnessKeyPath = args[++i];
                    case "--evidence-key" -> evidenceKeyPath = args[++i];
                    case "--old" -> oldPath = args[++i];
                    case "--include" -> include = Long.parseLong(args[++i]);
                    default -> {
                        System.err.println("unknown argument: " + args[i]);
                        return 2;
                    }
                }
            }
            if (logPath == null || cpPath == null || logKeyPath == null) {
                System.err.println("required: --log --checkpoint --log-key");
                return 2;
            }
            Path logFile = Path.of(logPath);
            Checkpoint cp = LogStore.readCheckpoint(Path.of(cpPath));
            PublicKey logKey = Ed25519.decodePublic(Files.readString(Path.of(logKeyPath)));
            PublicKey witnessKey = witnessKeyPath == null ? null
                    : Ed25519.decodePublic(Files.readString(Path.of(witnessKeyPath)));

            LogVerifier.Result r = LogVerifier.verify(logFile, cp, logKey, witnessKey);
            if (evidenceKeyPath != null) {
                PublicKey ev = Ed25519.decodePublic(Files.readString(Path.of(evidenceKeyPath)));
                LogVerifier.verifyRecordSignatures(LogVerifier.parse(logFile), ev, r);
            }
            if (oldPath != null) {
                Checkpoint old = LogStore.readCheckpoint(Path.of(oldPath));
                LogVerifier.Result c = LogVerifier.verifyConsistency(logFile, old, cp, logKey, witnessKey);
                if (!c.valid) {
                    r.valid = false;
                    r.errors.addAll(c.errors);
                }
            }
            if (include != null) {
                if (!LogVerifier.verifyInclusion(logFile, cp, include, logKey, witnessKey)) {
                    r.valid = false;
                    r.errors.add("inclusion proof failed for seq " + include);
                }
            }
            System.out.println(r.summary());
            return r.valid ? 0 : 1;
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            return 2;
        }
    }
}
