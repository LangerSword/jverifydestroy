package io.jvd.ui;

import io.jvd.evidence.Ed25519;
import io.jvd.evidence.EvidenceRecord;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;
import io.jvd.log.LogVerifier;
import io.jvd.log.Witness;
import io.jvd.txn.*;
import io.jvd.verify.Canary;
import io.jvd.verify.CanaryVerifier;
import io.jvd.verify.Mode;
import io.jvd.verify.ValidationResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/** UI-facing facade over the transaction, evidence, log, and verification services. */
public final class AppService {
    public record DestroyView(String state, String validation, boolean dataAbsent, boolean restored,
                              String assurance, List<String> checks, String journal, String checkpoint,
                              String evidenceJson, String detail) {}

    public record VerifyView(boolean valid, String summary, List<String> errors) {}

    public record RecoverView(List<String> lines) {}

    public record SelfTestView(String result, List<String> checks) {}

    private AppService() {}

    public static DestroyView destroy(Path target, Method method, Path work, Path image,
                                      String canaryHex, long grace, boolean requireCheckable) throws Exception {
        Path workAbs = work.toAbsolutePath().normalize();
        Keys keys = Keys.loadOrCreate(workAbs);
        LogStore log = new LogStore(workAbs.resolve("log"), "jvd.local/ui");
        Witness witness = new Witness("local-witness", keys.witness().getPrivate(), keys.witness().getPublic());
        byte[] masked = null;
        try {
            if (canaryHex != null && !canaryHex.isBlank()) {
                byte[] raw = HexFormat.of().parseHex(canaryHex.trim());
                masked = Canary.mask(raw);
                Arrays.fill(raw, (byte) 0);
            }
            TxnConfig cfg = new TxnConfig(target, method, workAbs, image, masked, grace, !requireCheckable);
            DestructionTransaction txn = new DestructionTransaction(cfg, keys.evidence(), log,
                    keys.log().getPrivate(), witness);
            DestructionTransaction.Outcome out = txn.run();
            String evidence = out.record() == null ? "" : out.record().toJson();
            return new DestroyView(out.state().name(),
                    out.validation() == null ? "NOT_RUN" : out.validation().result(),
                    out.validation() != null && out.validation().dataAbsent(),
                    out.restored(),
                    out.record() == null ? "A0" : out.record().assurance.name(),
                    out.validation() == null ? List.of() : out.validation().checks(),
                    txn.journalFile() == null ? "" : txn.journalFile().toString(),
                    workAbs.resolve("checkpoints").resolve("latest.json").toString(),
                    evidence, out.detail());
        } finally {
            if (masked != null) Arrays.fill(masked, (byte) 0);
        }
    }

    public static VerifyView verify(Path work) throws Exception {
        Path workAbs = work.toAbsolutePath().normalize();
        Path logFile = workAbs.resolve("log").resolve("log.jsonl");
        Path cpFile = workAbs.resolve("checkpoints").resolve("latest.json");
        if (!Files.exists(logFile) || !Files.exists(cpFile)) {
            return new VerifyView(false, "no log or checkpoint under " + workAbs, List.of("missing log/checkpoint"));
        }
        Keys keys = Keys.load(workAbs);
        Checkpoint cp = LogStore.readCheckpoint(cpFile);
        LogVerifier.Result r = LogVerifier.verify(logFile, cp, keys.log().getPublic(), keys.witness().getPublic());
        LogVerifier.verifyRecordSignatures(LogVerifier.parse(logFile), keys.evidence().getPublic(), r);
        return new VerifyView(r.valid, r.summary(), new ArrayList<>(r.errors));
    }

    public static RecoverView recover(Path work) throws Exception {
        List<String> lines = new ArrayList<>();
        for (Recovery.Result r : Recovery.recover(work.toAbsolutePath().normalize())) {
            lines.add(r.txnId() + "  last=" + r.lastState() + "  action=" + r.action()
                    + "  restored=" + r.restored() + (r.detail().isBlank() ? "" : "  " + r.detail()));
        }
        if (lines.isEmpty()) lines.add("nothing to recover under " + work.toAbsolutePath());
        return new RecoverView(lines);
    }

    public static SelfTestView selfTest() {
        ValidationResult r = CanaryVerifier.validate(Mode.WIPE, "G1");
        return new SelfTestView(r.result(), r.checks());
    }

    private record Keys(KeyPair evidence, KeyPair log, KeyPair witness) {
        static Keys loadOrCreate(Path work) throws Exception {
            Path dir = work.resolve("keys");
            return new Keys(pair(dir.resolve("evidence.key"), dir.resolve("evidence.key.pub")),
                    pair(dir.resolve("log.key"), dir.resolve("log.key.pub")),
                    pair(dir.resolve("witness.key"), dir.resolve("witness.key.pub")));
        }

        static Keys load(Path work) throws Exception {
            Path dir = work.resolve("keys");
            return new Keys(read(dir.resolve("evidence.key"), dir.resolve("evidence.key.pub")),
                    read(dir.resolve("log.key"), dir.resolve("log.key.pub")),
                    read(dir.resolve("witness.key"), dir.resolve("witness.key.pub")));
        }

        private static KeyPair pair(Path priv, Path pub) throws Exception {
            if (Files.exists(priv) && Files.exists(pub)) return read(priv, pub);
            KeyPair kp = Ed25519.generate();
            Ed25519.writeKey(priv, kp.getPrivate());
            Ed25519.writeKey(pub, kp.getPublic());
            return kp;
        }

        private static KeyPair read(Path priv, Path pub) throws Exception {
            if (!Files.exists(priv) || !Files.exists(pub)) {
                throw new IllegalStateException("missing key files under " + priv.getParent());
            }
            return new KeyPair(Ed25519.decodePublic(Files.readString(pub)),
                    Ed25519.decodePrivate(Files.readString(priv)));
        }
    }
}
