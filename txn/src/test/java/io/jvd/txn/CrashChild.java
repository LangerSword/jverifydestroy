package io.jvd.txn;

import io.jvd.evidence.Ed25519;
import io.jvd.log.LogStore;
import io.jvd.log.Witness;

import java.nio.file.Path;
import java.security.KeyPair;

/** Test-only child: runs a transaction and halts (SIGKILL-like) at a named state. */
public final class CrashChild {
    public static void main(String[] args) throws Exception {
        Path target = Path.of(args[0]);
        Path work = Path.of(args[1]);
        Method method = Method.valueOf(args[2]);
        String crashAt = args[3];
        System.setProperty("jvd.crashAt", crashAt);

        KeyPair ev = Ed25519.generate();
        KeyPair lk = Ed25519.generate();
        KeyPair wk = Ed25519.generate();
        LogStore log = new LogStore(work.resolve("log"), "jvd.local/crash");
        Witness witness = new Witness("w1", wk.getPrivate(), wk.getPublic());
        TxnConfig cfg = new TxnConfig(target, method, work, null, null, 0, true);
        new DestructionTransaction(cfg, ev, log, lk.getPrivate(), witness).run();
    }
}
