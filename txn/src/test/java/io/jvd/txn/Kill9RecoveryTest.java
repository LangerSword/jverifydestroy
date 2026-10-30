package io.jvd.txn;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class Kill9RecoveryTest {
    private static String classpath() {
        List<String> parts = new ArrayList<>();
        for (String p : List.of("target/test-classes", "target/classes",
                "../verify/target/classes", "../evidence/target/classes",
                "../log/target/classes", "../destroy-file/target/classes")) {
            Path abs = Path.of(p).toAbsolutePath().normalize();
            if (Files.isDirectory(abs)) parts.add(abs.toString());
        }
        return String.join(File.pathSeparator, parts);
    }

    @ParameterizedTest
    @ValueSource(strings = {"STAGED", "VAULTED", "SCRUBBED", "VALIDATED", "COMMITTING", "COMMITTED"})
    void killAtEveryStateRecoversHonestly(String state, @TempDir Path dir) throws Exception {
        Path target = dir.resolve("secret.txt");
        Path work = dir.resolve("work");
        byte[] plain = ("kill at " + state).getBytes();
        Files.write(target, plain);

        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-cp", classpath(), "io.jvd.txn.CrashChild",
                target.toString(), work.toString(), Method.CRYPTO_SHRED.name(), state)
                .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        int code = p.waitFor();
        assertEquals(137, code, "child should halt at " + state + ": " + out);

        List<Recovery.Result> results = Recovery.recover(work);
        assertEquals(1, results.size(), results.toString());
        Recovery.Result r = results.get(0);
        assertEquals(State.valueOf(state), r.lastState());

        if (state.equals("COMMITTED")) {
            assertFalse(r.restored());
            assertFalse(Files.exists(target), "COMMITTED must not restore");
        } else if (state.equals("STAGED") || state.equals("VAULTED")) {
            assertFalse(r.restored());
            assertTrue(Files.exists(target), "original should be untouched");
            assertArrayEquals(plain, Files.readAllBytes(target));
        } else {
            assertTrue(r.restored(), r.toString());
            assertTrue(Files.exists(target));
            assertArrayEquals(plain, Files.readAllBytes(target), "restored content must match");
        }
    }
}
