package io.jvd.txn;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class Kill9RecoveryTest {
    private static final String[] POINTS = {
            "STAGED", "VAULTED", "SCRUBBED", "VALIDATED", "COMMITTING",
            "KEY_DESTROYED", "CONFIRMED", "COMMITTED"
    };

    static Stream<Arguments> cases() {
        List<Arguments> out = new ArrayList<>();
        for (String point : POINTS) {
            out.add(Arguments.of(point, Method.CRYPTO_SHRED));
            out.add(Arguments.of(point, Method.OVERWRITE));
        }
        return out.stream();
    }

    private static String classpath() {
        List<String> parts = new ArrayList<>();
        for (String p : List.of("target/test-classes", "target/classes",
                "../verify/target/classes", "../evidence/target/classes",
                "../log/target/classes", "../destroy-file/target/classes",
                "../presenter/target/classes")) {
            Path abs = Path.of(p).toAbsolutePath().normalize();
            if (Files.isDirectory(abs)) parts.add(abs.toString());
        }
        return String.join(File.pathSeparator, parts);
    }

    @ParameterizedTest(name = "{0}/{1}")
    @MethodSource("cases")
    void killAtEveryPointRecoversHonestly(String point, Method method, @TempDir Path dir) throws Exception {
        Path target = dir.resolve("secret.txt");
        Path work = dir.resolve("work");
        byte[] plain = ("kill at " + point + "/" + method).getBytes();
        Files.write(target, plain);

        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-cp", classpath(), "io.jvd.txn.CrashChild",
                target.toString(), work.toString(), method.name(), point)
                .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        int code = p.waitFor();
        assertEquals(137, code, "child should halt at " + point + ": " + out);

        List<Recovery.Result> results = Recovery.recover(work);
        assertEquals(1, results.size(), results.toString());
        Recovery.Result r = results.get(0);

        if (point.equals("COMMITTED")) {
            assertEquals(State.COMMITTED, r.lastState());
            assertFalse(r.restored());
            assertFalse(Files.exists(target), "COMMITTED must not restore");
        } else if (point.equals("CONFIRMED")) {
            assertEquals(State.COMMITTED, r.lastState(), "CONFIRMED evidence must reconcile to COMMITTED");
            assertFalse(r.restored());
            assertFalse(Files.exists(target));
        } else if (point.equals("KEY_DESTROYED")) {
            assertEquals(State.UNRESOLVED, r.lastState(), "key destroyed without CONFIRMED is unresolved");
            assertFalse(r.restored());
            assertFalse(Files.exists(target));
        } else if (point.equals("STAGED") || point.equals("VAULTED")) {
            assertEquals(State.valueOf(point), r.lastState());
            assertFalse(r.restored());
            assertTrue(Files.exists(target), "original should be untouched");
            assertArrayEquals(plain, Files.readAllBytes(target));
        } else {
            assertEquals(State.valueOf(point), r.lastState());
            assertTrue(r.restored(), r.toString());
            assertTrue(Files.exists(target));
            assertArrayEquals(plain, Files.readAllBytes(target), "restored content must match");
        }
    }
}
