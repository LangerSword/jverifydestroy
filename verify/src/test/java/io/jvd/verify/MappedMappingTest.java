package io.jvd.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MappedMappingTest {
    @Test void namedFileMappingIsScanned(@TempDir Path dir) throws Exception {
        byte[] seed = Canary.newSeed();
        byte[] raw = Canary.derive(seed, "target");
        byte[] masked = Canary.mask(raw);
        Arrays.fill(raw, (byte) 0);
        List<String> cp = new ArrayList<>();
        for (String p : List.of("target/test-classes", "target/classes")) {
            Path abs = Path.of(p).toAbsolutePath().normalize();
            if (Files.isDirectory(abs)) cp.add(abs.toString());
        }
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-cp", String.join(File.pathSeparator, cp),
                "io.jvd.verify.MappedVictim", Canary.hex(seed)).redirectErrorStream(true).start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = br.readLine();
        assertNotNull(line, "victim did not start");
        long pid = Long.parseLong(line.split(" ")[1]);
        ScanResult r = MemoryScanner.scan(pid, masked);
        assertEquals(Verdict.FOUND, r.verdict(), r.toString());
        p.getOutputStream().write('\n');
        p.getOutputStream().flush();
        p.waitFor();
    }
}
