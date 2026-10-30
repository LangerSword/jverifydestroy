import io.jvd.file.CryptoShredder;
import java.nio.file.*;
import java.util.*;

/** F8 probe: decrypt a large GCM container in a small heap. */
public class CryptoMemProbe {
    public static void main(String[] a) throws Exception {
        int mb = Integer.parseInt(a.length > 0 ? a[0] : "128");
        Path dir = Files.createTempDirectory("jvd-gcm-");
        Path src = dir.resolve("plain.bin");
        Path cont = dir.resolve("c.jvd");
        Path key = dir.resolve("c.key");
        Path out = dir.resolve("out.bin");
        byte[] chunk = new byte[1 << 20];
        new Random(1).nextBytes(chunk);
        try (var os = Files.newOutputStream(src)) {
            for (int i = 0; i < mb; i++) os.write(chunk);
        }
        CryptoShredder.encrypt(src, cont, key);
        byte[] k = java.nio.file.Files.readAllBytes(key);
        System.out.println("encrypted " + mb + "MiB, heap=" + Runtime.getRuntime().maxMemory() / (1 << 20) + "MiB");
        try {
            CryptoShredder.decrypt(cont, out, k);
            System.out.println("decrypt OK size=" + Files.size(out));
        } catch (OutOfMemoryError e) {
            System.out.println("OOM: " + e.getMessage());
        } finally {
            Arrays.fill(k, (byte) 0);
        }
        try (var s = Files.walk(dir)) { s.sorted(Comparator.reverseOrder()).forEach(p -> { try { Files.deleteIfExists(p); } catch (Exception ignored) {} }); }
    }
}
