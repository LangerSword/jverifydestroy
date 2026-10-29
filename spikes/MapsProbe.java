import java.nio.file.*;
import java.util.*;

public class MapsProbe {
    static byte[] KEEP;
    public static void main(String[] a) throws Exception {
        byte[] x = new byte[1 << 20];
        Arrays.fill(x, (byte) 0xAB);
        KEEP = x;
        System.out.println("READY"); System.out.flush();
        for (String l : Files.readAllLines(Paths.get("/proc/self/maps"))) {
            String[] q = l.split("\\s+");
            if (q.length < 2 || !q[1].startsWith("rw")) continue;
            String[] r = q[0].split("-");
            long s = Long.parseUnsignedLong(r[0], 16), e = Long.parseUnsignedLong(r[1], 16);
            String path = q.length > 5 ? q[5] : "";
            System.out.printf("%08x-%08x %8dK %s%n", s, e, (e - s) / 1024,
                    path.isEmpty() ? "<anon>" : path);
        }
        Thread.sleep(3000);
    }
}
