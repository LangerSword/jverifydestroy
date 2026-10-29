package io.jvd.verify;

import java.util.Arrays;

/**
 * The victim process. It derives a target canary and a positive-control canary from a seed,
 * stores the control in a static field, performs the requested destruction on the target, and
 * waits for the parent to scan it.
 *
 * <p>Every temporary copy of a canary is wiped here. A helper that returns a digest copy without
 * wiping the digest output is a real leak (observed in the first H1 probe).</p>
 */
public final class CanaryVictim {
    public static final int TARGET_SIZE = 4096;
    public static final int CONTROL_SIZE = 512;
    public static final int CONTROL_OFFSET = 128;
    public static final int TARGET_OFFSET = 512;

    static byte[] CONTROL;
    static byte[] TARGET;

    public static void main(String[] args) throws Exception {
        byte[] seed = java.util.HexFormat.of().parseHex(args[0]);
        String mode = args[1];
        byte[] tc = Canary.derive(seed, "target");
        byte[] cc = Canary.derive(seed, "control");
        byte[] control = new byte[CONTROL_SIZE];
        System.arraycopy(cc, 0, control, CONTROL_OFFSET, Canary.LEN);
        CONTROL = control;
        Arrays.fill(cc, (byte) 0);
        byte[] target = new byte[TARGET_SIZE];
        System.arraycopy(tc, 0, target, TARGET_OFFSET, Canary.LEN);
        Arrays.fill(tc, (byte) 0);

        switch (mode) {
            case "KEEP" -> TARGET = target;
            case "WIPE" -> {
                Arrays.fill(target, (byte) 0);
                target = null;
            }
            case "WIPEGC" -> {
                Arrays.fill(target, (byte) 0);
                target = null;
                System.gc();
            }
            case "MOVE" -> {
                System.gc();
                Thread.sleep(20);
                Arrays.fill(target, (byte) 0);
                target = null;
                System.gc();
            }
            case "HOT" -> {
                for (int i = 0; i < 2_000_000; i++) Arrays.fill(target, (byte) 0);
                TARGET = target;
            }
            default -> throw new IllegalArgumentException("unknown mode " + mode);
        }
        System.out.println("READY " + ProcessHandle.current().pid());
        System.out.flush();
        System.in.read();
        Thread.sleep(50);
    }
}
