package io.jvd.evidence;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.List;

/** Environment facts captured into every evidence record. */
public final class Env {
    public static final String TOOL = "jverifydestroy";
    public static final String VERSION = "1.0.0";

    private Env() {}

    public static String jvm() {
        return System.getProperty("java.vm.name") + " " + System.getProperty("java.vm.version")
                + " (" + System.getProperty("java.runtime.version") + ")";
    }

    public static String os() {
        return System.getProperty("os.name") + " " + System.getProperty("os.version")
                + " " + System.getProperty("os.arch");
    }

    public static String gc() {
        List<String> names = new ArrayList<>();
        for (GarbageCollectorMXBean b : ManagementFactory.getGarbageCollectorMXBeans()) names.add(b.getName());
        return String.join("+", names);
    }

    public static String jvmFlags() {
        return String.join(" ", ManagementFactory.getRuntimeMXBean().getInputArguments());
    }
}
