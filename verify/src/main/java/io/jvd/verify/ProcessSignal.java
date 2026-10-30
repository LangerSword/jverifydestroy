package io.jvd.verify;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * Linux SIGSTOP/SIGCONT for a consistent scanner snapshot. Java has no public ProcessHandle
 * signal API, so this uses a small libc downcall. On non-Linux or when the symbol is absent,
 * the methods return false and the caller must report the missing capability.
 */
public final class ProcessSignal {
    private static final int SIGCONT = 18;
    private static final int SIGSTOP = 19;

    private ProcessSignal() {}

    public static boolean stop(long pid) { return signal(pid, SIGSTOP); }

    public static boolean resume(long pid) { return signal(pid, SIGCONT); }

    private static boolean signal(long pid, int sig) {
        try {
            Linker linker = Linker.nativeLinker();
            MethodHandle kill = linker.downcallHandle(
                    linker.defaultLookup().find("kill").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
            int rc = (int) kill.invokeExact((int) pid, sig);
            return rc == 0;
        } catch (Throwable t) {
            return false;
        }
    }
}
