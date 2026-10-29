package io.jvd.memory;

/**
 * Demonstrates the String problem rather than pretending to solve it.
 *
 * <p>{@code String} is immutable, so there is no supported way to clear its backing array.
 * The value remains reachable until the collector decides otherwise, and may be interned.
 * Use {@code char[]}, {@code byte[]} (wiped with {@link HeapWipe}), or {@link SecretBuffer}.</p>
 */
public final class StringMisuseDemo {
    private StringMisuseDemo() {}

    public record Report(String valueAfterAttempt, boolean sameReference, String recommendation) {}

    public static Report run(String secret) {
        String held = secret;
        // There is deliberately no "wipe" call: String has none.
        return new Report(held, held == secret,
                "String cannot be wiped; use char[], byte[], or SecretBuffer and wipe explicitly");
    }
}
