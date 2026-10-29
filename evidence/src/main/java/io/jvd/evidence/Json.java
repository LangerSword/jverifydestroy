package io.jvd.evidence;

import java.util.*;

/**
 * Minimal JSON reader/writer. No external dependencies.
 *
 * <p>Writing is canonical: object keys are sorted, there is no insignificant whitespace, and
 * strings are UTF-8 with the standard short escapes. The same bytes are used for Ed25519
 * signatures and RFC 9162 leaves, so canonicalisation is part of the protocol, not a
 * formatting preference.</p>
 */
public final class Json {
    private Json() {}

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    public static byte[] writeBytes(Object value) {
        return write(value).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    public static Object parse(String text) {
        Parser p = new Parser(text);
        Object v = p.value();
        p.ws();
        if (!p.done()) throw new IllegalArgumentException("trailing JSON at " + p.pos);
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map<?, ?> m)) throw new IllegalArgumentException("not a JSON object");
        return (Map<String, Object>) m;
    }

    public static Map<String, Object> obj(Object... kv) {
        if (kv.length % 2 != 0) throw new IllegalArgumentException("obj needs key/value pairs");
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    public static List<Object> arr(Object... values) {
        return new ArrayList<>(Arrays.asList(values));
    }

    public static long asLong(Object v) {
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s) return Long.parseLong(s);
        throw new IllegalArgumentException("not a number: " + v);
    }

    public static boolean asBool(Object v) {
        if (v instanceof Boolean b) return b;
        throw new IllegalArgumentException("not a boolean: " + v);
    }

    public static String asString(Object v) {
        if (v == null) return null;
        if (v instanceof String s) return s;
        throw new IllegalArgumentException("not a string: " + v);
    }

    private static void writeValue(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String s) { writeString(sb, s); return; }
        if (v instanceof Boolean b) { sb.append(b); return; }
        if (v instanceof Byte || v instanceof Short || v instanceof Integer || v instanceof Long) {
            sb.append(((Number) v).longValue()); return;
        }
        if (v instanceof Float || v instanceof Double) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("non-finite number");
            sb.append(Double.toString(d)); return;
        }
        if (v instanceof Map<?, ?> m) {
            List<String> keys = new ArrayList<>();
            for (Object k : m.keySet()) {
                if (!(k instanceof String)) throw new IllegalArgumentException("non-string key");
                keys.add((String) k);
            }
            Collections.sort(keys);
            sb.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, k);
                sb.append(':');
                writeValue(sb, m.get(k));
            }
            sb.append('}');
            return;
        }
        if (v instanceof List<?> list) {
            sb.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(',');
                writeValue(sb, list.get(i));
            }
            sb.append(']');
            return;
        }
        throw new IllegalArgumentException("unsupported JSON value: " + v.getClass());
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) { this.s = s; }

        boolean done() { return pos >= s.length(); }

        void ws() { while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++; }

        Object value() {
            ws();
            if (done()) throw new IllegalArgumentException("unexpected end of JSON");
            char c = s.charAt(pos);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object() {
            expect('{');
            Map<String, Object> m = new LinkedHashMap<>();
            ws();
            if (peek('}')) { pos++; return m; }
            while (true) {
                ws();
                String k = string();
                ws(); expect(':');
                m.put(k, value());
                ws();
                if (peek(',')) { pos++; continue; }
                expect('}');
                return m;
            }
        }

        private List<Object> array() {
            expect('[');
            List<Object> l = new ArrayList<>();
            ws();
            if (peek(']')) { pos++; return l; }
            while (true) {
                l.add(value());
                ws();
                if (peek(',')) { pos++; continue; }
                expect(']');
                return l;
            }
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c != '\\') { sb.append(c); continue; }
                if (pos >= s.length()) throw new IllegalArgumentException("bad escape");
                char e = s.charAt(pos++);
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > s.length()) throw new IllegalArgumentException("bad unicode escape");
                        sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        pos += 4;
                    }
                    default -> throw new IllegalArgumentException("bad escape \\" + e);
                }
            }
            throw new IllegalArgumentException("unterminated string");
        }

        private Object number() {
            int start = pos;
            if (peek('-')) pos++;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
            boolean fp = false;
            if (peek('.')) { fp = true; pos++; while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++; }
            if (peek('e') || peek('E')) {
                fp = true; pos++;
                if (peek('+') || peek('-')) pos++;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
            }
            String n = s.substring(start, pos);
            if (n.isEmpty() || n.equals("-")) throw new IllegalArgumentException("bad number at " + start);
            return fp ? (Object) Double.valueOf(n) : (Object) Long.valueOf(n);
        }

        private Object literal(String lit, Object v) {
            if (!s.startsWith(lit, pos)) throw new IllegalArgumentException("bad literal at " + pos);
            pos += lit.length();
            return v;
        }

        private boolean peek(char c) { return pos < s.length() && s.charAt(pos) == c; }

        private void expect(char c) {
            if (!peek(c)) throw new IllegalArgumentException("expected '" + c + "' at " + pos);
            pos++;
        }
    }
}
