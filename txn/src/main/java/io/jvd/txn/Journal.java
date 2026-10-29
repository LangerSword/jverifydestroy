package io.jvd.txn;

import io.jvd.evidence.Json;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/**
 * Write-ahead journal: one JSON line per event, fsynced before the corresponding side effect.
 * Recovery reads the last event and decides whether to restore or to leave the transaction
 * alone. The journal never contains key bytes.
 */
public final class Journal {
    public record Event(long seq, State state, String timestamp, Map<String, Object> detail) {}

    private final Path file;
    private final List<Event> events = new ArrayList<>();

    public Journal(Path file) throws IOException {
        this.file = file;
        Files.createDirectories(file.toAbsolutePath().getParent());
        if (Files.exists(file)) {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) events.add(parse(line));
            }
        }
    }

    public Path file() { return file; }

    public List<Event> events() { return List.copyOf(events); }

    public State lastState() {
        return events.isEmpty() ? null : events.get(events.size() - 1).state();
    }

    public Event append(State state, Map<String, Object> detail) throws IOException {
        Event e = new Event(events.size(), state, Instant.now().toString(), detail == null ? Map.of() : detail);
        String line = Json.write(Json.obj("seq", e.seq(), "state", state.name(),
                "timestamp", e.timestamp(), "detail", e.detail()));
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ch.write(ByteBuffer.wrap((line + "\n").getBytes(StandardCharsets.UTF_8)));
            ch.force(true);
        }
        events.add(e);
        return e;
    }

    @SuppressWarnings("unchecked")
    private static Event parse(String line) {
        Map<String, Object> m = Json.parseObject(line);
        return new Event(Json.asLong(m.get("seq")), State.valueOf(String.valueOf(m.get("state"))),
                String.valueOf(m.get("timestamp")), (Map<String, Object>) m.getOrDefault("detail", Map.of()));
    }

    public static Journal open(Path workDir, String txnId) throws IOException {
        return new Journal(workDir.resolve("journal").resolve(txnId + ".jsonl"));
    }
}
