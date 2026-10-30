package io.jvd.log;

import io.jvd.evidence.EvidenceRecord;
import io.jvd.evidence.Json;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Append-only JSONL log. Each line is {seq, leaf, record}; the leaf is RFC 9162 leaf hash. */
public final class LogStore {
    public static final class Entry {
        public final long seq;
        public final byte[] leaf;
        public final Map<String, Object> record;
        public final String recordJson;

        Entry(long seq, byte[] leaf, Map<String, Object> record, String recordJson) {
            this.seq = seq;
            this.leaf = leaf;
            this.record = record;
            this.recordJson = recordJson;
        }
    }

    private static final ConcurrentHashMap<String, Object> JVM_LOCKS = new ConcurrentHashMap<>();

    private final Path dir;
    private final Path logFile;
    private final Path lockFile;
    private final Object jvmLock;
    private final String origin;
    private final List<Entry> entries = new ArrayList<>();

    public LogStore(Path dir, String origin) throws IOException {
        this.dir = dir;
        this.origin = origin;
        Files.createDirectories(dir);
        this.logFile = dir.resolve("log.jsonl");
        this.lockFile = dir.resolve("log.lock");
        this.jvmLock = JVM_LOCKS.computeIfAbsent(lockFile.toAbsolutePath().normalize().toString(),
                k -> new Object());
        if (Files.exists(logFile)) load();
    }

    private void load() throws IOException {
        entries.clear();
        if (!Files.exists(logFile)) return;
        long expected = 0;
        for (String line : Files.readAllLines(logFile, StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            Map<String, Object> m = Json.parseObject(line);
            long seq = Json.asLong(m.get("seq"));
            if (seq != expected) throw new IllegalStateException("log gap at " + seq + ", expected " + expected);
            @SuppressWarnings("unchecked")
            Map<String, Object> record = (Map<String, Object>) m.get("record");
            String recordJson = Json.write(record);
            byte[] leaf = Merkle.leafHash(recordJson.getBytes(StandardCharsets.UTF_8));
            String stored = String.valueOf(m.get("leaf"));
            if (!Base64.getEncoder().encodeToString(leaf).equals(stored)) {
                throw new IllegalStateException("leaf mismatch at " + seq);
            }
            entries.add(new Entry(seq, leaf, record, recordJson));
            expected++;
        }
    }

    public Path logFile() { return logFile; }

    public String origin() { return origin; }

    public int size() { return entries.size(); }

    public List<Entry> entries() { return List.copyOf(entries); }

    public List<byte[]> leaves() {
        List<byte[]> out = new ArrayList<>(entries.size());
        for (Entry e : entries) out.add(e.leaf);
        return out;
    }

    public byte[] root() { return Merkle.rootOfHashes(leaves()); }

    public Entry append(EvidenceRecord record) throws IOException {
        synchronized (jvmLock) {
            try (FileChannel lockCh = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE);
                 FileLock ignored = lockCh.lock()) {
                // Another process may have appended since this instance loaded. Re-read the
                // tail under the file lock so seq is unique and contiguous.
                load();
                String recordJson = record.toJson();
                byte[] leaf = Merkle.leafHash(recordJson.getBytes(StandardCharsets.UTF_8));
                long seq = entries.size();
                String line = Json.write(Json.obj("seq", seq,
                        "leaf", Base64.getEncoder().encodeToString(leaf),
                        "record", record.toMap(true)));
                try (FileChannel ch = FileChannel.open(logFile, StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
                    ch.write(ByteBuffer.wrap((line + "\n").getBytes(StandardCharsets.UTF_8)));
                    ch.force(true);
                }
                Entry e = new Entry(seq, leaf, record.toMap(true), recordJson);
                entries.add(e);
                return e;
            }
        }
    }

    public Checkpoint checkpoint(PrivateKey logKey) {
        return Checkpoint.create(origin, entries.size(), root(), logKey);
    }

    public static void writeCheckpoint(Path file, Checkpoint checkpoint) throws IOException {
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.writeString(file, checkpoint.toJson() + "\n", StandardCharsets.UTF_8);
    }

    public static Checkpoint readCheckpoint(Path file) throws IOException {
        return Checkpoint.fromJson(Files.readString(file));
    }
}
