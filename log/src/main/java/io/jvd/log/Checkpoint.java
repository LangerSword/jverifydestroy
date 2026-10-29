package io.jvd.log;

import io.jvd.evidence.Ed25519;
import io.jvd.evidence.Json;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/** A signed RFC 9162 tree head, optionally cosigned by a witness. */
public final class Checkpoint {
    public String origin;
    public long size;
    public String rootHash;       // base64
    public String logSignature;   // base64, over logBytes()
    public String witnessName;
    public String witnessTimestamp;
    public String witnessSignature; // base64, over witnessBytes()

    public static Checkpoint create(String origin, long size, byte[] root, PrivateKey logKey) {
        Checkpoint c = new Checkpoint();
        c.origin = origin;
        c.size = size;
        c.rootHash = Base64.getEncoder().encodeToString(root);
        c.logSignature = Base64.getEncoder().encodeToString(Ed25519.sign(c.logBytes(), logKey));
        return c;
    }

    public byte[] root() {
        return Base64.getDecoder().decode(rootHash);
    }

    public byte[] logBytes() {
        return Json.writeBytes(Json.obj("origin", origin, "size", size, "rootHash", rootHash));
    }

    public byte[] witnessBytes() {
        return Json.writeBytes(Json.obj("origin", origin, "size", size, "rootHash", rootHash,
                "witnessName", witnessName, "witnessTimestamp", witnessTimestamp));
    }

    public boolean verifyLog(PublicKey key) {
        return logSignature != null
                && Ed25519.verify(logBytes(), Base64.getDecoder().decode(logSignature), key);
    }

    public void cosign(String name, PrivateKey witnessKey) {
        this.witnessName = name;
        this.witnessTimestamp = Instant.now().toString();
        this.witnessSignature = Base64.getEncoder().encodeToString(Ed25519.sign(witnessBytes(), witnessKey));
    }

    public boolean verifyWitness(PublicKey key) {
        return witnessSignature != null && witnessName != null
                && Ed25519.verify(witnessBytes(), Base64.getDecoder().decode(witnessSignature), key);
    }

    public String toJson() {
        return Json.write(toMap());
    }

    public Map<String, Object> toMap() {
        return Json.obj("origin", origin, "size", size, "rootHash", rootHash,
                "logSignature", logSignature, "witnessName", witnessName,
                "witnessTimestamp", witnessTimestamp, "witnessSignature", witnessSignature);
    }

    public static Checkpoint fromJson(String text) {
        return fromMap(Json.parseObject(text));
    }

    public static Checkpoint fromMap(Map<String, Object> m) {
        Checkpoint c = new Checkpoint();
        c.origin = str(m, "origin");
        c.size = Json.asLong(m.get("size"));
        c.rootHash = str(m, "rootHash");
        c.logSignature = str(m, "logSignature");
        c.witnessName = str(m, "witnessName");
        c.witnessTimestamp = str(m, "witnessTimestamp");
        c.witnessSignature = str(m, "witnessSignature");
        return c;
    }

    private static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? null : v.toString();
    }
}
