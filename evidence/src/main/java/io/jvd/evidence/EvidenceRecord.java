package io.jvd.evidence;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

/**
 * A signed destruction evidence record.
 *
 * <p>Verification (NIST SP 800-88r2 §4.5.1) and validation (§4.5.2) are deliberately separate
 * objects. A record with verification=PASS and validation=NOT_CHECKABLE is a valid and honest
 * record; it is not a claim that the data is gone.</p>
 */
public final class EvidenceRecord {
    public String schemaVersion = "1";
    public String eventId = UUID.randomUUID().toString();
    public String timestamp = Instant.now().toString();
    public String subjectHash;
    public String subjectSalt;
    public String subjectLabel;
    public String method;          // CLEAR, PURGE, DESTROY (NIST terms)
    public String technique;       // OVERWRITE, CRYPTO_ERASE, MEMORY_WIPE, DELETE
    public String tool = Env.TOOL;
    public String toolVersion = Env.VERSION;
    public String jvm = Env.jvm();
    public String os = Env.os();
    public String gc = Env.gc();
    public String jvmFlags = Env.jvmFlags();
    public Verification verification = new Verification();
    public Validation validation = new Validation();
    public String residualRisk = "user-space Java cannot verify physical flash, FTL remapping, "
            + "controller-held copies, backups, snapshots, or copies made before this tool ran";
    public AssuranceLevel assurance = AssuranceLevel.A0;
    public String signature;

    public static EvidenceRecord create(String subject, String method, String technique) {
        EvidenceRecord r = new EvidenceRecord();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        r.subjectSalt = Base64.getEncoder().encodeToString(salt);
        r.subjectHash = hashSubject(subject, salt);
        r.subjectLabel = subject;
        r.method = method;
        r.technique = technique;
        return r;
    }

    public static String hashSubject(String subject, byte[] salt) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(salt);
            md.update((byte) 0);
            md.update(subject.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(md.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public Map<String, Object> toMap(boolean withSignature) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("schemaVersion", schemaVersion);
        m.put("eventId", eventId);
        m.put("timestamp", timestamp);
        m.put("subjectHash", subjectHash);
        m.put("subjectSalt", subjectSalt);
        m.put("subjectLabel", subjectLabel);
        m.put("method", method);
        m.put("technique", technique);
        m.put("tool", tool);
        m.put("toolVersion", toolVersion);
        m.put("jvm", jvm);
        m.put("os", os);
        m.put("gc", gc);
        m.put("jvmFlags", jvmFlags);
        m.put("verification", verification.toMap());
        m.put("validation", validation.toMap());
        m.put("residualRisk", residualRisk);
        m.put("assurance", assurance.name());
        if (withSignature) m.put("signature", signature);
        return m;
    }

    public byte[] signedBytes() {
        return Json.writeBytes(toMap(false));
    }

    public String toJson() {
        return Json.write(toMap(true));
    }

    public void sign(PrivateKey key) {
        signature = Base64.getEncoder().encodeToString(Ed25519.sign(signedBytes(), key));
    }

    public boolean verifySignature(PublicKey key) {
        if (signature == null) return false;
        try {
            return Ed25519.verify(signedBytes(), Base64.getDecoder().decode(signature), key);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public static EvidenceRecord fromJson(String text) {
        Map<String, Object> m = Json.parseObject(text);
        EvidenceRecord r = new EvidenceRecord();
        r.schemaVersion = str(m, "schemaVersion", "1");
        r.eventId = str(m, "eventId", null);
        r.timestamp = str(m, "timestamp", null);
        r.subjectHash = str(m, "subjectHash", null);
        r.subjectSalt = str(m, "subjectSalt", null);
        r.subjectLabel = str(m, "subjectLabel", null);
        r.method = str(m, "method", null);
        r.technique = str(m, "technique", null);
        r.tool = str(m, "tool", Env.TOOL);
        r.toolVersion = str(m, "toolVersion", Env.VERSION);
        r.jvm = str(m, "jvm", null);
        r.os = str(m, "os", null);
        r.gc = str(m, "gc", null);
        r.jvmFlags = str(m, "jvmFlags", null);
        Object v = m.get("verification");
        if (v instanceof Map<?, ?> vm) r.verification = Verification.fromMap((Map<String, Object>) vm);
        Object val = m.get("validation");
        if (val instanceof Map<?, ?> vm) r.validation = Validation.fromMap((Map<String, Object>) vm);
        r.residualRisk = str(m, "residualRisk", null);
        r.assurance = AssuranceLevel.valueOf(str(m, "assurance", "A0"));
        r.signature = str(m, "signature", null);
        return r;
    }

    private static String str(Map<String, Object> m, String k, String def) {
        Object v = m.get(k);
        return v == null ? def : v.toString();
    }

    public static final class Verification {
        public boolean operationCompleted;
        public String status = "NOT_RUN";
        public List<String> notes = new ArrayList<>();

        public Map<String, Object> toMap() {
            return Json.obj("operationCompleted", operationCompleted, "status", status, "notes", notes);
        }

        @SuppressWarnings("unchecked")
        public static Verification fromMap(Map<String, Object> m) {
            Verification v = new Verification();
            v.operationCompleted = Json.asBool(m.getOrDefault("operationCompleted", false));
            v.status = str(m, "status", "NOT_RUN");
            Object n = m.get("notes");
            if (n instanceof List<?> l) for (Object o : l) v.notes.add(String.valueOf(o));
            return v;
        }
    }

    public static final class Validation {
        public String result = "NOT_CHECKABLE"; // PASS, FAIL, NOT_CHECKABLE, INVALID
        public boolean dataAbsent;
        public List<String> checks = new ArrayList<>();
        public Control positive = new Control("positive");
        public Control negative = new Control("negative");
        public String reason;

        public Map<String, Object> toMap() {
            return Json.obj("result", result, "dataAbsent", dataAbsent, "checks", checks,
                    "positive", positive.toMap(), "negative", negative.toMap(), "reason", reason);
        }

        @SuppressWarnings("unchecked")
        public static Validation fromMap(Map<String, Object> m) {
            Validation v = new Validation();
            v.result = str(m, "result", "NOT_CHECKABLE");
            v.dataAbsent = Json.asBool(m.getOrDefault("dataAbsent", false));
            Object c = m.get("checks");
            if (c instanceof List<?> l) for (Object o : l) v.checks.add(String.valueOf(o));
            if (m.get("positive") instanceof Map<?, ?> pm) v.positive = Control.fromMap((Map<String, Object>) pm);
            if (m.get("negative") instanceof Map<?, ?> nm) v.negative = Control.fromMap((Map<String, Object>) nm);
            v.reason = str(m, "reason", null);
            return v;
        }
    }

    public static final class Control {
        public String name;
        public String expected = "FOUND";
        public String actual = "NOT_RUN";
        public boolean ok;
        public boolean applicable = true;
        public String detail;

        public Control() { this("control"); }

        public Control(String name) { this.name = name; }

        public Map<String, Object> toMap() {
            Map<String, Object> m = Json.obj("name", name, "expected", expected, "actual", actual,
                    "ok", ok, "detail", detail);
            if (!applicable) m.put("applicable", false);
            return m;
        }

        public static Control fromMap(Map<String, Object> m) {
            Control c = new Control(str(m, "name", "control"));
            c.expected = str(m, "expected", "FOUND");
            c.actual = str(m, "actual", "NOT_RUN");
            c.ok = Json.asBool(m.getOrDefault("ok", false));
            c.applicable = Json.asBool(m.getOrDefault("applicable", true));
            c.detail = str(m, "detail", null);
            return c;
        }
    }
}
