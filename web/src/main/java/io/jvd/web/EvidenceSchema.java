package io.jvd.web;

import java.util.List;

/**
 * The JSON Schema (draft 2020-12) for one evidence record, plus a validator for it.
 *
 * <p>The schema is published at {@code GET /schema} so a website can check a record before
 * showing it to a visitor, and it is enforced on the verify path so a malformed record is
 * reported as a problem instead of crashing the run.</p>
 *
 * <p>The validator is hand-written rather than delegated to a JSON Schema library: the project
 * depends on nothing but the JDK, and the subset that matters here (required properties, types,
 * enumerations) is small enough to state exactly. The schema constant and the validator are
 * written from the same list of rules so that they cannot drift silently.</p>
 */
public final class EvidenceSchema {

    /** The schema version this validator implements. */
    public static final String DRAFT = "2020-12";

    /**
     * The evidence-record schema.
     *
     * <p>Kept as a text block so it reads as the JSON document it is, rather than as Java
     * string concatenation that has to be escaped by hand. The enumerations are the ones the
     * project itself emits: NIST SP 800-88r2 §4.5 verbs for {@code method}, the techniques in
     * {@code io.jvd.evidence.EvidenceRecord}, and the record lifecycle in
     * {@code io.jvd.txn.DestructionTransaction}.</p>
     */
    public static final String SCHEMA = """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "$id": "https://jverifydestroy.dev/schema/evidence-record/1.json",
              "title": "jverifydestroy evidence record",
              "description": "One signed destruction evidence record. Verification (NIST SP 800-88r2 section 4.5.1) and validation (section 4.5.2) are separate: a record with verification=PASS and validation=NOT_CHECKABLE is honest, not a claim that the data is gone.",
              "type": "object",
              "required": ["schemaVersion", "eventType", "eventId", "timestamp", "subjectHash", "method", "technique", "tool", "toolVersion", "verification", "validation", "residualRisk", "assurance"],
              "additionalProperties": false,
              "properties": {
                "schemaVersion": {"type": "string", "enum": ["1"]},
                "eventType": {"type": "string", "enum": ["RECORD", "INTENT", "CONFIRMED", "ABORTED", "RESTORE_FAILED", "UNRESOLVED"]},
                "eventId": {"type": "string", "minLength": 1},
                "timestamp": {"type": "string", "minLength": 1},
                "subjectHash": {"type": "string", "minLength": 1},
                "subjectSalt": {"type": "string"},
                "subjectLabel": {"type": "string"},
                "method": {"type": "string", "enum": ["CLEAR", "PURGE", "DESTROY"]},
                "technique": {"type": "string", "enum": ["OVERWRITE", "CRYPTO_ERASE", "MEMORY_WIPE", "DELETE"]},
                "tool": {"type": "string", "minLength": 1},
                "toolVersion": {"type": "string", "minLength": 1},
                "jvm": {"type": ["string", "null"]},
                "os": {"type": ["string", "null"]},
                "gc": {"type": ["string", "null"]},
                "jvmFlags": {"type": ["string", "null"]},
                "verification": {
                  "type": "object",
                  "required": ["status", "operationCompleted", "notes"],
                  "properties": {
                    "status": {"type": "string", "minLength": 1},
                    "operationCompleted": {"type": "boolean"},
                    "notes": {"type": "array", "items": {"type": "string"}}
                  }
                },
                "validation": {
                  "type": "object",
                  "required": ["result", "dataAbsent", "checks", "positive", "negative"],
                  "properties": {
                    "result": {"type": "string", "enum": ["PASS", "FAIL", "NOT_CHECKABLE", "NOT_RUN", "INVALID", "RESTORE_FAILED"]},
                    "dataAbsent": {"type": "boolean"},
                    "checks": {"type": "array", "items": {"type": "string"}},
                    "positive": {"$ref": "#/$defs/control"},
                    "negative": {"$ref": "#/$defs/control"},
                    "reason": {"type": ["string", "null"]}
                  }
                },
                "residualRisk": {"type": "string", "minLength": 1},
                "assurance": {"type": "string", "enum": ["A0", "A1", "A2", "A3"]},
                "signature": {"type": "string", "minLength": 1}
              },
              "$defs": {
                "control": {
                  "type": "object",
                  "required": ["name", "expected", "actual", "ok"],
                  "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "expected": {"type": "string", "minLength": 1},
                    "actual": {"type": "string", "minLength": 1},
                    "ok": {"type": "boolean"},
                    "applicable": {"type": "boolean"},
                    "detail": {"type": ["string", "null"]}
                  }
                }
              }
            }
            """;

    /** The enumerations the validator enforces, kept next to the schema they mirror. */
    private static final List<String> EVENT_TYPES = List.of(
            "RECORD", "INTENT", "CONFIRMED", "ABORTED", "RESTORE_FAILED", "UNRESOLVED");
    private static final List<String> METHODS = List.of("CLEAR", "PURGE", "DESTROY");
    private static final List<String> TECHNIQUES = List.of(
            "OVERWRITE", "CRYPTO_ERASE", "MEMORY_WIPE", "DELETE");
    private static final List<String> VALIDATION_RESULTS = List.of(
            "PASS", "FAIL", "NOT_CHECKABLE", "NOT_RUN", "INVALID", "RESTORE_FAILED");
    private static final List<String> ASSURANCE_LEVELS = List.of("A0", "A1", "A2", "A3");

    private EvidenceSchema() {
    }

    /**
     * The assurance levels this schema accepts.
     *
     * <p>Published so that callers can tell a visitor what the allowed values are instead of
     * failing a record for using one that is not on the list.</p>
     */
    public static List<String> assuranceLevels() {
        return ASSURANCE_LEVELS;
    }

    /**
     * The record event types this schema accepts.
     *
     * <p>Published for the same reason as {@link #assuranceLevels()}: a visitor who used the
     * wrong value should be told which values are correct.</p>
     */
    public static List<String> eventTypes() {
        return EVENT_TYPES;
    }

    /**
     * Checks one record against the schema and returns the problems found.
     *
     * <p>An empty list means the record is well formed. Problems are phrased for a human
     * reading a verification report, because that is who has to act on them: the record either
     * came from a different tool version, or it was edited by hand, or a producer wrote a value
     * outside the vocabulary this schema defines.</p>
     *
     * <p>Validation never throws. A record that cannot be validated is still worth reporting on
     * — a record with a bad enum is still evidence that something is wrong — so the caller gets
     * problems, not an exception.</p>
     *
     * @param record the record to check; {@code null} is reported as a problem, not thrown
     * @return the human-readable problems, empty when the record satisfies the schema
     */
    public static List<String> validate(io.jvd.evidence.EvidenceRecord record) {
        List<String> problems = new java.util.ArrayList<>();
        if (record == null) {
            problems.add("record is missing");
            return problems;
        }
        required(problems, "eventType", record.eventType);
        required(problems, "eventId", record.eventId);
        required(problems, "timestamp", record.timestamp);
        required(problems, "subjectHash", record.subjectHash);
        required(problems, "method", record.method);
        required(problems, "technique", record.technique);
        required(problems, "tool", record.tool);
        required(problems, "toolVersion", record.toolVersion);
        required(problems, "residualRisk", record.residualRisk);

        enumeration(problems, "eventType", record.eventType, EVENT_TYPES);
        enumeration(problems, "method", record.method, METHODS);
        enumeration(problems, "technique", record.technique, TECHNIQUES);
        enumeration(problems, "assurance", record.assurance == null ? null : record.assurance.name(),
                ASSURANCE_LEVELS);

        if (record.verification == null) {
            problems.add("verification is missing");
        } else {
            required(problems, "verification.status", record.verification.status);
        }
        if (record.validation == null) {
            problems.add("validation is missing");
        } else {
            enumeration(problems, "validation.result", record.validation.result, VALIDATION_RESULTS);
            if (record.validation.positive == null) {
                problems.add("validation.positive is missing");
            } else {
                control(problems, "validation.positive", record.validation.positive);
            }
            if (record.validation.negative == null) {
                problems.add("validation.negative is missing");
            } else {
                control(problems, "validation.negative", record.validation.negative);
            }
        }
        return problems;
    }

    private static void required(List<String> problems, String field, String value) {
        if (value == null || value.isBlank()) {
            problems.add("missing required field '" + field + "'");
        }
    }

    private static void enumeration(List<String> problems, String field, String value, List<String> allowed) {
        if (value == null) return; // already reported as missing
        if (!allowed.contains(value)) {
            problems.add("field '" + field + "' has value '" + value + "' which is not one of "
                    + String.join(", ", allowed));
        }
    }

    private static void control(List<String> problems, String field, io.jvd.evidence.EvidenceRecord.Control c) {
        required(problems, field + ".name", c.name);
        required(problems, field + ".expected", c.expected);
        required(problems, field + ".actual", c.actual);
    }
}
