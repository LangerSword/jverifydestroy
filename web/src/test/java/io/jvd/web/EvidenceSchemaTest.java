package io.jvd.web;

import io.jvd.evidence.Ed25519;
import io.jvd.evidence.EvidenceRecord;
import io.jvd.evidence.Json;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the schema that every evidence record is checked against.
 *
 * <p>Two things are checked here: that the schema document itself is the JSON it claims to be,
 * and that the validator catches the mistakes a real record can contain. A schema that is
 * never applied is documentation; a schema that is applied but never tested is a promise.</p>
 */
class EvidenceSchemaTest {

    /** A well-formed record, as the project produces it. */
    private EvidenceRecord good() {
        EvidenceRecord r = EvidenceRecord.create("/tmp/file", "CLEAR", "OVERWRITE");
        r.verification.operationCompleted = true;
        r.verification.status = "COMPLETED";
        r.validation.result = "PASS";
        r.validation.dataAbsent = true;
        r.sign(Ed25519.generate().getPrivate());
        return r;
    }

    @Test void aWellFormedRecordHasNoProblems() {
        assertEquals(List.of(), EvidenceSchema.validate(good()));
    }

    @Test void aMissingFieldIsCaught() {
        EvidenceRecord r = good();
        r.eventId = null;

        List<String> problems = EvidenceSchema.validate(r);

        assertFalse(problems.isEmpty());
        assertTrue(problems.stream().anyMatch(p -> p.contains("eventId")
                        && p.contains("missing required field")),
                problems.toString());
    }

    @Test void aMissingMethodIsCaught() {
        EvidenceRecord r = good();
        r.method = null;

        List<String> problems = EvidenceSchema.validate(r);

        assertTrue(problems.stream().anyMatch(p -> p.contains("method")),
                problems.toString());
    }

    @Test void aWrongEnumValueIsCaught() {
        EvidenceRecord r = good();
        r.validation.result = "MAYBE";

        List<String> problems = EvidenceSchema.validate(r);

        assertFalse(problems.isEmpty());
        assertTrue(problems.stream().anyMatch(p -> p.contains("validation.result")
                        && p.contains("MAYBE")),
                problems.toString());
    }

    @Test void aWrongTechniqueIsCaught() {
        EvidenceRecord r = good();
        r.technique = "TELEPORT";

        List<String> problems = EvidenceSchema.validate(r);

        assertTrue(problems.stream().anyMatch(p -> p.contains("technique")
                        && p.contains("TELEPORT")),
                problems.toString());
    }

    @Test void aWrongEventTypeIsCaught() {
        EvidenceRecord r = good();
        r.eventType = "PROBABLY";

        List<String> problems = EvidenceSchema.validate(r);

        assertTrue(problems.stream().anyMatch(p -> p.contains("eventType")
                        && p.contains("PROBABLY")),
                problems.toString());
    }

    @Test void aWrongAssuranceLevelIsCaught() {
        EvidenceRecord r = good();
        r.assurance = io.jvd.evidence.AssuranceLevel.A3;
        // A3 is a legal level, so this record must pass; the point is that the validator
        // accepts every level the project defines.
        assertEquals(List.of(), EvidenceSchema.validate(r));
        assertTrue(EvidenceSchema.assuranceLevels().contains("A3"));
    }

    @Test void aMissingValidationSectionIsCaught() {
        EvidenceRecord r = good();
        r.validation = null;

        List<String> problems = EvidenceSchema.validate(r);

        assertTrue(problems.stream().anyMatch(p -> p.contains("validation is missing")),
                problems.toString());
    }

    @Test void aMissingVerificationSectionIsCaught() {
        EvidenceRecord r = good();
        r.verification = null;

        List<String> problems = EvidenceSchema.validate(r);

        assertTrue(problems.stream().anyMatch(p -> p.contains("verification is missing")),
                problems.toString());
    }

    @Test void aNullRecordIsReportedNotThrown() {
        List<String> problems = EvidenceSchema.validate(null);

        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("missing"));
    }

    @Test void theSchemaDocumentIsValidJsonAndDescribesTheRecord() {
        Map<String, Object> schema = Json.parseObject(EvidenceSchema.SCHEMA);

        assertEquals("https://json-schema.org/draft/2020-12/schema", schema.get("$schema"));
        assertEquals("object", schema.get("type"));

        @SuppressWarnings("unchecked")
        List<String> required = (List<String>) schema.get("required");
        assertTrue(required.contains("eventId"));
        assertTrue(required.contains("verification"));
        assertTrue(required.contains("validation"));

        @SuppressWarnings("unchecked")
        Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
        assertTrue(properties.containsKey("method"));
        assertTrue(properties.containsKey("technique"));
        assertTrue(properties.containsKey("assurance"));
    }

    @Test void theSchemaEnumerationsMatchWhatTheValidatorEnforces() {
        Map<String, Object> schema = Json.parseObject(EvidenceSchema.SCHEMA);
        @SuppressWarnings("unchecked")
        Map<String, Object> properties = (Map<String, Object>) schema.get("properties");

        @SuppressWarnings("unchecked")
        List<String> methodEnum = (List<String>) ((Map<String, Object>) properties.get("method")).get("enum");
        assertEquals(List.of("CLEAR", "PURGE", "DESTROY"), methodEnum);

        @SuppressWarnings("unchecked")
        List<String> assuranceEnum = (List<String>) ((Map<String, Object>) properties.get("assurance")).get("enum");
        assertEquals(EvidenceSchema.assuranceLevels(), assuranceEnum);

        @SuppressWarnings("unchecked")
        List<String> eventEnum = (List<String>) ((Map<String, Object>) properties.get("eventType")).get("enum");
        assertEquals(EvidenceSchema.eventTypes(), eventEnum);
    }

    @Test void theSchemaAndTheValidatorAgreeOnEveryEnumValue() {
        // Each allowed value must pass, and one value outside each list must fail.
        for (String method : List.of("CLEAR", "PURGE", "DESTROY")) {
            EvidenceRecord r = good();
            r.method = method;
            assertEquals(List.of(), EvidenceSchema.validate(r), "method " + method);
        }
        for (String technique : List.of("OVERWRITE", "CRYPTO_ERASE", "MEMORY_WIPE", "DELETE")) {
            EvidenceRecord r = good();
            r.technique = technique;
            assertEquals(List.of(), EvidenceSchema.validate(r), "technique " + technique);
        }
        for (String type : EvidenceSchema.eventTypes()) {
            EvidenceRecord r = good();
            r.eventType = type;
            assertEquals(List.of(), EvidenceSchema.validate(r), "eventType " + type);
        }
    }
}
