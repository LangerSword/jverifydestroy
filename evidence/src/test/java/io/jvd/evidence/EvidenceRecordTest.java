package io.jvd.evidence;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class EvidenceRecordTest {
    @Test void signatureCoversEveryFieldAndTamperFails() {
        KeyPair kp = Ed25519.generate();
        EvidenceRecord r = EvidenceRecord.create("/tmp/secret.bin", "CLEAR", "OVERWRITE");
        r.verification.operationCompleted = true;
        r.verification.status = "COMPLETED";
        r.validation.result = "PASS";
        r.validation.dataAbsent = true;
        r.validation.checks.add("path absent");
        r.validation.positive.actual = "FOUND";
        r.validation.positive.ok = true;
        r.validation.negative.actual = "NOT_FOUND";
        r.validation.negative.ok = true;
        r.assurance = AssuranceLevel.A2;
        r.sign(kp.getPrivate());

        assertTrue(r.verifySignature(kp.getPublic()));
        EvidenceRecord parsed = EvidenceRecord.fromJson(r.toJson());
        assertTrue(parsed.verifySignature(kp.getPublic()));
        assertEquals("PASS", parsed.validation.result);
        assertEquals(AssuranceLevel.A2, parsed.assurance);

        parsed.validation.result = "FAIL";
        assertFalse(parsed.verifySignature(kp.getPublic()));
    }

    @Test void aRecordWithoutSignatureIsNotValid() {
        KeyPair kp = Ed25519.generate();
        EvidenceRecord r = EvidenceRecord.create("x", "PURGE", "CRYPTO_ERASE");
        assertFalse(r.verifySignature(kp.getPublic()));
    }

    @Test void subjectHashIsSaltedAndStable() {
        byte[] salt = new byte[16];
        String a = EvidenceRecord.hashSubject("/a", salt);
        String b = EvidenceRecord.hashSubject("/a", salt);
        String c = EvidenceRecord.hashSubject("/b", salt);
        assertEquals(a, b);
        assertNotEquals(a, c);
    }
}
