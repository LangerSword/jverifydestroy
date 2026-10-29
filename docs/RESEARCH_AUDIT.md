# Research Audit — verifiable secure data destruction in Java

Date: 2026-10-30
Auditor: Hermes (independent re-check of the attached report v1)
Scope: every C/K/N item in the report, plus prior art the report missed.

Verdict vocabulary: CONFIRMED (primary source read), CONFIRMED-S (secondary source only),
PARTLY (part of the claim holds, part does not), REFUTED, UNVERIFIABLE (could not obtain the
source), NOT_TESTED (empirical claim not settled here; see SPIKES.md).

## A. Claim table

| ID | Verdict | Evidence (URL / file read) | Note |
|---|---|---|---|
| C-1a | CONFIRMED | https://csrc.nist.gov/pubs/sp/800/88/r2/final ; https://csrc.nist.gov/pubs/sp/800/88/r1/final | Rev.2 published 2025-09-26. Rev.1 page says “Withdrawn on September 26, 2025. Superseded by SP 800-88 Rev. 2.” |
| C-1b | PARTLY | NIST SP 800-88r2 PDF, §1 and §4 (downloaded from tsapps.nist.gov, pub_id=960712) | It is program-level guidance. It defines no product-certification scheme. “Not a product-certification scheme” is a fair reading, not a sentence in the document. |
| C-2 | CONFIRMED | NIST SP 800-88r2 §4.5.1, §4.5.2, §4.6; FAQ Q7 (https://csrc.nist.gov/files/pubs/sp/800/88/r2/final/docs/sp800-88r2-faq.pdf) | Verification = technique completed without errors/anomalies. Validation = decision that target data was effectively sanitized. §4.6 lists manufacturer, model, serial, media type/source, method (Clear/Purge/Destroy), technique, tool+version, verification method, persons performing verification and validation, signature. The field list in the report is essentially right; the primary text is stronger than the vendor summaries. |
| C-3 | REFUTED (as worded) | NIST SP 800-88r2 §4.6 + Appendix C | The word “mandates” is wrong. §4.6 says a certificate “should be completed” per policy. Appendix C’s sample has a Signature block and a separate “Concurrence” block, i.e. two signers in the sample, but no normative dual-signatory requirement. |
| C-4 | CONFIRMED-S | https://blancco.com/resources/blog-verifiable-data-destruction-how-to-know-data-is-gone-for-good/ quoting IEEE 2883.1-2025: the standard “does not require verification of the actual functioning of the sanitization commands.” | IEEE 2883.1-2025 is paywalled; the IEEE page (https://standards.ieee.org/ieee/2883.1/11015/) gives only the abstract. The quote is from a vendor with a commercial interest in verification, so treat as secondary. It does support the report’s [S] claim. |
| C-5 | CONFIRMED (date PARTLY) | NVMe 2.1 change log, “Post Sanitize Media Verification – TP4152 (optional)”, https://nvmexpress.org/wp-content/uploads/NVM-Express-Revision-2.1-Changes-09_05_24.pdf ; nvme-sanitize(1) `--emvs` / `exit-media-verification` | Adds Media Verification state, Read-during-verification, EMVS bit, Sanitize Status SANS field. Optional. The change-log file is dated 2024-09-05; the report’s “Aug 2024” is approximate. Hardware/user-space boundary is exactly as the report says. |
| C-6 | CONFIRMED | https://www.opencompute.org/documents/ocp-lock-specification-v1-1-final-pdf/ (“OCP L.O.C.K. 1.1 (RC4) … Effective June 3, 2026”); https://chipsalliance.github.io/caliptra-web/docs/2.1/lock_spec.html | Contributors listed by OCP: Google, Microsoft, Samsung, KIOXIA, Solidigm. Caliptra docs describe LOCK as an extension to Caliptra and host the 2.1 LOCK spec. Hardware root-of-trust level; out of scope for pure Java. |
| C-7 | CONFIRMED | RFC 9162 (https://www.rfc-editor.org/rfc/rfc9162.txt): “Obsoletes: 6962”, Dec 2021; §2 Merkle tree, inclusion and consistency proofs. C2SP tlog-checkpoint (https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md) and tlog-witness. | RFC 9162 does not itself define the checkpoint note format; C2SP does. Witness cosignatures are what make split-view detection possible; the C2SP witness protocol says witnesses verify consistency with their recorded state and return a timestamped cosignature. |
| C-8 | CONFIRMED-S | PIB “DPDP Rules, 2025 Notified” (https://www.pib.gov.in/PressReleseDetailm.aspx?PRID=2190014): 18-month phased compliance timeline; Legal500 analysis: retention/erasure provisions in force 2027-05-13. | The primary Gazette mapping of Rule 8 to 2027-05-13 was not read. Treat the exact date as TO VERIFY against the Gazette; the 18-month phased timeline is confirmed. |
| C-9 | CONFIRMED | Destroyable javadoc (Java SE 25): “The default implementation throws DestroyFailedException.” SecretKeySpec javadoc: implements Destroyable and inherits the default methods. Local test: `new SecretKeySpec(new byte[16], "AES").destroy()` throws DestroyFailedException. | Any Destroyable implementation must override destroy(); SecretKeySpec does not. “Behaviour varies per class/provider” is correct and should be tested per class, not assumed. |
| C-10 | CONFIRMED (zeroing PARTLY) | JEP 454 (https://openjdk.org/jeps/454): FFM final in JDK 22; a confined arena deallocates its memory on close. | Deallocation is specified; zeroing is not. A test (SPIKES.md H5) confirms an arena can be mlocked and marked MADV_DONTDUMP; nothing in the API zeroes it for you. The report’s “zeroing is NOT implied” is an inference from the absence of a guarantee, and is the safe engineering assumption. |
| C-11 | CONFIRMED | JLS §4.3.3 / String javadoc: String is immutable. CERT MSC59-J (https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/miscellaneous-msc/msc59-j/) | Cannot be wiped in place. CERT recommends limiting lifetime and clearing buffers; it also states that full mitigation needs OS/JVM support. |
| C-12 | CONFIRMED for Serial, Parallel, Shenandoah | Local H2 experiment, 10/10 trials each: after `System.gc()` while a canary array was live, then wiping the live reference, the canary was FOUND 10/10 in process memory. G1 0/10, ZGC 0/10. See SPIKES.md H2. | This is the report’s [S] claim made concrete. Copying collectors can leave a stale copy in from-space after the object moves. The result is collector-dependent; do not generalise to “all GCs”. |
| C-13 | NOT_TESTED / no evidence | H1 experiments: a published/reachable array wiped with Arrays.fill was NOT found (0/10 per collector). A non-escaping array can be eliminated entirely (allocation and fill), which is safe but unobservable. | No evidence that C2 removes a fill on an array that is reachable/published. The 2015 comp.lang.java.security discussion remains inconclusive. The safe rule is: wipe, publish/fence, and still validate; do not claim a guarantee. |

## B. Competitor / prior-art table

| ID | Verdict | Evidence | Note |
|---|---|---|---|
| K-1 | PARTLY | Vendor sites (Blancco, BitRaser, Certus, KillDisk, Jetico, Ziperase, WhiteCanyon) reviewed only at marketing level | Signed reports prove the report was not edited, not that the data is gone. Issuer is the eraser; no public log. That critique stands. Vendor claims were not independently tested. |
| K-2 | PARTLY | Blancco Drive Verifier page; Ontrack/DriveSavers lab services | Independent read-back exists, but it is point-in-time and firmware-build-specific. No public methodology or false-assurance rate found. |
| K-3 | CONFIRMED | https://github.com/klappdev/jefl (README) | Java/JNI over C++20; overwrite, truncate, rename, delete; Simple/DOE/RCMP/OpenBSD/DoD-7/Gutmann-35. No verification, no evidence. Exactly as the report says. |
| K-4 | UNVERIFIABLE | https://github.com/FlossWare/jsecurity now serves a README titled “diskwipe-java”; GitHub API returned null description/language | Could not confirm the report’s “Java 11, GPL-3, multithreaded zero-fill of free space”. Treat as unverified. |
| K-5 | CONFIRMED | https://github.com/heshanthenura/fileshredder | JavaFX file shredder; overwrite multiple times; hobby grade. |
| K-6 | UNVERIFIABLE-S | Report cites docs.ankatech.co “Zeroization”/SecretBuffer | The docs page was not retrieved. The quoted admissions (JIT spills, interning, BC pools) are plausible and consistent with known Java limits, but this audit did not read the source. |
| K-7 | CONFIRMED, understated | https://github.com/1of1Canopus/gdpr-shredding | Java/Spring Boot/JPA. Per-subject DEKs, envelope encryption, hash-chained HMAC-keyed erasure log, key destruction and proof in one transaction, startup guards against plaintext leak paths, explicit residual-risk notes. Paid edition adds grace period and erasure PDF. Maven coordinates `com.housedevinci:gdpr-shredding-core` were not found via search.maven.org’s API (TO VERIFY); the GitHub repo is real. This is closer prior art than the report suggested. |
| K-8 | CONFIRMED | CERT MSC59-J page | Canonical guidance; says full mitigation requires OS/JVM support. |
| K-9 | PARTLY | https://sourceforge.net/projects/aad50/ ; dev.to article by the author | AAD-50 exists and claims 50-cycle NVMe sanitize, SHA-256 audit chain, PDF. “Adopted into nvme-cli” and “Gutmann review” are self-reported and were not confirmed. Multi-cycle sanitize conflicts with NIST guidance against unnecessary passes. |
| K-10 | CONFIRMED | GNU coreutils manual, shred invocation (https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html) | Explicitly states the in-place assumption and lists journaling/COW/compressed/RAID/snapshot exceptions. |
| K-11 | CONFIRMED | nvme-cli nvme-sanitize(1) | Hardware sanitize + status log; not a Java user-space facility. |
| K-12 | PARTLY | Design pattern; no single primary source | Per-tenant DEKs under a KMS KEK, delete key = shred. Real weakness: key backups/escrow and provider-owned logs. This is a pattern, not a product. |
| K-13 | PARTLY | PoSE: Perito & Tsudik, “Secure Code Update for Embedded Devices via Proofs of Secure Erasure”, ESORICS 2010. PURE: De Oliveira Nunes, Eldefrawy, Rattanavipanon, Tsudik, ICCAD 2019. SPEED: Ammar et al., “SPEED: Secure Provable Erasure for Class-1 IoT Devices” (PDF via UNITN). PTAD: ISCC 2019. Hao, Clarke, Zorzo, “Deleting Secret Data with Public Verifiability”, IEEE TDSC 2016. SevDel: arXiv 2307.04316. | The lines of work exist. The report’s years/titles are partly wrong (PURE is 2019, not 2013; PoSE’s title is not “Proofs of Secure Erasure”; Hao & Clarke is TDSC 2016 with Zorzo and is public-verifiability, not merely TPM). “None wired to NIST/IEEE workflows” is plausible but not exhaustively proven. |
| K-14 | CONFIRMED | US20260030390A1, “Attestable secure erase”, Microsoft Technology Licensing, priority 2024-07-24, published 2026-01-29 (https://patents.google.com/patent/US20260030390A1/en) | Root-of-trust/PCR measurements + drive-specific ledger + attestation certificate. Hardware-level, not user-space Java. The report’s “no number/assignee” is now resolved. |

## C. Prior art the report missed (relevant to the novelty claims)

| Work | What it is | Why it matters |
|---|---|---|
| merklon (https://github.com/TrustBeat/merklon) | JVM transparency log in Scala 3 with a Java facade: RFC 9162/6962 Merkle proofs, Ed25519-signed checkpoints, N-of-M witness cosigning, offline proof bundles, standalone verifier, Maven Central. | Directly undercuts N-4 as a novel component. It is JVM, not Java-source, but the report claims “in Java”; a JVM library with a Java API is prior art. |
| US20260228352A1 (https://patents.google.com/patent/US20260228352A1/en) | Ephemeral CPU/GPU memory confinement, locked/non-swappable allocations, zeroization verified before reuse, optional tamper-evident/blockchain proof-of-erasure. | Directly overlaps the “verifiable memory zeroization + proof” idea. It is a patent application, not a shipping Java tool, but it is prior art for N-1’s broad framing. |
| US12299313B2 (https://patents.google.com/patent/US12299313B2/en) | Prover/verifier challenge-response proving erasure of a memory region by overwriting with a seed-derived block chain. | PoSE-style memory-erasure proof; prior art for “prove the memory was overwritten”. |
| US20240362187A1 (https://patents.google.com/patent/US20240362187A1/en) | Overwriting-based deletion with a verifiable pseudo-random function and post-deletion state verification. | Prior art for overwrite + verification. |
| US20260141108A1 (https://patents.google.com/patent/US20260141108A1/en) | Secure data erasure framework with individualized encryption keys and a proof of deletion/destruction/erasure. | Prior art for crypto-shred + proof. |
| US10169606B2 (https://patents.google.com/patent/US10169606B2/en) | Verifiable data destruction in a database. | Prior art for verifiable destruction records. |
| cryptoshred (https://github.com/prisma-capacity/cryptoshred) | Java library for transparent encryption/decryption of persisted data and key deletion. | Crypto-shredding is not novel; already a Java library. |
| SecurerString (https://github.com/simmel/SecurerString) | Java char/string shredding helper; wipes input and internal char arrays; documents length leakage. | Prior art for the “String misuse / best-effort wipe” part of N-2. |
| DNEFS / UBIFSec (USENIX Security 2012) | Secure deletion for flash memory inside the FTL/filesystem. | Shows the flash problem is a systems problem, not a Java API problem. |
| Bauer & Priyantha (USENIX 2001) | Secure data deletion for Linux file systems. | Classic treatment of deleted-block residue and journaling. |
| AAD-50 | 50-cycle NVMe sanitize + audit chain + PDF. | Prior art for audit-chained sanitize evidence, albeit hardware-level and self-reported. |

## D. Revised novelty assessment

**N-1 (control-validated canary validation of Java destruction).** Keep, but narrow.
Prior art proves erasure of memory with challenge-response (PoSE, PURE, US12299313B2) and
claims zeroization with proof-of-erasure (US20260228352A1). No Java tool was found that
(a) plants HMAC-derived canaries, (b) scans a child JVM’s `/proc/<pid>/mem`, (c) runs a
positive control (an unwiped copy that must be found) and a negative control (a value that
must not be found) on every run, and (d) reports a measured false-assurance rate. The
defensible contribution is the *measurement discipline* plus the Java-specific leak matrix,
not the abstract idea of proving erasure. Patent risk: avoid claiming “immutable proof of
erasure” as a broad concept; implement it as evidence, and cite the patents.

**N-2 (empirical Java secret-handling matrix).** Keep as a measurement paper/module.
SecurerString and AnkaSecure acknowledge the problem; neither publishes a GC/JIT matrix with
controls. The H2 result (stale copies on Serial/Parallel/Shenandoah, not G1/ZGC in this test)
is a concrete, repeatable finding. Novelty is medium: it is a measurement, not an invention.

**N-3 (commit/rollback destruction).** Narrow. gdpr-shredding already couples key
destruction and proof in one transaction, and its paid edition advertises a grace period.
What was not found is a file-level destruction transaction with a write-ahead journal,
pre-commit validation, crash recovery at every state, and a hard no-restore-after-COMMIT
rule. Defensible as engineering, low as research novelty.

**N-4 (witness-cosigned Merkle log + offline verifier).** DROP as a novelty claim.
merklon already implements exactly this on the JVM (RFC 9162, witness cosigning, offline
bundles, a verifier CLI). The project should still implement its own log (the brief requires
it), but RELATED_WORK must credit merklon and the novelty claim must be limited to the
destruction-evidence schema and its integration with validation, not the log itself.

**N-5 (NIST Rev.2 mapping).** Keep as an engineering contribution, not a research claim.
The mapping is derived from NIST §4.5/§4.6 and Appendix C, which are public. No direct
prior-art schema was found, but the novelty is low and easy to re-derive.

## E. Errors and overstatements in report v1

1. **C-3 is wrong as written.** NIST does not “mandate” dual-signatory certificates. The
   sample form has a signature and a concurrence block; the text says “should”.
2. **N-4 is not novel.** merklon is a JVM implementation of the same log, witness, and
   offline-verification design. The report’s “hash-chain alone is NOT novel” is right, but
   the conclusion that the witness-cosigned log is novel is wrong.
3. **K-7 is understated.** gdpr-shredding-core is not just a hash chain: it has per-subject
   DEKs, envelope encryption, an HMAC-keyed hash-chained erasure log, key destruction and
   proof in one transaction, and explicit residual-risk documentation.
4. **K-13 citations are sloppy.** PURE is ICCAD 2019 (not 2013); PoSE’s title is “Secure
   Code Update for Embedded Devices via Proofs of Secure Erasure” (ESORICS 2010); SPEED is
   an IoT secure-erasure protocol, not a cloud deduplication scheme; Hao & Clarke is
   “Deleting Secret Data with Public Verifiability” (TDSC 2016) with Zorzo.
5. **K-14 is now identified.** US20260030390A1, Microsoft, priority 2024-07-24.
6. **C-5’s date is approximate.** The NVMe 2.1 change log is dated 2024-09-05. The feature
   is optional and hardware-level, as stated.
7. **H3 is subtler than the report.** `jcmd GC.heap_dump -all` does include unreachable
   objects, but the default dump performs a full GC first, which can destroy the very
   evidence you wanted; running default and `-all` in that order makes `-all` look empty.
   The `-all` dump must be run on a fresh process. H3 is confirmed with that caveat.
8. **H4 is worse than the report.** The scanner’s own read buffer contains the target bytes,
   so a self-scan finds the canary even after the target array is wiped. Masking the needle
   is not sufficient; the scanner must run in a separate process and wipe its buffers.
   A victim helper that returns `Arrays.copyOf(digest, n)` without wiping the digest output
   also leaves a real copy — observed as a FOUND in the first version of the H1 probe.
9. **“Every [C-n] is a claim” is right, but several [V] tags in v1 are vendor or secondary.**
   C-2’s field list, C-4, and C-6’s “built on Caliptra 2.1” were not primary in v1. This
   audit read the NIST PDF, the NVMe change log, the OCP page, and the Caliptra docs.
10. **The report’s C-1 “not a product-certification scheme” is an interpretation.** It is a
    correct reading, but the document does not say those words. The audit marks it PARTLY.

## F. Sources read in full or in relevant part

- NIST SP 800-88r2 PDF (tsapps.nist.gov, pub_id=960712), §4.5–§4.7, Appendix C, change log.
- NIST SP 800-88r2 FAQ PDF, Q7 and Q9.
- NIST CSRC Rev.1 and Rev.2 publication pages.
- IEEE 2883.1-2025 abstract page; Blancco article quoting the standard (secondary).
- NVMe 2.1 change log PDF, TP4152 section.
- nvme-cli nvme-sanitize(1) man page.
- OCP L.O.C.K. 1.1 page and Caliptra 2.1 LOCK spec.
- RFC 9162 text; C2SP tlog-checkpoint and tlog-witness specs.
- PIB DPDP Rules 2025 release; Legal500 analysis (secondary).
- OpenJDK JEP 454; Java SE 25 Destroyable and SecretKeySpec javadocs.
- CERT MSC59-J; GNU coreutils shred manual.
- USENIX FAST 2011 Wei et al. PDF.
- jefl, gdpr-shredding, cryptoshred, merklon, SecurerString GitHub pages.
- US20260030390A1, US20260228352A1, US12299313B2, US20240362187A1, US20260141108A1,
  US10169606B2 Google Patents pages.
- UCI SPRout publications page (PURE/ICCAD 2019); PoSE Springer page; PTAD IEEE CSDL page;
  Hao/Clarke/Zorzo TDSC PDF; SevDel arXiv page.
