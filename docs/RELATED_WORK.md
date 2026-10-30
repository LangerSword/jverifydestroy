# Related Work and Novelty

Status: prior-art search is a web/source review, not a legal freedom-to-operate opinion.
A patent attorney has not reviewed this. The honest claim is **combination plus measured
results**, not any single mechanism.

## What is not novel

- **Crypto-shredding.** `prisma-capacity/cryptoshred` is a Java library for encrypting
  persisted fields and deleting the key. `1of1Canopus/gdpr-shredding` goes further:
  per-subject DEKs, envelope encryption, a hash-chained HMAC-keyed erasure log, key
  destruction and proof in one transaction, and explicit residual-risk notes.
  https://github.com/prisma-capacity/cryptoshred · https://github.com/1of1Canopus/gdpr-shredding
- **Overwrite + unlink.** `klappdev/jefl` overwrites/truncates/renames/deletes through JNI;
  GNU `shred` documents the in-place assumption and its journaling/COW exceptions.
  https://github.com/klappdev/jefl · https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html
- **Hash-chained audit logs.** Present in `gdpr-shredding` and in AAD-50. A plain hash chain
  is not tamper-evident against the operator who owns it.
- **RFC 9162 transparency logs with witnesses and offline proofs.** `merklon` implements
  exactly this on the JVM: Merkle inclusion/consistency proofs, Ed25519-signed checkpoints,
  N-of-M witness cosigning, offline proof bundles, and a standalone verifier. It is Scala 3
  with a Java facade and is on Maven Central.
  https://github.com/TrustBeat/merklon
- **Proofs of secure erasure.** PoSE (Perito & Tsudik, ESORICS 2010), PURE (ICCAD 2019),
  SPEED (Ammar et al.), PTAD (ISCC 2019), SevDel (arXiv 2307.04316), and Hao/Clarke/Zorzo
  (IEEE TDSC 2016) prove erasure of memory or cloud data with challenge-response or public
  verifiability. They are not wired to NIST/IEEE workflow fields.
- **Verifiable deletion patents.** US20260030390A1 (Microsoft, “Attestable secure erase”,
  priority 2024-07-24) uses a root of trust, PCR measurements, and a drive-specific ledger.
  US20260228352A1 claims locked CPU/GPU memory, zeroization verification, and an immutable
  proof-of-erasure ledger. US12299313B2 proves erasure of a memory region.
  US20240362187A1 covers overwrite-based deletion with verification. US10169606B2 covers
  verifiable data destruction in a database.

## What this project actually contributes

1. **Control-validated canary validation of Java destruction.** A child JVM is scanned for
   HMAC-derived canaries; every run carries a positive control (an unwiped canary that must
   be found) and a negative control (a value that must not be found). A failed control makes
   the run `INVALID`, not `PASS`. No Java tool found in this review does the control pair
   plus a measured false-assurance rate. This is the strongest defensible contribution.
2. **A measured Java leak matrix.** The H2 result is concrete: after `System.gc()` moves a
   live canary array and the live reference is wiped, the canary was still found **20/20**
   on Serial, Parallel, and Shenandoah; **0/200** on G1 and **1/200** on ZGC. The H1/H3/H4 probes add the
   scanner-buffer and heap-dump traps. This is measurement, not a new primitive.
3. **A journaled commit/rollback file-destruction transaction.** `gdpr-shredding` couples
   key destruction and proof in one transaction, and its paid edition advertises a grace
   period. What was not found is a file-level state machine with a write-ahead journal,
   pre-commit validation, kill -9 recovery at every state, and a hard no-restore-after-COMMIT
   rule. This is engineering novelty, not research novelty.
4. **An evidence schema mapped to NIST SP 800-88 Rev.2.** Verification (§4.5.1) and
   validation (§4.5.2) are separate fields; the record carries method, technique, tool,
   version, JVM/OS/GC, controls, residual risk, and assurance. NIST Appendix C is the basis;
   the mapping is easy to re-derive, so this is low-novelty engineering.

## What is explicitly not claimed

- That the log design is new. `merklon` is prior art; this project implements its own log for
  the integration, and credits `merklon`.
- That crypto-shredding is new. It is a Java library pattern already.
- That overwrite sanitizes flash. It does not; it is NIST Clear at best.
- That any result is physical erasure. See the threat model.
- That the evidence is unforgeable by an operator who holds both the log and witness keys and
  withholds every old checkpoint. It is tamper-evident relative to a trusted checkpoint.

## Patent risk

The Microsoft applications cover attestable secure erase with a hardware root of trust and a
proof-of-erasure ledger. This project does not implement a hardware root of trust, TPM, or a
drive ledger. It does implement signed destruction evidence and a witness-cosigned log, which
is adjacent. Do not market it as “attestable secure erase” or “immutable proof-of-erasure”;
describe it as control-validated logical destruction with signed evidence. Get legal review
before any commercial claim.

## Search status

Reviewed: GitHub, Maven Central (search API), Google Patents, NIST CSRC, IEEE abstracts,
RFC 9162/C2SP, USENIX/ACM/Springer/arXiv pages, and the Java security documentation. Not
reviewed: paywalled IEEE 2883.1 full text, full patent claims, non-English literature,
commercial source code. The search is sufficient for an academic project, not for a
freedom-to-operate opinion.
