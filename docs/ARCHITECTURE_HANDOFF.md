# Architecture Handoff — for independent review

Status: working prototype, 57 tests green, 4,406 experiment rows.
Review goal: find architectural defects, not missing polish. Do not assume features exist.
Do not turn `NOT_CHECKABLE` into `PASS`.

## 1. What this is

A Java 25 / Maven multi-module logical-level data-destruction tool. It destroys a file with
AES-256-GCM crypto-shredding or overwrite+fsync+unlink, measures the result with a
control-validated canary scan, and records Ed25519-signed evidence in an RFC 9162 Merkle log
with a local witness. It has a CLI, an offline verifier, and a Swing UI. It does **not** verify
physical flash.

## 2. Modules

| Module | Responsibility |
|---|---|
| `evidence` | canonical JSON, Ed25519, signed record, assurance levels |
| `log` | RFC 9162 Merkle tree, checkpoints, witness, inclusion/consistency proofs, verifier |
| `destroy-memory` | `SecretBuffer` (FFM), `NativeLock`, heap wipe, String demo |
| `destroy-file` | overwrite+fsync+delete, AES-GCM crypto-shred, 0600 key vault |
| `verify` | child-JVM canary victim, `/proc/<pid>/mem` scanner, controls, raw-image scanner |
| `txn` | journaled state machine, vault, commit/rollback, recovery |
| `verifier-cli` | offline `jvd-verify` |
| `cli` | `jvd` commands |
| `ui` | Swing app over `AppService` |
| `experiments` | 200-trial matrices, CSV, generated `docs/RESULTS.md` |

Core dependency direction:

```text
evidence <- log <- txn
evidence <- verify <- txn
destroy-file <- txn
cli / ui / verifier-cli / experiments -> the above
```

## 3. Transaction

```text
STAGED -> VAULTED -> SCRUBBED -> VALIDATED -> [grace] -> COMMITTED
                                  \-> ABORTED (restore)
```

- `STAGED`: regular file checked; journal event fsynced.
- `VAULTED`: encrypted rollback copy (`OVERWRITE`) or crypto container (`CRYPTO_SHRED`),
  with a 0600 key file.
- `SCRUBBED`: overwrite with zeros + fsync + truncate + delete.
- `VALIDATED`: path absent, rollback copy decrypts, optional raw-image canary scan. The image
  is pre-scanned; if the canary is not in it, it is not a witness.
- `COMMITTED`: key/vault destroyed; evidence signed, logged, checkpointed, witness-cosigned.
- `ABORTED`: restore from vault/container, delete vault/key.
- `Recovery`: `STAGED`/`VAULTED` abort without restore; `SCRUBBED`/`VALIDATED` restore;
  `COMMITTED` never restores.

`DestructionTransaction` currently owns config, journal, filesystem paths, vault, key files,
crypto, evidence, log, checkpoint, witness, and recovery. This is the main god object.

## 4. Verification

Parent JVM spawns a child `CanaryVictim`. Child derives target, positive-control, and
negative-control canaries from a seed. Positive control must be FOUND; negative must be
NOT_FOUND; target is the measurement. A failed control makes the run `INVALID`.

Scanner reads `rw` anonymous, `[heap]`, and `/memfd:` mappings; never self-scans; wipes
buffers. It skips `[stack]`, file-backed mappings, native/metaspace/code, and registers.

## 5. Evidence and log

Record fields include `schemaVersion`, `eventId`, `timestamp`, salted subject hash and
plaintext `subjectLabel`, method/technique/tool/version/JVM/OS/GC/flags, separate
`verification` and `validation`, residual risk, assurance, Ed25519 signature.

Log leaf = `SHA-256(0x00 || canonical record)`; node = `SHA-256(0x01 || left || right)`.
Checkpoint signs `(origin,size,root)`; witness signs that plus name/timestamp. Verifier
checks record signatures, leaves, checkpoint, witness, size/root, inclusion, consistency.
Detects edited, deleted, backdated, truncated, forked logs relative to a trusted checkpoint.

## 6. Current evidence

- `mvn -q verify`: 57 tests, 0 failures/errors/skips.
- 200 trials/cell, JDK 25.0.5+8:
  - Serial/Parallel/Shenandoah `MOVE`: 200/200 target FOUND (false assurance).
  - G1 `MOVE`: 0/200; ZGC `MOVE`: 2/200 (1.0%, Wilson CI 0.3–3.6%).
  - WIPE/HOT: 0/200 on every collector.
  - Tamper: edit/delete/backdate/fork 200/200 detected.
  - File matrix: logical checks 200/200; raw-media residue `NOT_CHECKABLE` without an image.
- H6 ext4 overwrite is partial; delete-only residue observed, overwrite branch not run.

## 7. Known architectural problems

### Critical

1. **Commit/evidence is not atomic.** `commit()` destroys key/vault, then signs/logs/
   checkpoints, then journals `COMMITTED`. A crash after key destruction but before the
   journal leaves `VALIDATED`; recovery tries to restore from deleted material. A failure
   after commit but before evidence leaves a committed transaction without valid evidence.
   No `COMMITTING` intent/outbox/reconciliation.
2. **Recovery ignores the log.** It reads the journal only; it cannot detect committed-with-
   missing-evidence or reconcile a checkpoint mismatch.

### High

3. **God object.** `DestructionTransaction` mixes domain state, filesystem, crypto, evidence,
   log, keys, and witness. No application service or ports.
4. **CLI/UI duplication.** `cli.Keys` vs `ui.AppService.Keys`; both create log/witness/txn.
   CLI `verify` checks only `latest.json`; `jvd-verify` supports old checkpoints and
   inclusion. UI has no old-checkpoint check.
5. **A3 unreachable.** `AssuranceLevel.A3` exists in enum/README, but the file transaction
   caps at A1/A2; no path emits A3.
6. **MEMORY is not a transaction mode.** `SecretBuffer`/`HeapWipe` exist, but no memory
   transaction/evidence path. Experiments use synthetic `byte[]`, not the library APIs.
7. **TOCTOU/file identity.** Target can be replaced between vault and scrub; no lock, no
   `NOFOLLOW_LINKS`, no inode/fileKey check, no hard-link (`nlink`) check. Hard links leave
   plaintext; permissions/xattrs/timestamps are not preserved on restore.
8. **Raw-image oracle is not tied to the file.** Pre-check only proves the canary exists in
   the image; no block map/filesystem metadata proof that the image contains this file.

### Medium

9. Key copies: `SecretKeySpec` cannot be destroyed; provider copies; file key deletion leaves
   journal/backup copies. No KMS/HSM.
10. Evidence leaks `subjectLabel` path and stores the salt; salted hash of a known path is
    dictionary-testable. No content hash/inode/volume ID/ciphertext hash.
11. Log loads all entries in memory; proof generation recomputes subroots; checkpoint is
    custom JSON, not C2SP note wire format; local witness only.
12. Scanner skips stacks/native/metaspace/registers; child is trusted; classpath heuristic.
13. Journal fsyncs events but not parent dir; checkpoints not fsynced; key file perms set
    after write.
14. `CryptoShredder.decrypt` can leave partial plaintext on GCM failure; encrypt can leave
    orphan key/container on failure.
15. Recovery atomically overwrites target without checking user changes; loses metadata.
16. UI is static `AppService` calls, inline metric updates, no MVC/state store; no
    confirmation dialog, progress/cancel, history, log export, keyboard/accessibility, UI
    interaction tests. `Theme` is a static global.
17. No CI, Maven wrapper, JDK enforcer, `jpackage` installer; experiments not in `mvn verify`.
18. Public mutable fields/arrays in `EvidenceRecord`/`TxnConfig`; no thread safety; `Json`
    has no depth/size limit.
19. Swallowed exceptions in rollback/recovery/decrypt; `commit()` can throw after COMMITTED.
20. CLI/UI verification scope differs.

## 8. Target architecture (starting point)

```text
jvd-domain        TransactionState, DestructionPlan, ValidationOutcome, AssurancePolicy
                  ports: Journal, Vault, EvidenceSink, TransparencyLog, KeyStore, Clock,
                         MemoryOracle, FileOracle
jvd-application   DestroyFileUseCase, RecoverUseCase, VerifyEvidenceUseCase, KeyService,
                  EvidenceAssembler
jvd-infra-fs      FileDestroyer, CryptoShredder, FileKeyVault, Journal, Recovery
jvd-infra-jvm     CanaryVerifier, MemoryScanner, VictimProcess, FileScanner
jvd-infra-log     Merkle, LogStore, Checkpoint, Witness, LogVerifier
jvd-cli / jvd-ui / jvd-verifier
```

Recommended sequence:

```text
STAGED
VAULTED
SCRUBBED
VALIDATED
COMMITTING   (intent: evidence hash, checkpoint target, key id)
COMMITTED    (after evidence is durable or outboxed)
```

Recovery should reconcile journal + log:
- `COMMITTING` + key exists: rollback or complete evidence.
- `COMMITTING` + key gone: committed; repair/append evidence.
- `VALIDATED` + payload/key: restore.
- never claim a restore it did not perform.

## 9. Questions for the reviewer

1. Smallest safe fix for the commit/evidence crash window without a database?
2. Is `COMMITTING` + outbox sufficient, or is a two-phase idempotent evidence append needed?
3. How should A3 be defined so it is honest and reachable?
4. Is the raw-image pre-check an acceptable demo oracle, or should it be removed?
5. How to handle TOCTOU/symlinks/hardlinks/sparse files/metadata in JDK-only code?
6. Should MEMORY become a transaction mode, and how should its evidence map?
7. How to merge/split modules to remove CLI/UI duplication?
8. Which tests catch the current critical bugs?
9. What to cut for a student team without reducing verification quality?
10. How to structure the UI if it is a product, not a demo shell?

## 10. Rules

- Keep positive/negative controls.
- Keep `NOT_CHECKABLE` honest.
- No physical-erasure claim.
- No restore after COMMIT.
- No network/blockchain/Spring/JavaFX just for style.
- Preserve JDK-only core.
