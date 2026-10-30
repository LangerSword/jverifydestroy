# STATUS — remediation ledger

Date: 2026-10-30
Commit before this pass: `dbf40c6`
Gate: `mvn -q verify` — 81 tests, 0 failures/errors/skips.

## Earlier findings

| ID | Status | Proof / limitation |
|---|---|---|
| F1 | FIXED | `FindingReproTest.f1ConcurrentRecoverDuringGraceMustNotCommitAsA2`; commit preflights target, post-check failure is `UNRESOLVED`. |
| F2 | FIXED | `FindingReproTest.f2FailedRestoreMustKeepVaultAndKey`; failed restore keeps vault/key and records `RESTORE_FAILED`. |
| F3 | PARTIAL | Code fixed: no truncate-first, 0600 at create. No block-level ext4 test yet; root/loop image is TO VERIFY. |
| F4 | PARTIAL | Scanner now includes named/large regions, uses mincore resident pages, records read errors/coverage, and has a named-mapping test. Single-pass multi-canary and mincore fallback are still open. |
| F5 | FIXED | `FindingReproTest.f5TwoStoresMustNotCreateDuplicateSequenceNumbers`; JVM lock + `log.lock` + tail reload. |
| F6 | FIXED | `FindingReproTest.f6WitnessMustNotCosignAForgedCheckpoint`; `cosign(checkpoint, log)` checks origin/size/root. |
| F7 | FIXED | `Kill9RecoveryTest` covers 8 points x 2 methods (16 cases), including KEY_DESTROYED and CONFIRMED, with recovery reconciliation. |
| F8 | FIXED | JVD2 chunked GCM; `spikes/CryptoMemProbe` decrypts 128 MiB at `-Xmx32m`. JVD1 remains read-only. |

## Patches

| ID | Status | Proof / limitation |
|---|---|---|
| P1 | FIXED | `RESTORE_FAILED`; failed restore never deletes recovery material. |
| P2 | FIXED | Assurance derived from post-checks; target reappearance -> rollback; failed post-check -> `UNRESOLVED`. A3 still not emitted. |
| P3 | PARTIAL | Key overwrite-in-place and atomic 0600 create; no ext4 block-level proof. |
| P4 | PARTIAL | `COMMITTING` + signed `INTENT` before key destruction; `CONFIRMED` after probe; verifier flags unresolved INTENT. Full outbox/reconciliation is not complete. |
| P5 | FIXED | 16-case kill matrix, both methods, KEY_DESTROYED/CONFIRMED; CONFIRMED evidence reconciles to COMMITTED. |
| P6 | PARTIAL | Log file lock and tail reload; work-dir lock / recovery-refuses-live is not implemented. Windows/macOS lock behaviour TO VERIFY. |
| P7 | PARTIAL | Named/large regions, mincore residency, read-error/coverage accounting, SIGSTOP snapshot, and a named-mapping test landed. Single-pass multi-canary scan and a mincore fallback policy remain. |
| P8 | PARTIAL | Witness checks the log head before cosigning; no independent external witness, so A3 remains unreachable. |
| P9 | OPEN | TOCTOU, symlink/hard-link identity, metadata-preserving restore not implemented. |
| P10 | PARTIAL | JVD2 chunked GCM and presenter landed; CLI/UI still duplicate key/log setup. |

## Step 0.3 order

1. Crash points between key destruction and CONFIRMED, both methods.
2. Full OVERWRITE kill matrix.
3. P7 scanner coverage.
4. Recovery reconciliation.
5. Presenter `UNRESOLVED` = amber, plain warning.
6. Windows/macOS lock test or `TO VERIFY`.

## Commands

```bash
export JAVA_HOME=$HOME/tools/jdk-25.0.5+8
export PATH=$JAVA_HOME/bin:$HOME/tools/apache-maven-3.9.16/bin:$PATH
mvn -q verify
```
