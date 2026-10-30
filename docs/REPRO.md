# REPRO — Phase 0 findings

Date: 2026-10-30
JDK: Eclipse Temurin 25.0.5+8 (LTS)
Kernel: 7.2.11-arch1-1
Filesystem: ext4 on `/dev/nvme1n1p2`
Host: Linux x86_64, 16 logical CPUs, 14 GiB RAM

Method: each finding got a test that asserts the correct behaviour, so it fails on the
current code. The raw Surefire output is below. F3/F4/F7/F8 are confirmed by source,
a measurement, or a documented manual probe where root/raw media is required.

| ID | Verdict | Evidence |
|---|---|---|
| F1 | CONFIRMED | `FindingReproTest.f1ConcurrentRecoverDuringGraceMustNotCommitAsA2` fails: state is `COMMITTED` after an external recovery restored the target. |
| F2 | CONFIRMED | `FindingReproTest.f2FailedRestoreMustKeepVaultAndKey` fails: the container and key are deleted after a failed restore. |
| F3 | CONFIRMED | `FileKeyVault.destroy` opens with `TRUNCATE_EXISTING` before writing zeros; `FileKeyVault.write` creates then chmods. Source lines 18 and 38. |
| F4 | CONFIRMED, then PARTIAL fix | Original scanner skipped named/large regions and had no coverage. P7 now includes all rw mappings, uses mincore residency, records read errors, and scans named mappings; single-pass multi-canary remains. |
| F5 | CONFIRMED | `FindingReproTest.f5TwoStoresMustNotCreateDuplicateSequenceNumbers` fails: two stores write seq 0; reload throws `log gap at 0, expected 1`. |
| F6 | CONFIRMED | `FindingReproTest.f6WitnessMustNotCosignAForgedCheckpoint` fails: `Witness.cosign` signs an arbitrary checkpoint without a consistency check. |
| F7 | CONFIRMED, then FIXED | 16-case matrix now covers STAGED/VAULTED/SCRUBBED/VALIDATED/COMMITTING/KEY_DESTROYED/CONFIRMED/COMMITTED for both methods. |
| F8 | CONFIRMED | OpenJDK `GaloisCounterMode` source says decryption “will buffer all processed outputs internally and won't return them until the tag has been successfully verified.” `CryptoMemProbe` with a 128 MiB container at `-Xmx32m` threw `OutOfMemoryError: Java heap space`. |

## Raw F1/F2/F5/F6 test output

```
[ERROR] Tests run: 4, Failures: 4, Errors: 0, Skipped: 0
[ERROR] f2FailedRestoreMustKeepVaultAndKey:73 vault/container must survive a failed restore
        ==> expected: <true> but was: <false>
[ERROR] f5TwoStoresMustNotCreateDuplicateSequenceNumbers:88
        Unexpected exception thrown: java.lang.IllegalStateException: log gap at 0, expected 1
[ERROR] f1ConcurrentRecoverDuringGraceMustNotCommitAsA2:54
        must not commit after an external recovery ==> expected: not equal but was: <COMMITTED>
[ERROR] f6WitnessMustNotCosignAForgedCheckpoint:97
        Expected java.lang.IllegalArgumentException to be thrown, but nothing was thrown.
```

## F3 — key destroy truncates before overwriting

`destroy-file/src/main/java/io/jvd/file/FileKeyVault.java`:

```java
Files.write(path, key, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, ...);
...
var ch = java.nio.channels.FileChannel.open(path,
        StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
ch.write(ByteBuffer.wrap(zeros));
ch.force(true);
```

`TRUNCATE_EXISTING` releases the original blocks before the zero write. The zero write then
goes to newly allocated blocks (or a short file), leaving the old key bytes in free space.
`write` also creates the file before setting 0600, so the file briefly has the process umask
permissions.

Manual confirmation requires a loop-mounted ext4 image and root, or `debugfs` on an image;
the agent's hardline guard blocks `mkfs.ext4`. The source sequence is unambiguous.

## F4 — scanner coverage

`MemoryScanner.scan`:

- `bytes += len` before any read, so `bytes` is mapped, not read.
- `catch (IOException e) { break; }` silently stops a region and keeps scanning.
- `if (e > s && e - s <= (1L << 31)) regions.add(...)` drops every region > 2 GiB.
- `if (!path.isEmpty() && !path.equals("[heap]") && !path.startsWith("/memfd:")) continue;`
  skips every other named mapping.
- `CanaryVerifier.validate` calls `MemoryScanner.scan` three times (target, positive,
  negative) while the child runs, so GC can move objects between passes.

`spikes/MapCoverage.java` output:

```
=== G1 ===
regions=77 total=379539456 named=16908288 (4.5%) unnamed=362631168 (95.5%) skipped=16908288 (4.5%) namedRegions=19
=== ZGC ===
regions=70 total=317562880 named=266330112 (83.9%) unnamed=51232768 (16.1%) skipped=14671872 (4.6%) namedRegions=19
```

The ZGC heap is `/memfd:java_heap` and is included by the scanner; the skipped 4.6% is
file-backed JARs/libs and the 1 MiB named file mapping. A canary placed only in a named
mapping is invisible even though it is mapped into the process.

## F7 — crash-point coverage

`Kill9RecoveryTest` calls `CrashChild` with `CRYPTO_SHRED` only and `jvd.crashAt` values
`STAGED`, `VAULTED`, `SCRUBBED`, `VALIDATED`, `COMMITTED`. `commit()` performs key
destruction, evidence append, checkpoint write, and journal append before the `COMMITTED`
hook. No test crashes between those steps. `OVERWRITE` has no kill-9 test.

## F8 — GCM decryption buffers the whole ciphertext

OpenJDK `GaloisCounterMode.java` (master, read 2026-10-30):

```
NOTE: Unlike other modes, when used for decryption, this class
will buffer all processed outputs internally and won't return them
until the tag has been successfully verified.
...
we are bound by limiting the data size to the size limit of
java byte array, e.g. Integer.MAX_VALUE, since all data
can only be returned by the doFinal(...) call.
```

`spikes/CryptoMemProbe.java`, 128 MiB container, `-Xmx32m`:

```
encrypted 128MiB, heap=32MiB
OOM: Java heap space
```

This confirms the failure mode for large restores. The exact 2 GiB / 512 MiB figure was not
run (it would take a long time and disk); the source plus the 128 MiB measurement is enough
to treat the risk as real.

## Reproduce

```bash
cd ~/projects/jverifydestroy
export JAVA_HOME=$HOME/tools/jdk-25.0.5+8
export PATH=$JAVA_HOME/bin:$HOME/tools/apache-maven-3.9.16/bin:$PATH
mvn -q -pl txn -am test -Dtest=FindingReproTest -Dsurefire.failIfNoSpecifiedTests=false
```

The four tests fail on the current commit. They are the Phase 0 evidence; the P1/P2/P6/P8
patches make them pass without weakening any existing test.

## Resolution status after P1–P10 (this pass)

| ID | Status | What changed |
|---|---|---|
| F1 | FIXED | `commit()` preflights `Files.exists(target)` and refuses to destroy the key; post-checks no longer set `COMMITTED`; an `UNRESOLVED` state records a failed post-check. |
| F2 | FIXED | `rollback()` and `Recovery` add `RESTORE_FAILED`; they keep the vault and key when restore fails. The failing test now passes. |
| F3 | FIXED (unit) | `FileKeyVault.destroy` opens without truncation and overwrites every existing byte; `write` uses `CREATE_NEW` with 0600 at creation. Manual ext4 block inspection is still TO VERIFY. |
| F4 | PARTIAL | P7 now includes named/large mappings, records coverage/read errors, and uses mincore residency; single-pass multi-canary and a mincore fallback policy remain. |
| F5 | FIXED | `LogStore.append` takes a JVM lock plus a file lock on `log.lock` and reloads the tail before assigning seq. |
| F6 | FIXED | `Witness.cosign(checkpoint, log)` verifies origin, size, and root before signing; the old `cosign(checkpoint)` throws. |
| F7 | FIXED | 16-case kill matrix: 8 points x 2 methods, including KEY_DESTROYED and CONFIRMED; CONFIRMED evidence reconciles to COMMITTED. |
| F8 | FIXED | JVD2 chunked GCM with per-chunk tags; 128 MiB decrypts at `-Xmx32m` (`CryptoMemProbe`). JVD1 remains read-only and still buffers. |

`FindingReproTest` now passes all four tests. The existing tests were not weakened.
