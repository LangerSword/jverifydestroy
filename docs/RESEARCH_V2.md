# RESEARCH V2 — primary sources and measurements

Date: 2026-10-30
Environment: JDK 25.0.5+8, Linux 7.2.11-arch1-1, ext4, x86_64, 16 CPUs, 14 GiB RAM.
Every claim below is either read in a primary source, measured on this host, or marked
TO VERIFY. Vendor blogs are not used as load-bearing evidence.

## a. Does SunJCE AES/GCM decrypt release plaintext before tag verification?

**Answer: no.** OpenJDK’s `GaloisCounterMode` source says, for decryption, it “will buffer all
processed outputs internally and won't return them until the tag has been successfully
verified.” It also notes that recovered text is bound by the size limit of a Java byte array,
because all data is returned by `doFinal(...)`.

Primary source: https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/GaloisCounterMode.java
(lines 55–56 and the `MAX_BUF_SIZE` comment).

Consequence for this project: `CryptoShredder.decrypt` streams ciphertext into
`Cipher.update`, but SunJCE holds the plaintext internally until `doFinal`. A 128 MiB
container at `-Xmx32m` threw `OutOfMemoryError` (`spikes/CryptoMemProbe.java`). The 2 GiB /
512 MiB case was not run, but the source shows the same linear buffering.

What the JDK recommends for large GCM payloads: no public JDK guidance was found that says
“use GCM for multi-gigabyte files”. The safe design is chunked AEAD: split the file into
fixed-size chunks, use a unique nonce per chunk, and authenticate the chunk index and final
flag (STREAM construction; Hoang, Reyhanitabar, Rogaway, Vizár, “Online
Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance”, CRYPTO 2015,
https://eprint.iacr.org/2015/189). Each chunk can be verified and released independently;
a truncated file is detected by the final-chunk flag/length.

Decision for ADR: keep JVD1 for small files, introduce JVD2 chunked AEAD before claiming
large-file restore, or cap the supported file size and refuse rather than OOM. If JVD2 is
introduced, `canDecrypt` must verify every chunk tag without writing plaintext.

**Adversarial review.** Strongest counterargument: the JDK could change to release plaintext
after each chunk, or a provider other than SunJCE could stream. Why I still hold it: the
source is the current JDK 25 implementation and the measured OOM confirms the behavior for
the provider this project uses. A different provider is not a defense unless the code pins
and tests it.

## b. truncate-then-write vs overwrite-in-place; safest user-space key destruction

`FileKeyVault.destroy` currently opens with `TRUNCATE_EXISTING` and then writes zeros. On a
POSIX file system, truncation changes the file size and releases the old blocks before the
new write; the zeros may land on different blocks. That is the wrong order for key
destruction.

The safest user-space sequence available here is:

1. Open the key file without truncation.
2. Overwrite all existing bytes in place with zeros (multiple passes are not justified by
   NIST for this case; one in-place zero pass is the measurable action).
3. `force(true)` (fsync) the file data.
4. Close, unlink the path.
5. fsync the parent directory so the unlink is durable.

This still does not guarantee physical erasure: ext4 may journal data, delayed allocation
may have written the key to a different block, and the SSD FTL may retain the old block.
The kernel ext4 documentation describes journaling and allocation behavior, not a guarantee:
https://docs.kernel.org/admin-guide/ext4.html. `fsync(2)` and `rename(2)` define durability,
not overwrite semantics: https://man7.org/linux/man-pages/man2/fsync.2.html and
https://man7.org/linux/man-pages/man2/rename.2.html.

tmpfs-resident rollback keys: a key file in tmpfs is not written to the ext4 block device,
so there is no ext4 block to recover after a crash/power loss. It is lost on reboot, which
means rollback is unavailable across a reboot. This is a useful *option* for a short grace
window, not a universal replacement for a durable vault key. It also does not protect
against swap/core dumps unless `mlock`/`MADV_DONTDUMP` are used.

**TO VERIFY:** btrfs/XFS exact block-release behavior and whether `fallocate`/`FALLOC_FL_ZERO_RANGE`
is preferable. The host root is ext4; a btrfs/XFS loop test needs a filesystem image and root,
which this agent cannot create (`mkfs` is blocked).

**Adversarial review.** Counterargument: on ext4 with data=ordered, overwriting in place may
still be journaled, so the “safe” sequence is not safe either. Correct — that is why the
README must say logical-level only. The change is still worth making because truncate-first
is strictly worse: it releases the original blocks before any overwrite.

## c. `/proc/<pid>/maps` naming, skipped memory, ptrace/SIGSTOP

Measured with `spikes/MapCoverage.java` (rw mappings, a 64 MiB heap, a 1 MiB named file
mapping):

```
G1:  total=379539456  named=16908288 (4.5%)   skipped(non-memfd named)=16908288 (4.5%)
ZGC: total=317562880  named=266330112 (83.9%) skipped(non-memfd named)=14671872 (4.6%)
```

ZGC’s heap is `/memfd:java_heap`; `MemoryScanner` includes `/memfd:`, so the 83.9% named
figure is not all skipped. The skipped 4.5–4.6% is file-backed JARs/libs plus the named file
mapping. A canary placed only in a named mapping is invisible. The current scanner also
drops any region > 2 GiB, and its `bytes` count is mapped length, not bytes actually read.

ptrace/Yama: on this host `/proc/sys/kernel/yama/ptrace_scope` is `1` (restricted ptrace).
A parent may attach to its child; a sibling may not. The parent/child design already relies
on that. `proc(5)` documents `/proc/<pid>/mem` and maps:
https://man7.org/linux/man-pages/man5/proc.5.html. Yama is documented at
https://docs.kernel.org/admin-guide/LSM/Yama.html.

SIGSTOP: `kill(2)` can stop a child before the scan and `SIGCONT` resume it:
https://man7.org/linux/man-pages/man2/kill.2.html. Java has no public `ProcessHandle` signal
API, so the project would need a small FFM downcall to `kill` (Linux-only, accepted by the
brief) or a helper process. A single stopped snapshot removes the three-pass GC race.

**Adversarial review.** Counterargument: stopping the child perturbs the JVM and may itself
trigger safepoints; true, but it gives a consistent virtual-memory image and is measurable.
The alternative — three live passes — is known to race. A stopped process is the lesser
measurement error.

## d. Safe file identity from JDK-only code

Available in the JDK:

- `LinkOption.NOFOLLOW_LINKS` on `Files.readAttributes`, `Files.newByteChannel`,
  `Files.delete` (for symlink handling).
- `Files.readAttributes(path, "unix:ino,dev,nlink,mode", NOFOLLOW_LINKS)` on Linux.
- `FileChannel.lock()` / `tryLock()` for an advisory lock on an open file.
- `Files.isSameFile(a, b)` for a path-level identity check (still TOCTOU-prone).

`openat2(2)` with `RESOLVE_NO_SYMLINKS` is available on Linux 5.6+:
https://man7.org/linux/man-pages/man2/openat2.2.html. `unlinkat(2)` can unlink relative to a
directory fd; both can be reached through the FFM Linker. The remaining race after opening
an fd with `O_NOFOLLOW` and verifying `fstat` is that the path can be renamed/replaced after
the check; operating on the fd (not the path) for read/overwrite, and using `unlinkat` on the
parent dirfd with the expected name, is the closest user-space fix. Hard links still mean
another name references the same inode; `nlink > 1` must be reported/refused or the other
links must be found and handled. A file lock is advisory and does not stop rename/unlink.

**Adversarial review.** Counterargument: none of this is a true security boundary against a
malicious same-uid process; correct. It reduces accidental races and makes the tool honest
about links; it does not defeat an attacker who already has the same UID.

## e. Witness design and A3

C2SP’s witness protocol says a witness verifies that a checkpoint is consistent with its
previously recorded state and returns a timestamped cosignature:
https://github.com/C2SP/C2SP/blob/main/tlog-witness.md. The checkpoint format is
https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md. RFC 9162 defines the Merkle tree
and consistency proofs: https://www.rfc-editor.org/rfc/rfc9162.txt.

Therefore a witness that signs an arbitrary checkpoint without checking consistency is not a
witness; it is a second signer. Honest A3 needs:

- a pinned witness public key supplied by the verifier, not loaded from the same work dir;
- a consistency proof from the witness’s last seen size/root to the new checkpoint;
- a checkpoint signature over the C2SP note text (or a clearly versioned equivalent);
- an offline proof bundle containing the checkpoint and cosignature.

**Adversarial review.** Counterargument: a local witness still detects accidental corruption
and naive edits; true, but it does not support the split-view claim. The README must not call
it independent.

## f. Crash-consistency primitives

For a new file: write data, `fsync(file)`, then `fsync(parent directory)` so the directory
entry is durable. For a rename: write the temp file, `fsync(temp)`, `rename`, `fsync(parent)`.
For an unlink: `unlink`, `fsync(parent)`. For a checkpoint: write temp, `fsync(temp)`,
`rename`, `fsync(parent)`. These are the operations described by `fsync(2)` and `rename(2)`
(links above); ext4’s `auto_da_alloc` behavior is a heuristic, not a contract.

Current gaps: `Journal` fsyncs the file but not the parent after creation; `LogStore` fsyncs
the log but `writeCheckpoint` uses `Files.writeString` without fsync; `FileKeyVault.write`
does not fsync; `CryptoShredder` forces the container but not the parent directory.

**Adversarial review.** Counterargument: directory fsync is expensive and many apps omit it;
true, but this project’s claim is evidence durability, so it is load-bearing.

## g. Commit protocols with idempotent evidence

The transactional outbox pattern records the intent in the same durable transaction as the
state change, then a relay publishes it idempotently:
https://microservices.io/patterns/data/transactional-outbox.html. The same shape applies here:
journal an `INTENT` with a stable `eventId` and evidence bytes/hash, perform the destructive
step, then append `CONFIRMED` evidence idempotently by `eventId`. Recovery can probe the key,
payload, and log to decide whether to complete or roll back. This is a local, file-based
outbox, not a database or network.

**Adversarial review.** Counterargument: a file-based outbox still has a crash window between
the journal fsync and the key destruction; correct, but the intent is durable, so recovery can
decide from facts instead of guessing from a state name. That is the improvement.

## Summary of decisions this research forces

1. GCM decryption cannot stream plaintext on this JDK; chunked AEAD or a size cap is required.
2. Truncate-first key destruction is wrong; overwrite-in-place, fsync, unlink, fsync parent.
3. A stopped single-pass scan is safer than three live passes; coverage must be measured.
4. Path-based file operations are TOCTOU-prone; fd + `NOFOLLOW` + `nlink` check is the floor.
5. A local second key is not an independent witness; A3 must say so or use a pinned external one.
6. The journal must carry an intent so recovery decides from facts, not a state label.


## Post-research implementation note

F8 was confirmed and JVD2 was implemented in this pass: 1 MiB independently authenticated GCM
chunks with a unique nonce prefix+counter and AAD binding the chunk index/final flag.
`spikes/CryptoMemProbe` decrypts 128 MiB at `-Xmx32m`; JVD1 remains readable but still buffers.
F3 was fixed in code (overwrite-in-place, no truncate-first; 0600 at create). F4/F7/P9 remain
open or partial; see `docs/REPRO.md`.
