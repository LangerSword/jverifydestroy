# Empirical Spikes — H1–H6

Host: Arch Linux, kernel 7.2.11-arch1-1, x86_64, 16 logical CPUs, 14 GiB RAM.
JDK: Eclipse Temurin 25.0.5+8 (LTS), `java -version` reports `25.0.5 2026-10-20 LTS`.
Maven: Apache Maven 3.9.16 (downloaded; not on PATH).
Filesystem: `/` is ext4 on `/dev/nvme1n1p2`.
All probes are in `spikes/` and were compiled with `javac` from the same JDK.

The rule for every memory experiment: a trial is VALID only if the positive control
(an unwiped canary) is FOUND and the negative control (a value never written) is NOT_FOUND.
An INVALID trial is reported as such, never counted as a success.

## H1 — does `Arrays.fill` survive JIT compilation?

Probe: `spikes/MemProbe.java`, modes `hold`, `wipe`, `wipegc`, `move`, `hot`, `publish`,
`publishAfter`, `publishRead`. Each trial runs a child JVM; the parent scans the child’s
`/proc/<pid>/mem` for a masked canary. 20 trials per cell in the matrix run (see the
summary file `experiments/out/` once the experiment module is built).

Initial version of the probe found the canary after a plain `wipe`. Root cause was not the
JIT: the helper returned `Arrays.copyOf(md.digest(in), 32)` and never wiped the 32-byte
digest output. That is a real Java leak pattern (a helper copy the caller never sees).
After wiping the digest output:

```
hold            5/5 FOUND        (positive control)
wipe            0/5 FOUND
wipegc          0/5 FOUND
move            0/5 FOUND (G1)
hot             0/10 FOUND (G1)
publish         0/5 FOUND
publishAfter    0/5 FOUND
publishRead     0/5 FOUND
```

`hot` runs 2,000,000 `Arrays.fill(target, 0)` calls on a 4 KiB array held in a static field.
`publish` stores the array in a `volatile` field before the wipe, so the allocation cannot be
scalar-replaced and the fill is observable to another thread. `publishAfter` publishes after
the fill. `publishRead` reads one byte after the fill.

**Conclusion.** No evidence that C2 removes an `Arrays.fill` on a reachable or published
array. The report’s H1 is not reproduced as a practical risk. A *non-escaping* array can be
eliminated entirely (allocation + fill), which is memory-safe but unobservable; the verifier
must not treat “not found” as proof when it cannot prove the canary was ever in memory —
hence the positive control is mandatory. The correct library rule is: wipe, publish/fence,
then validate; never claim a guarantee.

A separate self-scan probe (`spikes/MinimalSelf.java`) initially appeared to show residue
after a wipe. The residue was the scanner’s own 1 MiB read buffer, which contained the
target bytes. That is H4, not H1.

## H2 — stale copies after garbage collection

Probe: `MemProbe` mode `move`: allocate a 4 KiB canary array, keep it live, `System.gc()`
(forcing a move/promotion), then `Arrays.fill(array, 0)`, drop the reference, `System.gc()`,
and scan. `hot` is the JIT-hot-loop mode. 10 trials per cell (the 20-trial matrix is running;
the numbers below are the completed 10-trial runs).

| Collector | `move` FOUND / valid | `hot` FOUND / valid |
|---|---|---|
| Serial | 10 / 10 | 0 / 10 |
| Parallel | 10 / 10 | 0 / 10 |
| G1 | 0 / 10 | 0 / 10 |
| ZGC | 0 / 3 (after fixing the `UseZGCGC` flag; earlier run INVALID) | 0 / 10 |
| Shenandoah | 10 / 10 | 0 / 10 |

Raw example (`Serial`, one trial):

```
move,Serial,,0,FOUND,FOUND,NOT_FOUND,VALID,1
move,Serial,,1,FOUND,FOUND,NOT_FOUND,VALID,1
...
SUMMARY,move,Serial,,valid=10,invalid=0,found=10,rate=1.0000
```

**Conclusion.** H2 is CONFIRMED for Serial, Parallel, and Shenandoah: a copying collector can
leave a stale copy of a moved array in from-space; wiping the live reference does not remove
it. G1 and ZGC did not exhibit it in this micro-test. The result is collector-dependent and
must be measured, not assumed. This is the strongest argument for the verifier: “wiped” is a
claim about a reference, not about the process’s memory.

ZGC note: its heap is mapped as `/memfd:java_heap`, not an anonymous mapping. A scanner that
only reads anonymous `rw-p` regions will report NOT_FOUND for ZGC even for an unwiped canary.
The scanner must include `/memfd:java_heap` and must make the positive control mandatory.

## H3 — `jcmd GC.heap_dump` and unreachable objects

Probe: `spikes/HeapDumpProbe.java`. Child allocates a 4 KiB array containing a canary, drops
it without GC, and holds. Parent runs `jcmd <pid> GC.heap_dump` in different orders.

`jcmd <pid> help GC.heap_dump` (JDK 25):

```
-all : [optional] Dump all objects, including unreachable objects (BOOLEAN, false)
```

Results, fresh child for each dump mode:

```
=== default dump only ===
/proc before dump: FOUND(1)
hprof default: NOT_FOUND size=5172045
/proc after  : NOT_FOUND

=== -all dump only ===
/proc before dump: FOUND(1)
hprof -all   : FOUND size=8832121
/proc after  : FOUND(1)

=== default then -all in the same process ===
/proc before dump: FOUND(1)
hprof default: NOT_FOUND
hprof -all   : NOT_FOUND   <-- the default dump's full GC already collected the object
```

**Conclusion.** H3 CONFIRMED, with a trap: `-all` does include unreachable objects (8.8 MB
dump vs 5.17 MB), but the default dump performs a full GC first and can destroy the evidence.
Never run the default dump before `-all` in the same process. For the verifier, `/proc/<pid>/mem`
is the primary memory source; a heap dump is a secondary, `-all`-only artifact, and the tool
must record that a default dump is not a complete memory image.

## H4 — the scanner finds itself

Probe: `spikes/SelfScanProbe.java`, `spikes/MinimalSelf.java`.

```
naive self-scan (raw held): FOUND (self-match)
masked self-scan (raw wiped): FOUND (bad)
masked child scan: FOUND (good)
```

The “bad” result is not a failure of masking. The scanner reads the target’s memory into a
1 MiB heap buffer; that buffer still contains the canary after the scan returns, so scanning
your own process finds the scanner’s buffer. Masking the needle only prevents the scanner’s
*needle* from matching; it does not remove the read buffer.

MinimalSelf printed the matching bytes at the same address before and after the wipe:

```
match at 711619110 bytes=a0a1a2a3a4a5a6a7
after wipe, masked=true
match at 711619110 bytes=a0a1a2a3a4a5a6a7
```

**Conclusion.** H4 CONFIRMED. Required mitigation: (1) the scanner runs in a parent process
and scans a separate child JVM, never itself; (2) the scanner derives a masked needle and
wipes the raw canary immediately; (3) the scanner wipes each read buffer after use (best
effort); (4) the victim must wipe every helper copy, including digest outputs, not just the
array it thinks of as “the secret”. The first H1 probe demonstrated (4) by accident: the
un-wiped `MessageDigest.digest()` output was found after the visible array was wiped.

## H5 — mlock and MADV_DONTDUMP from user-space Java

Probe: `spikes/FfmProbe.java` on JDK 25 with `--enable-native-access=ALL-UNNAMED`.
`ulimit -l` is 8192 KiB on this host. A 4 KiB `Arena.ofConfined()` segment was mlocked and
marked `MADV_DONTDUMP` via libc downcalls.

```
segment at 0x7f5ad419d000
mlock=0 madvise(DONTDUMP)=0
VMA: 7f5ad419d000-7f5ad419e000 rw-p 00000000 00:00 0
Locked:                4 kB
VmFlags: rd wr mr mw me lo ac dd sd
```

**Conclusion.** H5 CONFIRMED. `mlock` and `madvise(MADV_DONTDUMP)` work through the FFM
Linker, and `/proc/self/smaps` shows `lo` (locked) and `dd` (do-not-dump). Limits: only
8 MiB can be locked under the default `RLIMIT_MEMLOCK`; mlock is not a confidentiality
boundary against a privileged attacker; `MADV_DONTDUMP` affects the containing VMA, not just
the segment. The `SecretBuffer` API will expose this as best-effort hardening and will fall
back with a recorded reason when mlock fails.

## H6 — ext4 delete and overwrite residue

Status: **PARTIAL / NOT COMPLETED.** The probe `spikes/ext4_probe.sh` creates a 32 MiB ext4
image, writes an 8 KiB random canary with `debugfs`, scans the image, deletes the file, and
scans again. The delete-only run completed and showed:

```
== delete only ==
before delete: FOUND at 0x24e000
after delete : FOUND at 0x24e000
```

The overwrite passes did not run: the `debugfs stat` block-range parser returned empty, and
the agent’s hardline guard blocks a direct `mkfs.ext4` invocation. The script is kept for a
human to run outside the agent; it is not cited as a completed experiment.

**What this does and does not show.** It shows the logical-level point on a real ext4 image:
unlink leaves the file’s bytes in the image. It does not show that overwrite+fsync removes
them (the overwrite branch did not run), and it does not touch the SSD FTL, journal copies,
snapshots, or bad-block pools. The library will label file overwrite as NIST **Clear** and
weak on flash, and its file validation will return NOT_CHECKABLE unless the caller supplies
a raw image to scan. No claim of physical erasure will be made.

The report’s Wei et al. figure was checked in the primary PDF: “between 4% and 75% of the
files’ contents remained on the SATA SSDs” after single-file overwrite protocols, and USB
drives were no better (0.57%–84.9%). That is a hardware-level result and is cited as such,
not as a Java finding.

## C-9 probe — SecretKeySpec cannot be destroyed

`spikes/DestroyProbe.java`:

```
isDestroyed before=false
destroy threw javax.security.auth.DestroyFailedException: null
isDestroyed after=false
```

**Conclusion.** `SecretKeySpec` implements `Destroyable` but inherits the default `destroy()`
that always throws. A crypto-shred implementation must not rely on `Destroyable.destroy()` to
erase key bytes; it must own the key bytes (off-heap or a byte[]) and wipe them explicitly.
