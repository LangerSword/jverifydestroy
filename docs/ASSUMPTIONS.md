# Assumptions

Every ambiguity resolved by choosing the simplest defensible option. If an assumption is
wrong, the code or the docs must be changed, not quietly ignored.

| # | Assumption | Why |
|---|---|---|
| A1 | Target JDK is Eclipse Temurin 25.0.5+8; `--release 25`. | Newest LTS on the host; FFM is final. The host’s default `java` is 21, so scripts set `JAVA_HOME` explicitly. |
| A2 | Build tool is Apache Maven 3.9.16, downloaded to `~/tools`; JUnit Jupiter 5.11.4; Surefire 3.5.2. | Maven is not installed system-wide; these versions are available and stable. |
| A3 | One transaction destroys one regular file. Directories are rejected. | Keeps the state machine and rollback semantics testable; recursive destruction is a feature cut. |
| A4 | Crypto-shred container format: magic `JVD1` (4 bytes), 12-byte GCM IV, ciphertext+tag. The 32-byte DEK lives in a separate `0600` key file. AAD is `JVD1` + transaction id, not the path. | Simple, JDK-only, path-move tolerant. The container is not self-contained by design: losing the key is the shred. |
| A5 | Rollback vault: AES-256-GCM encrypted copy of the original under a random 32-byte vault key stored in a `0600` file. The journal never contains key bytes. | Crash recovery needs the key on disk; keeping it out of the journal limits accidental log leakage. |
| A6 | Journal is JSONL, one event per line, `FileChannel.force(true)` after each append. Recovery reads the last parseable line per transaction. | Append-only, simple, crash-tolerant; no database dependency. |
| A7 | Crash injection uses the system property `jvd.crashAt=<STATE>` and calls `Runtime.getRuntime().halt(137)` immediately after the state is journaled. It is enabled only when the property is set. | Lets tests kill the JVM at exact states without a debugger; production code path is a no-op when unset. |
| A8 | For FILE_OVERWRITE, the required checks are: overwrite completed, file path absent. A raw-image residue scan is optional; if no image is supplied the result is `NOT_CHECKABLE` and recorded, but the transaction may still COMMIT under policy `ALLOW_LOGICAL`. For CRYPTO_SHRED, decrypt-failure is required. | The report’s “NOT_CHECKABLE on a required check → rollback” leaves “required” undefined. This definition is honest about what is actually checked. |
| A9 | The memory scanner reads only `rw` mappings that are anonymous, `[heap]`, or `/memfd:`. Other file-backed mappings are skipped. ZGC’s `/memfd:java_heap` is included. | H2/H3 showed the heap can be anonymous or memfd; scanning every file-backed JAR would add noise without finding a Java heap copy. |
| A10 | Canary = first 32 bytes of `SHA-256(seed || label)`; the scanner stores only `canary XOR 0x5A` and compares `(targetByte XOR 0x5A)` to it. | No HMAC key management; adequate for a test oracle. Masking prevents the needle itself from being the match. |
| A11 | The victim is a child JVM started by the parent verifier, with the parent’s classpath. The child prints `READY <pid>` and waits for one stdin line. The parent kills it after scanning. | Gives a real second process; avoids self-scan false positives (H4). |
| A12 | Log origin is `jvd.local/<random log id>`; checkpoints are JSON `{origin,size,rootHash,signature,witness}`. | C2SP-style note content without implementing the full note parser. |
| A13 | The witness is a second Ed25519 key file, and its cosignature includes a timestamp string. The verifier checks the signature; it does not treat the timestamp as trusted time. | No network and no independent service in scope. The limitation is documented. |
| A14 | Evidence timestamps are informational UTC ISO-8601 strings. They are covered by the signature but are not a trusted-time proof. | Trusted time needs an external timestamp authority; out of scope. |
| A15 | Default overwrite is one zero pass + fsync + delete, labelled NIST Clear. Optional 3-pass (`0x00`, `0xFF`, random) is offered for compatibility, not because it is stronger on flash. | NIST Rev.2 warns against unnecessary passes; one pass is the simplest Clear. |
| A16 | `StringMisuseDemo` does not try to wipe a `String`. It demonstrates that the value survives and recommends `char[]`, `byte[]`, or `SecretBuffer`. | C-11: String is immutable. Pretending otherwise would be dishonest. |
| A17 | Tests use `target/tmp` as `java.io.tmpdir` (set in Surefire), not `/tmp`. | Matches the host’s scratch-file convention and keeps test residue inside the build. |
| A18 | The library makes no network calls at runtime. Maven may download build plugins/dependencies. | The brief forbids network calls in the product, not in the build. |
| A19 | Key files are text `ed25519:<base64>` with `0600` permissions. No PEM/JKS parsing. | JDK-only, easy to inspect, no external dependency. |
| A20 | JSON values are objects, arrays, strings, booleans, null, `long`, and `double`; timestamps are strings. Canonical JSON sorts object keys and uses no whitespace. | Deterministic bytes for signatures and Merkle leaves. |
| A21 | A log leaf is one canonical evidence-record JSON object; the log does not store arbitrary blobs. | Keeps the log schema and the evidence schema aligned. |
| A22 | `jvd-verify` exit codes: 0 = valid, 1 = invalid/tamper, 2 = usage or I/O error. | Scriptable and unambiguous. |
| A23 | Experiments target N=200 per cell. A cell may be reduced only if the runtime is prohibitive, and then the CSV records the actual N and the Wilson CI; the docs never report a reduced cell as if it were 200. | Honest statistics; no silent truncation. |
| A24 | `docs/RESULTS.md` is generated from CSV produced by real runs; no hand-entered numbers. | The brief’s “generated only from real runs” rule. |
| A25 | No claim of physical erasure is made at any assurance level. “A3” is logical-level validation plus evidence, not hardware attestation. | User-space Java cannot see the FTL; the README says this on every relevant page. |
| A26 | The file destroyer writes patterns through a `FileChannel` at absolute positions, calls `force(true)`, then deletes. It does not attempt `fallocate`, `ioctl`, or TRIM. | JDK-only and portable; those operations need native/privileged access. |
| A27 | A crash between the last journal write and the side effect is treated as “state not reached”; recovery re-does or rolls back from the last journaled state. | Standard write-ahead ordering: journal first, then act. |
| A28 | `COMMITTED` is irreversible. The code path that deletes the vault/key has no inverse, and the CLI refuses `restore` after COMMIT. | The brief’s hard rule; also the security property. |

| A29 | A commit writes a signed `INTENT` evidence record and checkpoint before destroying the key/vault, then a `CONFIRMED` record with the same `eventId`. | Makes the irreversible step recoverable/auditable; an `INTENT` without resolution is `UNRESOLVED`. |
| A30 | New crypto containers use JVD2: 1 MiB independently authenticated GCM chunks, a unique nonce prefix+counter, and AAD binding chunk index/final flag. JVD1 remains readable but is not created. | SunJCE buffers all GCM decryption output until `doFinal`; chunking avoids the heap limit. |
| A31 | A failed restore keeps the vault and key and records `RESTORE_FAILED`; a post-check failure records `UNRESOLVED`, never `COMMITTED`. | Losing the only recovery copy or claiming a false commit is worse than reporting an uncertain state. |
