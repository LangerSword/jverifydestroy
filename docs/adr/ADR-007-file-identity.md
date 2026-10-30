# ADR-007 — File identity and TOCTOU

Status: Accepted for implementation (P9).

## Context

The target is checked, encrypted, and scrubbed by path. It can be replaced or hard-linked
between steps. Restore loses metadata.

## Decision

Minimum Linux/JDK-only floor:

- Open the target with `NOFOLLOW_LINKS`; reject symlinks.
- Read `unix:ino`, `unix:dev`, `unix:nlink`, `unix:mode` before encryption.
- Re-read the same attributes immediately before scrub; abort if ino/dev/nlink changed.
- Refuse `nlink > 1` (or list the links and require explicit confirmation).
- Hold a `FileLock` on the open file for the transaction; treat it as advisory.
- Restore preserves mode; owner/xattrs are best effort and reported if lost.
- Do not claim openat2/unlinkat unless implemented; if implemented, use `RESOLVE_NO_SYMLINKS`
  and a dirfd, and state the remaining race.

## Consequences

- Accidental symlink/hardlink/replacement races are refused.
- A same-uid malicious process can still race; the evidence says so.
- Restore metadata is narrower than a full backup.

## Falsifying test

Symlink target refused; hard-linked target refused; replacement between vault and scrub
aborts; restore preserves mode; a same-uid race is documented as residual.
