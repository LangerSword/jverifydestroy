# ADR-006 — Key destruction sequence

Status: Accepted for implementation (P3).

## Context

`FileKeyVault.destroy` opens with `TRUNCATE_EXISTING` before writing zeros, releasing the
original blocks. `write` creates the file then chmods 0600, leaving a permission window.

## Decision

- Create key files with `CREATE_NEW` and POSIX `rw-------` as a file attribute, not a
  post-create chmod. Refuse to overwrite an existing key file.
- Destroy by opening `WRITE` (no truncate), overwriting every existing byte with zeros,
  `force(true)`, closing, unlinking, and fsyncing the parent directory.
- Optionally place rollback keys in tmpfs for a 7-day window; document that a reboot loses
  rollback. Do not silently choose tmpfs.
- Report the limit: overwrite-in-place does not defeat ext4 journal/SSD FTL copies.

## Consequences

- No truncate-before-overwrite bug.
- Key file permissions are correct at creation.
- tmpfs is an explicit trade-off, not a default.

## Falsifying test

Unit: `write` twice throws; `destroy` writes zeros over the existing length before unlink
(use a test hook/FileChannel wrapper to observe no truncate option). Manual: ext4 loop image
with `debugfs`/`filefrag`, root required.
