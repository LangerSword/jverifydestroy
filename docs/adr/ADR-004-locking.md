# ADR-004 — Work-dir and log locking

Status: Accepted for implementation (P6).

## Context

`LogStore` appends by in-memory size with no file lock; two writers produce duplicate seq and
brick the log. Recovery can run concurrently with a live transaction and restore a file
during its grace window.

## Decision

- One `FileLock` on `<work>/lock` for the work directory; every destructive/recovery operation
  takes it. A live transaction holds it from `STAGED` to `COMMITTED`/`ABORTED`.
- `LogStore.append` takes a JVM lock per path plus a `FileLock` on `<log>/log.lock`, reloads
  the tail, then appends.
- Recovery refuses if the work-dir lock is held by a live PID; records `BUSY`/`REFUSED`.
- The lock file is never deleted.

## Consequences

- Concurrent CLI/UI runs fail safely instead of corrupting the log.
- A crashed process releases the OS lock; stale PID is not trusted alone.
- File locks are advisory and do not stop arbitrary writes; this is a correctness guard, not
  a security boundary.

## Falsifying test

Two `LogStore` instances append concurrently; the log reloads with contiguous seqs. A second
recovery while the work-dir lock is held is refused.
