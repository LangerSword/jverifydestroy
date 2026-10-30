# ADR-008 — Scanner snapshot and coverage

Status: Accepted for implementation (P7).

## Context

The scanner counts mapped bytes as scanned, silently drops unreadable regions and regions
>2 GiB, skips named mappings, and scans three times while GC can move objects.

## Decision

- Stop the child (`SIGSTOP` via FFM `kill`) before the scan; scan all canaries in one pass;
  resume (`SIGCONT`).
- Include every readable `rw` mapping, including named and large mappings; skip only
  non-readable or special regions with a recorded reason.
- Track `bytesMapped`, `bytesRead`, `readErrors`, `regionsSkipped`.
- If coverage (bytesRead/bytesMapped) is below a policy threshold, or a required region
  cannot be read, return `NOT_CHECKABLE` with the exact reason; never `NOT_FOUND`.
- Scan each canary in the same stopped snapshot.

## Consequences

- Coverage is measurable and honest.
- Large/named mappings no longer produce false `NOT_FOUND`.
- SIGSTOP is Linux-specific and adds complexity; the CLI is Linux-first.

## Falsifying test

Induce an unreadable region and a >2 GiB mapping; named mapping containing a canary must be
found; coverage below threshold must be `NOT_CHECKABLE`; three canaries must be scanned in one
stopped snapshot.
