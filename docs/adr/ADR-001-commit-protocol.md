# ADR-001 — Commit protocol with durable intent

Status: Accepted for implementation (P4).

## Context

`DestructionTransaction.commit()` destroys the key/vault, then writes evidence, then journals
`COMMITTED`. A crash between key destruction and journal/evidence leaves a transaction that
cannot be restored but looks `VALIDATED`; a log failure leaves a committed transaction with
no evidence. Recovery reads only the journal and cannot reconcile.

## Decision

Introduce one journal state and two evidence event types:

- Journal `COMMITTING` with an intent payload: `eventId`, record hash/bytes, target,
  payload path, key path, method.
- Append an evidence `INTENT` record (idempotent by `eventId`) before destroying the key.
- Destroy the key/vault.
- Probe: target absent; decrypt fails (crypto); vault absent (overwrite).
- Append a `CONFIRMED` evidence record with the same `eventId`.
- Write checkpoint atomically (temp + fsync + rename + parent fsync).
- Append journal `COMMITTED`.
- On failure, journal `UNRESOLVED` or `RESTORE_FAILED`; never claim `COMMITTED`.

Recovery probes facts, never a state name alone:

- key exists + payload exists -> can restore; restore or keep.
- key absent + target absent + `CONFIRMED` evidence -> committed.
- key absent + target exists -> UNRESOLVED; cannot restore.
- `INTENT` without `CONFIRMED`/`ABORTED` -> verifier reports UNRESOLVED.

## Consequences

- Evidence is durable before the irreversible key destruction.
- Recovery can complete or report unresolved without guessing.
- The log contains INTENT and CONFIRMED records; verifiers must understand both.
- More I/O and a larger journal/evidence surface.

## Falsifying test

Kill the process after `INTENT` fsync, after key destruction, after `CONFIRMED`, and after
checkpoint. Recovery must never claim `COMMITTED` without `CONFIRMED`, never delete a vault
when restore failed, and must be idempotent on repeat.
