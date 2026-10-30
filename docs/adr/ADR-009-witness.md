# ADR-009 — Witness must verify consistency

Status: Accepted for implementation (P8).

## Context

`Witness.cosign` signs any checkpoint. CLI/UI load the witness public key from the same work
directory, so “witness” is a second local signer, not an independent party.

## Decision

- `cosign(checkpoint, log)` requires: same origin, checkpoint size == log size, root ==
  computed root; otherwise throw.
- Long-term, a witness keeps its last seen size/root and requires a consistency proof from
  that state (C2SP tlog-witness). A local implementation can store the last checkpoint in the
  witness key dir.
- A3 requires a pinned witness public key supplied out-of-band and an offline proof bundle.
- The default A2 path does not claim witness independence.

## Consequences

- A forged checkpoint cannot be cosigned without matching the log.
- The local witness still is not independent; A3 remains unreachable for file transactions.

## Falsifying test

Forged root/size/origin is rejected; valid checkpoint is accepted; a stale witness refuses a
checkpoint without a consistency proof.
