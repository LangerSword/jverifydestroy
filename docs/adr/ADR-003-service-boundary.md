# ADR-003 — One application service, small ports

Status: Accepted for implementation (P10).

## Context

`DestructionTransaction` owns config, journal, paths, vault, keys, crypto, evidence, log,
checkpoint, witness, and recovery. CLI and UI duplicate key/log/witness setup and already
differ in verification scope. Tests reach into the god object.

## Decision

Keep a small boundary:

```
domain/
  TransactionState (pure transitions)
  DestructionPlan, ValidationOutcome, AssuranceFacts
  ports: Journal, Vault, EvidenceLog, Oracle, Clock, KeyCustody
application/
  JvdService (destroy, recover, verify, explain)
  EvidenceAssembler
infra/
  file, jvm scanner, merkle log, keys
ui/ and cli/ call JvdService only
```

Do not create a module per class. Create a split only where it removes a demonstrated defect:
the commit protocol, the duplicated CLI/UI setup, and the scanner oracle.

## Consequences

- UI/CLI share one code path and cannot drift.
- The state machine is testable without the file system.
- More interfaces; avoid over-abstracting the small project.

## Falsifying test

A CLI and a UI destroy of the same fixture must produce the same evidence facts and the same
presenter message; a test can call `JvdService` directly and assert both shells do not
construct keys/logs themselves.
