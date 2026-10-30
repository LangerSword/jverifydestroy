# ADR-002 — Assurance levels from facts, not method

Status: Accepted for implementation (P2).

## Context

`record.assurance = cfg.method().ceiling()` means a failed post-check can still be recorded
as A2. `A3` exists in the enum but no code path emits it. Levels are labels, not derived.

## Decision

Define `AssuranceFacts`:

```
controlsValid                 // memory subject only; N/A for file
keyDestroyedAndDecryptFails   // crypto
targetAbsent
bornEncrypted                 // CE precondition; false for ordinary files
keyCustody                    // LOCAL | EXTERNAL_VERIFIED
externalWitnessVerified       // pinned witness + consistency proof
independentRevalidation       // separate process re-ran the oracle
overwriteCompleted            // overwrite method
```

Mapping:

- A0: nothing established.
- A1: overwriteCompleted + targetAbsent; physical media NOT verified.
- A2: crypto + keyDestroyedAndDecryptFails + targetAbsent + (controlsValid if memory).
- A3: A2 + externalWitnessVerified + independentRevalidation + keyCustody=EXTERNAL_VERIFIED.
- A3 is never emitted for a file transaction in this scope; it is memory-only until a real
  external witness exists.

The level is computed after post-checks and stored with the facts in the evidence record.
A failed post-check yields A0 and `UNRESOLVED`, not `COMMITTED`.

## Consequences

- A2 cannot coexist with a restored target.
- A3 becomes honest and reachable only when the required facts exist.
- Evidence consumers can recompute the level instead of trusting a label.

## Falsifying test

Construct every fact combination; assert the level mapping. The grace + concurrent recovery
scenario must produce `UNRESOLVED`/A0, never A2.
