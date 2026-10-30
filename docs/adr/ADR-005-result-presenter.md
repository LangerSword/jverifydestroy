# ADR-005 — Result model and user presenter

Status: Accepted for implementation (Phase 2 design gate).

## Context

The engine returns state names and technical facts. The product must speak plain language to
ordinary users while keeping every honesty guarantee. UI/CLI must not print raw state names by
default.

## Decision

Domain returns a structured `Result`:

```
enum Outcome {
  SUCCESS, SUCCESS_WITH_LIMITS, RESTORE_FAILED, INVALID, UNRESOLVED, ERROR, CANCELLED
}
record Result(Outcome outcome, Map<String,String> facts, List<String> limits, String details)
```

A separate `Presenter` maps it to `UserMessage(Tone tone, String sentence, String details)`.
Tone is exactly GREEN, AMBER, RED.

| Engine outcome | Tone | Default sentence |
|---|---|---|
| SUCCESS | GREEN | The file is gone, and the receipt is saved. |
| SUCCESS_WITH_LIMITS | AMBER | The file is gone. We couldn't check the physical disk, so this is a software-level result. |
| RESTORE_FAILED | RED | We couldn't put the file back. Keep the recovery folder and try again. |
| INVALID | RED | The safety check didn't run correctly, so we can't confirm the file is gone. |
| UNRESOLVED | AMBER | The file might not be deleted. Do not rely on it. |
| ERROR | RED | Nothing was changed. Details explain what went wrong. |
| CANCELLED | AMBER | Nothing was changed. |

Rules:

- Default sentence contains no state names and none of:
  `COMMITTED`, `ABORTED`, `NOT_CHECKABLE`, `INVALID`, `canary`, `assurance`, `journal`,
  `vault`, `DEK`, `transaction`, `Merkle`, `Ed25519`, `hash`.
- Technical facts, limits, paths, and state names live in `details` and `--details`.
- `SUCCESS_WITH_LIMITS` is amber, not green: the file is gone but the limit matters.
- `RESTORE_FAILED` must tell the user to keep the recovery folder; it must not say “deleted”.
- `INVALID` must not say “failed”; it says the check could not confirm.
- `UNRESOLVED` must not say “destroyed”; it says treat as present.
- No stack traces. `details` is a human-readable explanation.

## Consequences

- UI and CLI share one presentation table.
- The default view is plain; the technical view remains available.
- A mapping bug is a product bug; exhaustive tests are mandatory.

## Falsifying test

Iterate every `Outcome`; assert tone, non-empty sentence, no banned token in the sentence,
and a non-empty details string. Add a string-lint test over the default UI/CLI text.
