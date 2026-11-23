# ADR 0001 — Rules are data, not code

## Context

Checks were being added as Python functions, so every new check touched the analysis path
and re-ran the full test suite of the engine.

## Decision

Rules are YAML with `id`, `severity`, `exposure`, `scope`, `match`, `expect`,
`remediation`. The engine is a matcher over `path|key=value`. Rulepacks load with schema
validation.

## Consequences

- A new check is one YAML file plus two fixtures, no engine change.
- Rule authors do not need Python.
- A malformed rule fails at load, not at match time.
- The engine is generic and cheap to test; the risk moves into regex quality.
