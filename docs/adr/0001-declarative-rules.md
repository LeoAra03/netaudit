# 1. Declarative rule engine instead of hardcoded checks

- Status: accepted
- Date: 2026-11-18

## Context

My first draft had one function per check: `check_telnet(config)`, `check_http(config)`,
and so on. It worked, and it was already wrong in two ways. The checks were FortiGate
shaped, so the Cisco pass became a pile of `if vendor ==` branches. And every new check
meant editing the analyzer, which meant a review of Python for something that is really a
line of policy.

Checks also change with every benchmark revision. The code should not.

## Decision

Rules live in YAML with `id`, `title`, `severity`, `scope`, `match`, `expect`,
`remediation` and `reference`. The engine only knows three things: is the statement path
in scope, does the regex hit, and which way round should a hit fire.

The parser is the only place that knows anything about vendor syntax. Its output is a flat
list of `Statement(path, key, value, object)` and rules match the string form
`path|key=value`.

## Consequences

- Adding a check is a data change, reviewable without touching Python. The reviewer reads
  a regex and a fixture instead of control flow.
- Every rule has a fixture pair (bad and good) so a rule that can never fire is caught in
  CI, not in production.
- Regex false positives become the main failure mode. Mitigated by validating `expect`,
  `severity` and the pattern at load time, and by showing the exact evidence line so a
  human can dismiss a false positive in a second.
- The match string is a public contract now. Renaming a statement path is a breaking change
  for every pack, including packs I do not ship. It is documented in `parser.py`.
- Packs can be versioned per benchmark release, since they are just files.
- A hostile pack can still write a catastrophic regex. See the threat model; the mitigation
  today is review, because packs are not user-supplied yet.
