# AI-assisted workflow

Tools: Claude Code for scaffolding, refactors and test skeletons; GitHub Copilot for
boilerplate inside a file I already understood. Nothing merges without `make verify`.

This is not a brag file and not a disclaimer. Half of what the models produced was wrong in
a way I had to catch myself, so the useful record is the wrong part.

## Loop

1. Write the contract first: the types, a failing test, or an ADR note.
2. Prompt with file paths and the failing test, not with vibes.
3. Run lint, types and tests on every suggestion, before reading it properly.
4. Reject any suggestion that adds a dependency, changes a public shape, or "improves"
   something I did not ask about.
5. Rewrite the prose myself. Docstrings included: I keep them short because I have to
   defend them in review.

## Log

### 2026-11-18 — FortiGate `edit` objects

Prompt: "Parse FortiGate `edit` blocks so the evidence names the object, without changing
the match path."

What came back: the object name pushed *into* the statement path, so
`system.interface|allowaccess=...` became `system.interface.port1|allowaccess=...`. Every
anchored regex in both packs stopped matching, and the bad-config fixtures went quiet,
which is the worst failure mode this tool can have.

Correction: path untouched, new `object` field rendered only in `Statement.evidence`.
Regression test: `test_fortigate_object_does_not_leak_into_the_path`, plus
`test_evidence_names_the_interface`.

### 2026-11-19 — SARIF export

Prompt: "Emit SARIF 2.1.0 so these findings show up in code scanning."

What came back: `results[].remediation`, which is not in the spec, and no `rules` array, so
the rule ids referenced nothing.

Correction: read the OASIS schema, moved the fix text into `message.text` and the rule
`help`, added the `rules` array, and added `partialFingerprints` so a repeated finding keeps
a stable identity. Test: `test_html_report_and_exports` asserts every `ruleId` is declared.

### 2026-11-19 — scan persistence

Prompt: "The report page 404s after a while, fix it."

What came back: a size cap on the in-memory dict with a lock. That hides the bug instead of
fixing it: the dict is per process, so the 404 comes back with a second worker.

Correction: SQLite, one worker, ADR 0002. Tests: `test_scan_is_persisted`,
`test_scan_survives_a_new_request`, `test_failed_insert_rolls_back`.

### 2026-11-20 — Cisco context keywords

Prompt: "Cisco sub-configs should keep their parent as context."

What came back: a context list missing the two-word parents (`ip access-list`,
`crypto isakmp`), so indented children were read as global commands and `CS-001` never
fired on `line vty 0 4` + ` transport input all`. It also invented
`transport input=` as the key, when the key is `transport` and the value is `input all`.

Correction: the rule regex was rewritten against the actual flattened statement, and the
parent list now has a comment saying why it matters. Tests: `test_cisco_two_word_context`,
`test_bad_cisco_flags_expected`.

## What I will not blame on the model

The rule set, the score weights, the single-worker tradeoff, and the decision to publish the
limitations instead of hiding them were mine, and they are the parts I would defend in a
design review.
