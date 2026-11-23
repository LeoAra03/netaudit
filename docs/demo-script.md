# 40-second terminal GIF

Record one genuine terminal session (no mock output or speed-up). The sequence demonstrates
the CI gate failing on a deliberately bad snapshot and passing on the fixed fixture.

| time | action | narration |
|---|---|---|
| 0–5s | Show the prompt and type `netaudit scan tests/fixtures/fortigate_bad.conf --fail-under 80`. Let the command return exit code 1. | “This exported FortiGate config fails the baseline gate.” |
| 5–24s | Keep the full output visible. Point to the high-severity Telnet finding and `path|key=value` evidence. | “The report tells us which rule fired and exactly which config statement triggered it.” |
| 24–34s | Type `netaudit scan tests/fixtures/fortigate_good.conf --fail-under 80`. Let it return exit code 0. | “The fixed snapshot clears the same gate.” |
| 34–40s | Hold the clean result in view. | “Same versioned rules, repeatable CI decision.” |

Keep a readable terminal font and show both real exit codes. Use the project-installed
`netaudit` command, capture the terminal itself, and save the reviewed 40-second result to
`docs/assets/netaudit-scan.gif`. Do not replace real output with a typeset or synthesized
mockup.

## SARIF screenshot

The `self-scan` GitHub Actions job uploads `netaudit.sarif` to code scanning. Once that
workflow has completed for the repository, open **Security → Code scanning** and capture
the actual rendered findings list and one finding detail panel. Save the genuine UI capture
to `docs/assets/github-security-sarif.png`; raw SARIF JSON is not a substitute.
