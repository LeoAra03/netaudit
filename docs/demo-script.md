# 90 second demo

Recorded in one take, real terminal, no slides, no music.

| time | what happens | line |
|---|---|---|
| 0-15s | Terminal, empty prompt. | "Network config review is manual and inconsistent, so I built a tool that makes the baseline explicit and testable." |
| 15-35s | `netaudit scan tests/fixtures/fortigate_bad.conf` | "Score 48, grade F. Telnet on the admin plane, password policy disabled, trusted host set to anything. Each finding is one rule." |
| 35-55s | `make run`, upload the same file in the browser | "Same audit as a page. The evidence names the exact object, `port1`, so a human can decide in a second instead of grepping the file." |
| 55-70s | `curl -s localhost:8000/scans/<id>/report.sarif`, then the code scanning tab | "That SARIF is why this can run in a pipeline. The CI job feeds it my own bad fixtures, so the tool reviews itself." |
| 70-85s | `git log --oneline --graph`, open one PR | "Ten pull requests, one concern each. The parser PR shows a rejected suggestion and the regression test that replaced it." |
| 85-90s | Back to the README limitations section. | "Adding a rule is a YAML change with a fixture. The threat model lists what still blocks production." |

Prep:

```bash
make cov                 # show it green first, then close the tab
docker compose up --build  # only if the container path is in the take
export PS1='$ '          # prompt noise ruins the recording
```

Rules for the take: talk slowly, type the commands by hand, no cuts other than the
terminal zoom. If something fails, stop and re-record; a staged failure in the demo is worse
than a slower demo.
