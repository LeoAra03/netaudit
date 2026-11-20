# Contributing

Short version: small pull requests, one concern each, `make verify` green before you push.

1. Branch from `main`: `feat/`, `fix/`, `docs/`, `ci/`, `build/`, `test/`.
2. Conventional commits, imperative mood, one logical change per commit. `fix:` needs a
   test that fails without it.
3. `make verify` must pass (`ruff check`, `ruff format --check`, `mypy`, coverage at 85%).
4. Pull request under roughly 400 lines, with "How it was verified" and "AI assistance"
   filled in. Use the template.
5. Adding a rule means adding a fixture that violates it and asserting it fires. A rule
   with no failing fixture does not merge, because nothing proves it can trigger.

## Layout

    src/netaudit/parser.py      vendor syntax only; emits Statements
    src/netaudit/engine.py      scope + match + expect; no vendor knowledge
    src/netaudit/rulepacks/     YAML baselines, validated on load
    src/netaudit/store.py       SQLite, one row per scan
    src/netaudit/reporters.py   Markdown and SARIF, no logic

The `Statement.flat` string (`path|key=value`) is the contract between the parser and the
rulepacks. Changing it breaks every pack, so it needs an ADR.

## Style

- Type hints everywhere; `mypy --strict` is the reviewer that never gets tired.
- Docstrings say why, not what. One sentence is usually enough.
- No new dependency without a paragraph in the pull request justifying it.

## Configs in tests

Never commit a real configuration, not even a redacted one. Rewrite it by hand with the
documentation ranges from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
and obviously fake hostnames. Hostnames, serial numbers and public addresses identify the
owner of a config even when the passwords are gone.

## Security findings

Not through a pull request. See [SECURITY.md](SECURITY.md).
