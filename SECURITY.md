# Security

Report a vulnerability by email to leonardo.araya.dev@gmail.com. I answer within a week and
patch the latest tag; this is a side project, so please do not open a public issue first.

What is already in place:

- Uploads are capped at 2 MiB, decoded defensively, and never executed.
- No shell, no `eval`, no subprocess in the request path. Config text only reaches a regex
  and a parameterised SQL statement.
- Containers run as a non-root user with `cap_drop: ALL`, `no-new-privileges` and a
  read-only root filesystem; only `/data` is writable.
- Trivy gates every build on HIGH and CRITICAL, and the SARIF lands in code scanning.
- The rulepacks are reviewed in Git and validated at load time, so a malformed baseline
  fails the scan instead of passing a device.
- Deployments pull images through OIDC, with no long-lived cloud credential stored in the
  repository.

Known gaps to assume while triaging (also in [docs/threat-model.md](docs/threat-model.md)):

- No authentication and no rate limiting. Do not expose this service to a network you do
  not control.
- No retention policy: every uploaded config report stays on disk until deleted.
- Regex execution time is not bounded. A hostile rulepack could stall a scan.

Versions before the latest tag are not supported.
