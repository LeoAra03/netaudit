# Threat model

Written for the deployment I actually run: one container, one operator, configs uploaded
by hand. If that changes, this file changes with it.

## Assets

- Uploaded configurations. These leak topology, address ranges, hostnames and password
  hashes, even when they are "just" a lab device.
- Stored reports in SQLite, which replay the same information later.
- The rulepacks, because a silently broken rule reports a clean device, which is worse
  than a crash.

## Trust boundaries

    browser / CI  ->  HTTP API  ->  parser  ->  rule engine + rulepack  ->  SQLite
                         ^                                              ^
                    size and type checks                            reviewed in Git

## In scope

| Threat | Mitigation |
|---|---|
| Oversized upload exhausts memory | 2 MiB cap checked on the raw bytes before parsing |
| Binary or non-UTF-8 input | decode with `errors="replace"`; the parser tolerates junk |
| Parser crash on malformed config | tolerant line parsing, no exception path for unknown syntax |
| Unbounded config work | one file per request, no recursion, single worker, `pids_limit` in compose |
| Malicious rulepack regex (ReDoS) | packs ship in Git and are reviewed; user-supplied packs are not implemented |
| Injection into the store | parameterised SQL only, one table, no dynamic DDL |
| Report id guessing | 12 hex chars from `uuid4`, and the deployment is single-tenant by design |
| Container escape surface | non-root user, `cap_drop: ALL`, `read-only` rootfs, no shell in the runtime path |
| Vulnerable base image | Trivy gate on HIGH and CRITICAL in CI, SARIF uploaded to code scanning |
| Supply chain of the audit itself | the CI `self-scan` job publishes netaudit's own findings next to Trivy's |
| Leaked long-lived cloud credential | OIDC federation to GHCR and Azure, no static secret in the repo |
| Configs committed to the repo | CONTRIBUTING requires RFC 5737 ranges; fixtures are synthetic |

## Out of scope

- Command injection on the device. NetAudit never executes a config and never connects to
  a device, so the classic "paste this command" risk does not exist here.
- TLS termination and network segmentation, delegated to the platform.
- Availability. A scan is a few milliseconds of CPU; losing the container is not a
  safety event.

## Attack I have not answered

1. No authentication. Anyone who can reach port 8000 can read every past report. This is
   the single thing that keeps the deployment lab-only.
2. No rate limiting, so the 2 MiB cap can still be reached by many small requests and grow
   the database without bound. Retention is unimplemented.
3. Regex time on hostile input is not bounded (see the roadmap item).

## Before production

Authentication, per-IP rate limiting at the proxy, a retention and purge policy, regex
timeouts, a private registry instead of public GHCR, and a written answer for "what happens
to a customer config after it is uploaded".
