# Threat model

Scope: the service that accepts config files and serves reports.

| STRIDE | Threat | Control | Residual |
| --- | --- | --- | --- |
| Spoofing | Anyone uploads as anyone | none yet | Accepted while unauthenticated |
| Tampering | Crafted config exploits a catastrophic regex | `regex_timeout` (roadmap), input size cap | High until timeout lands |
| Repudiation | No actor identity on a scan | scan IDs are random; no actor | Accepted |
| Information disclosure | Configs contain secrets and hashes | reports are per-ID, unlisted; SQLite on a private volume | Medium |
| Denial of service | Large upload, many scans | 2 MB cap, single worker | Medium |
| Elevation of privilege | Parser path traversal | no writes outside the temp dir, non-root | Low |

Explicit non-goals: multi-tenant isolation, RBAC, retention policy, encryption at rest.
