# Severity rationale

Every rule carries a weight (info 1, low 2, medium 5, high 10, critical 20). The weight is
not taste. Each one is derived from four inputs: exploitability without credentials, whether
the finding exposes the control plane or the data plane, whether detection exists elsewhere
in the stack, and the CIS and NIST SP 800-53 control it maps to.

Mapping is section-level against CIS FortiGate 7.4 and CIS Cisco IOS 17, control-level
against NIST SP 800-53 Rev 5. CIS control IDs move between benchmark revisions; the section
is the stable reference, the ID is marked provisional.

| Rule | Weight | Control plane / data plane | CIS | NIST 800-53 | Why this weight |
|---|---|---|---|---|---|
| FG-001 telnet admin | 10 | control plane | §2.4.5 — Ensure only encrypted access channels are enabled | CM-7, SC-8, AC-17 | Cleartext admin credential on the management plane. One on-path position yields full device control. No compensating control exists below it. |
| FG-006 password policy disabled | 10 | control plane | §2.2.1 — Ensure 'Password Policy' is enabled | IA-5 | Removes the only brute-force brake. Combined with FG-001 it is the fastest path from network access to device ownership. |
| FG-007 admin trusted host unrestricted | 10 | control plane | §2.4.2 — Ensure all the login accounts having specific trusted hosts enabled | AC-17, AC-3 | Turns the admin GUI and SSH into internet-facing services. Exploitability is a function of patch lag, which the operator does not control. |
| FG-002 legacy TLS on GUI | 5 | control plane | §2.1.10 — Ensure management GUI listens on secure TLS version | SC-8, SC-13 | Downgrade to TLS 1.0/1.1. Real but requires an active position; session hijack follows. |
| FG-003 plain HTTP on interface | 5 | control plane | §2.4.5 — Ensure only encrypted access channels are enabled | SC-8 | Same class as FG-002, lower because a redirect often exists upstream. |
| FG-005 password policy block missing | 5 | control plane | §2.2.1 — Ensure 'Password Policy' is enabled | IA-5 | Weaker than FG-006: defaults may still apply. Absence of configuration is not absence of control. |
| FG-008 logging disabled | 5 | control plane | §7.1.1 — Enable Event Logging | AU-2, AU-12 | No detection and no forensics. Does not prevent the breach, determines whether you ever learn about it. |
| FG-009 any-any policy | 5 | data plane | No direct match; §3.2 concerns ALL as Service, not source/destination addresses | AC-4, SC-7 | Collapses segmentation intent. Severity depends on position; at the WAN edge it is high, internally it is medium. Weighed at the lower bound deliberately. |
| FG-004 default SNMP community | 2 | control plane | §2.3.1 — Ensure only SNMPv3 is enabled (related control) | IA-5, SC-8 | Read-only topology disclosure. Informational alone, a reconnaissance multiplier in a chain. |
| CS-001 telnet on VTY | 10 | control plane | §1.2.2 — Set 'transport input ssh' for 'line vty' connections | CM-7, SC-8, AC-17 | Cisco equivalent of FG-001. `transport input all` on a VTY line accepts Telnet by default. |
| CS-005 AAA not enabled | 10 | control plane | §1.1.1 — Enable 'aaa new-model' | IA-2, AC-3 | No central identity, no accounting, per-device local accounts. Every credential becomes device-local and unrevocable at scale. |
| CS-007 cleartext local password | 10 | control plane | §1.4.3 — Set 'username secret' for all local users | IA-5, SC-8 | `service password-encryption` is type 7, reversible in seconds. It is obfuscation, not hashing. |
| CS-002 HTTP server enabled | 5 | control plane | §§1.2.11 and 1.6.4 (adjacent, not equivalent to disabling HTTP) | SC-8 | Same as FG-003. |
| CS-004 password-encryption absent | 5 | control plane | §1.4.2 — Enable 'service password-encryption' | IA-5 | Prerequisite for CS-007. Scored lower than CS-007 because it is the enabling condition, not the exposure. |

## Deliberate non-rules

- **Banner text.** Mandatory in many frameworks, near-zero security effect. Adding it would
  dilute the score.
- **NTP configuration.** Relevant to log correlation, not to exposure. Belongs in a
  compliance pack, not the hardening pack.
- **`exec-timeout`.** Real but low-value relative to weight budget; candidate for a future
  `low` rule.

## Known scoring weakness

The score is `max(0, 100 - total weight)`. Twenty medium findings score the same as ten
highs. That is a triage order, not a risk model. A CVSS-style vector per finding is on the
roadmap; until then the grade answers "how much is wrong", not "how bad is the worst thing".
