# CIS control traceability

This is a **best-effort crosswalk**, not a compliance assertion. The Cisco references
below use the **CIS Cisco IOS 17.x Benchmark v1.0.0** section numbering. The FortiGate
references use the **CIS FortiGate 7.4.x Benchmark v1.0.0** section numbering, because
that is the exact FortiGate release-specific benchmark edition verifiable for this
crosswalk; FortiOS 7.6 compatibility is not proof that a CIS FortiGate 7.6 benchmark
edition applies. Confirm the benchmark edition available to your organization before
using this table for an assessment. The benchmark text is copyrighted; this repository
lists control IDs and titles only, not the benchmark content.

“Direct” means the rule checks the same subject as the benchmark recommendation, not
that this tool implements all its audit requirements. “Adjacent” means a related
recommendation exists but the rule's condition is materially different. “No direct
match” is intentional: it is more accurate than implying CIS coverage.

## FortiGate rules

| NetAudit rule | CIS FortiGate 7.4.x Benchmark v1.0.0 section | Mapping |
|---|---|---|
| FG-001 — Telnet administration enabled | **2.4.5 Ensure only encrypted access channels are enabled** | Direct: rule checks the global Telnet admin switch; it does not check all management channels or reachability. |
| FG-002 — Legacy TLS allowed on admin GUI | **2.1.10 Ensure management GUI listens on secure TLS version** | Direct: checks for TLS 1.0/1.1 in the configured GUI protocol list. |
| FG-003 — Plain HTTP allowed on an interface | **2.4.5 Ensure only encrypted access channels are enabled** | Direct: HTTP is an unencrypted administrative channel. This rule only examines parsed interface `allowaccess`. |
| FG-004 — Default SNMP community name | **2.3.1 Ensure only SNMPv3 is enabled** | Related/direct risk area: a v1/v2c community violates an SNMPv3-only posture; this rule checks the literal `public` name, not every v1/v2c community. |
| FG-005 — Password policy block missing | **2.2.1 Ensure 'Password Policy' is enabled** | Direct intent; the rule tests for a policy block, not the full benchmark's policy parameters. |
| FG-006 — Password policy disabled | **2.2.1 Ensure 'Password Policy' is enabled** | Direct. |
| FG-007 — Admin trusted host unrestricted | **2.4.2 Ensure all the login accounts having specific trusted hosts enabled** | Direct intent; the rule detects an all-address trusthost value, not every account or all valid subnet policies. |
| FG-008 — Logging disabled | **7.1.1 Enable Event Logging** | Adjacent: this rule checks the global `log.setting status`; the benchmark event-logging recommendation may require additional event-category settings. |
| FG-009 — Firewall policy permits any-any | **3.2 Ensure that policies do not use “ALL” as Service** | **No direct match.** The rule checks `srcaddr=all` or `dstaddr=all`, while section 3.2 is specifically about the Service field. It is a NetAudit heuristic, not a test of 3.2. |

## Cisco IOS rules

| NetAudit rule | CIS Cisco IOS 17.x Benchmark v1.0.0 section | Mapping |
|---|---|---|
| CS-001 — VTY lines accept Telnet | **1.2.2 Set 'transport input ssh' for 'line vty' connections** | Direct: this parser also treats `transport input all` as allowing Telnet. |
| CS-002 — HTTP server enabled | **1.6.4 Configure Web interface**; **1.2.11 Set 'http Secure-server' limit** | Adjacent only. These sections cover the web interface / secure-server exposure; neither is equivalent to an unconditional `no ip http server` test. |
| CS-003 — Default SNMP community | **1.5.2 Unset 'private' for 'snmp-server community'** and **1.5.3 Unset 'public' for 'snmp-server community'** | Direct for the two conventional community strings detected by this rule. |
| CS-004 — `service password-encryption` absent | **1.4.2 Enable 'service password-encryption'** | Direct. This legacy IOS feature is obfuscation, not modern password hashing or a substitute for secrets management. |
| CS-005 — AAA not enabled | **1.1.1 Enable 'aaa new-model'** | Direct. This checks the AAA framework switch, not the complete authentication/authorization/accounting configuration. |
| CS-006 — No syslog host configured | **2.2.4 Set IP address for 'logging host'** | Direct intent; the rule checks for a configured host but does not validate destination reachability or logging policy. |
| CS-007 — Cleartext password on local user | **1.4.3 Set 'username secret' for all local users** | Direct intent; the regex detects a local username with a `password` clause and does not validate hash strength. |

## References and scope

- CIS Benchmark landing pages: [Fortinet](https://www.cisecurity.org/benchmark/fortinet) and [Cisco](https://www.cisecurity.org/benchmark/cisco).
- Cisco section numbers and titles are from the cited 17.x v1.0.0 edition. Newer IOS / IOS XE editions may renumber or change recommendations.
- The FortiGate edition is 7.4.x v1.0.0; control identifiers can change between editions. The CIS Fortinet landing page is the authoritative source for the current edition.
- Rulepack `reference` fields are concise operator-facing hints. This document is the detailed crosswalk; none of the rules alone establishes CIS compliance.
