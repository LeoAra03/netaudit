# Control mapping

Informative mapping from rule to external control. Not a certification; it exists so a
finding can be argued in an audit.

| Rule | CIS Controls v8 | NIST SP 800-41r1 | ISO 27001:2022 | Azure WAF |
| --- | --- | --- | --- | --- |
| FG-001 | 4.4 | 3.1 | A.8.20 | SE:05 |
| FG-002 | 4.4 | 3.1 | A.8.24 | SE:07 |
| FG-003 | 4.4 | 3.1 | A.8.20 | SE:05 |
| FG-004 | 4.4 | 3.3 | A.5.17 | SE:05 |
| FG-005 | 5.2 | 3.4 | A.5.17 | SE:05 |
| FG-006 | 5.2 | 3.4 | A.5.17 | SE:05 |
| FG-007 | 4.7 | 3.2 | A.8.20 | SE:05 |
| FG-008 | 8.2 | 3.5 | A.8.15 | OE:04 |
| FG-009 | 4.4 | 2.2 | A.8.20 | SE:05 |
| CS-001 | 4.4 | 3.1 | A.8.20 | SE:05 |
| CS-002 | 4.4 | 3.1 | A.8.20 | SE:05 |
| CS-003 | 4.4 | 3.3 | A.5.17 | SE:05 |
| CS-004 | 3.10 | 3.3 | A.5.17 | SE:05 |
| CS-005 | 5.6 | 3.2 | A.5.15 | SE:05 |
| CS-006 | 8.2 | 3.5 | A.8.15 | OE:04 |
| CS-007 | 3.10 | 3.3 | A.5.17 | SE:05 |

The same mapping lives in each rule's `controls` block in
[`src/netaudit/rulepacks/`](../src/netaudit/rulepacks), which is what
`netaudit explain <rule>` prints; this table is the human-readable mirror.

Maintenance rule: a rule without a mapping row is not merged, and a mapping row without a
rule is deleted in the same PR.
