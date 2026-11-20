"""Vendor detection and vendor-aware config parsing.

Nothing is executed and nothing is dialled home: text in, normalized
statements out. A malformed config should degrade into odd statements, never
into an exception, so one bad line cannot take down a scan of the rest.
"""

from __future__ import annotations

_CISCO_MARKERS = (
    "interface ",
    "line vty",
    "snmp-server",
    "service password-encryption",
    "ip route",
    "aaa new-model",
    "router ospf",
    "hostname ",
)

# A Cisco sub-config is any indented block under one of these parents. The
# parent list matters: if a keyword is missing here, its children are read as
# global commands and anchored rules stop matching.
_CISCO_CONTEXT = {
    "interface",
    "line",
    "router",
    "policy-map",
    "class-map",
    "route-map",
    "ip access-list",
    "ipv6 access-list",
    "key chain",
    "crypto isakmp",
    "crypto pki",
    "vlan",
}

MAX_BYTES = 2 * 1024 * 1024


def detect_vendor(raw: str) -> str:
    """Best-effort vendor guess from the raw text."""

    lowered = raw.lower()
    if "config system" in lowered or "config firewall" in lowered:
        return "fortigate"
    if any(marker in lowered for marker in _CISCO_MARKERS):
        return "cisco"
    return "unknown"
