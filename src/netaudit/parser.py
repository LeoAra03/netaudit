"""Vendor detection and vendor-aware config parsing.

Nothing is executed and nothing is dialled home: text in, normalized
statements out. A malformed config should degrade into odd statements, never
into an exception, so one bad line cannot take down a scan of the rest.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .models import DeviceConfig, Statement

MAX_BYTES = 2 * 1024 * 1024

_FG_OPEN = re.compile(r"^config\s+(?P<path>.+?)\s*$")
_FG_CLOSE = re.compile(r"^end\s*$")
_FG_SET = re.compile(r"^(?:set|unset)\s+(?P<key>\S+)(?:\s+(?P<value>.*))?$")

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


def detect_vendor(raw: str) -> str:
    """Best-effort vendor guess from the raw text."""

    lowered = raw.lower()
    if "config system" in lowered or "config firewall" in lowered:
        return "fortigate"
    if any(marker in lowered for marker in _CISCO_MARKERS):
        return "cisco"
    return "unknown"


def _parse_fortigate(raw: str) -> list[Statement]:
    stack: list[str] = []
    out: list[Statement] = []
    for line in raw.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if match := _FG_OPEN.match(text):
            block = match.group("path").strip().replace(" ", ".")
            out.append(Statement(tuple(stack), "config", block))
            stack.append(block)
            continue
        if _FG_CLOSE.match(text):
            if stack:
                stack.pop()
            continue
        if match := _FG_SET.match(text):
            out.append(
                Statement(
                    tuple(stack),
                    match.group("key"),
                    (match.group("value") or "").strip(),
                )
            )
    return out


def _parse_cisco(raw: str) -> list[Statement]:
    context: tuple[str, ...] = ()
    out: list[Statement] = []
    for line in raw.splitlines():
        text = line.strip()
        if not text:
            continue
        if text in {"!", "end"}:
            context = ()
            continue
        head, _, tail = text.partition(" ")
        if line[:1].isspace():
            out.append(Statement(context, head, tail.strip()))
            continue
        out.append(Statement((), head, tail.strip()))
        prefix = " ".join(text.split()[:2]).lower()
        in_context = head.lower() in _CISCO_CONTEXT or prefix in _CISCO_CONTEXT
        context = (text,) if in_context else ()
    return out


_PARSERS: dict[str, Callable[[str], list[Statement]]] = {
    "fortigate": _parse_fortigate,
    "cisco": _parse_cisco,
}


def parse(raw: str, vendor: str | None = None) -> DeviceConfig:
    """Parse ``raw`` into a DeviceConfig, detecting the vendor when omitted."""

    resolved = (vendor or detect_vendor(raw)).lower()
    if resolved not in _PARSERS:
        raise ValueError(f"unsupported vendor: {resolved}")
    if len(raw.encode("utf-8", errors="replace")) > MAX_BYTES:
        raise ValueError(f"config exceeds {MAX_BYTES} bytes")
    return DeviceConfig(vendor=resolved, statements=_PARSERS[resolved](raw))
