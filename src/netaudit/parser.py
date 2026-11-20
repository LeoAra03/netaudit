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
_FG_EDIT = re.compile(r"^edit\s+(?P<name>.+?)\s*$")
_FG_NEXT = re.compile(r"^next\s*$")
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

_CISCO_BLOCK_ENDS = {"!", "end"}


def _indent_width(line: str) -> int:
    """Leading whitespace width, with tabs expanded so the two mix sanely."""

    stripped = line.lstrip()
    return len(line[: len(line) - len(stripped)].expandtabs(8))


def detect_vendor(raw: str) -> str:
    """Best-effort vendor guess from the raw text."""

    lowered = raw.lower()
    if "config system" in lowered or "config firewall" in lowered:
        return "fortigate"
    if any(marker in lowered for marker in _CISCO_MARKERS):
        return "cisco"
    return "unknown"


def _object_chain(objects: dict[int, str], depth: int) -> str:
    """Names of every enclosing ``edit``, outermost first.

    A statement nested two edits deep (``config system interface`` > ``edit
    "port1"`` > ``config secondaryip`` > ``edit 1``) belongs to both of them. The
    old lookup by depth alone reported the innermost name, so the evidence
    pointed at a secondary IP ``1`` that exists on every interface.
    """

    return "/".join(objects[level] for level in sorted(objects) if level <= depth)


def _parse_fortigate(raw: str) -> list[Statement]:
    stack: list[str] = []
    objects: dict[int, str] = {}
    out: list[Statement] = []
    for line in raw.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if match := _FG_OPEN.match(text):
            block = match.group("path").strip().replace(" ", ".")
            out.append(
                Statement(tuple(stack), "config", block, object=_object_chain(objects, len(stack)))
            )
            stack.append(block)
            continue
        if _FG_CLOSE.match(text):
            objects.pop(len(stack), None)
            if stack:
                stack.pop()
            continue
        if match := _FG_EDIT.match(text):
            objects[len(stack)] = match.group("name").strip().strip('"')
            continue
        if _FG_NEXT.match(text):
            objects.pop(len(stack), None)
            continue
        if match := _FG_SET.match(text):
            out.append(
                Statement(
                    tuple(stack),
                    match.group("key"),
                    (match.group("value") or "").strip(),
                    object=_object_chain(objects, len(stack)),
                )
            )
    return out


def _parse_cisco(raw: str) -> list[Statement]:
    """One statement per line, nested by indentation.

    IOS blocks are structural, not keyword-specific: a line's parents are the
    enclosing lines indented less than it. Deriving the tree from indentation
    instead of a keyword list is what keeps the children of *every* block
    (``crypto map``, ``ip dhcp pool``, ``ip sla``, ``monitor session``,
    ``track``...) inside that block. A hardcoded parent list silently drops the
    blocks it does not know, and their children then read as global commands,
    where anchored per-block rules can never reach them -- measured on a real
    IOS config: ``set peer 203.0.113.9`` under ``crypto map VPN 10`` came out as
    the global statement ``|set=peer 203.0.113.9``.
    """

    stack: list[tuple[int, str]] = []
    out: list[Statement] = []
    for line in raw.splitlines():
        text = line.strip()
        if not text:
            continue
        if text in _CISCO_BLOCK_ENDS:
            stack.clear()
            continue
        width = _indent_width(line)
        while stack and stack[-1][0] >= width:
            stack.pop()
        head, _, tail = text.partition(" ")
        out.append(Statement(tuple(parent for _, parent in stack), head, tail.strip()))
        stack.append((width, text))
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
