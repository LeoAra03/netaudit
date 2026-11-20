from __future__ import annotations

from netaudit import parser


def test_detects_fortigate() -> None:
    assert parser.detect_vendor("config system global\nend\n") == "fortigate"


def test_detects_cisco() -> None:
    assert parser.detect_vendor("interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n") == "cisco"


def test_detects_unknown() -> None:
    assert parser.detect_vendor("totally not a device config") == "unknown"
