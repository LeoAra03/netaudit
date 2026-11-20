from __future__ import annotations

import pytest

from netaudit import parser


def test_detects_fortigate() -> None:
    assert parser.detect_vendor("config system global\nend\n") == "fortigate"


def test_detects_cisco() -> None:
    assert parser.detect_vendor("interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n") == "cisco"


def test_detects_unknown() -> None:
    assert parser.detect_vendor("totally not a device config") == "unknown"


def test_unknown_vendor_raises() -> None:
    with pytest.raises(ValueError, match="unsupported vendor"):
        parser.parse("nothing useful here")


def test_fortigate_config_header_is_a_statement() -> None:
    """The opening line becomes a statement, which is how FG-005 detects a
    missing block without special-casing the parser."""

    statements = parser.parse("config system global\nend\n", "fortigate").statements
    assert statements[0].flat == "|config=system.global"
    assert statements[0].path == ()


def test_fortigate_comments_and_blanks_are_ignored() -> None:
    raw = "# a comment\n\nconfig system global\n    set hostname fw\nend\n"
    assert len(parser.parse(raw, "fortigate").statements) == 2


def test_fortigate_unset_line_is_a_statement() -> None:
    raw = "config system global\n    unset hostname\nend\n"
    statements = parser.parse(raw, "fortigate").statements
    assert statements[1].flat == "system.global|hostname="


def test_cisco_context_opens_and_closes() -> None:
    raw = "interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n!\nhostname r1\n"
    statements = parser.parse(raw, "cisco").statements
    assert statements[0].path == ()
    assert statements[1].path == ("interface Gi0/1",)
    assert statements[2].path == ()


def test_indented_line_without_context_is_kept() -> None:
    statements = parser.parse(" hostname r1\n", "cisco").statements
    assert statements[0].flat == "|hostname=r1"


def test_vendor_is_case_insensitive() -> None:
    assert parser.parse("config system global\nend\n", "FortiGate").vendor == "fortigate"
