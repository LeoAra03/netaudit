from __future__ import annotations

from collections.abc import Callable

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


def test_fortigate_nesting_and_object() -> None:
    raw = 'config system interface\n    edit "port3"\n        set allowaccess ping\n    next\nend\n'
    statements = parser.parse(raw, "fortigate").statements
    target = next(s for s in statements if s.key == "allowaccess")
    assert target.path == ("system.interface",)
    assert target.flat == "system.interface|allowaccess=ping"
    assert target.evidence == "[port3] system.interface|allowaccess=ping"


def test_fortigate_object_does_not_leak_into_the_path() -> None:
    """The object name must not become part of the match path, or every anchored
    rule in the rulepacks breaks. Regression from the first parser attempt."""

    raw = 'config system global\n    edit "x"\n        set hostname fw\n    next\nend\n'
    statements = parser.parse(raw, "fortigate").statements
    host = next(s for s in statements if s.key == "hostname")
    assert host.flat == "system.global|hostname=fw"


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


def test_cisco_two_word_context() -> None:
    raw = (
        "ip access-list extended IN\n"
        " permit tcp any any eq 22\n"
        "!\n"
        "ip route 0.0.0.0 0.0.0.0 10.0.0.1\n"
    )
    statements = parser.parse(raw, "cisco").statements
    assert statements[1].path == ("ip access-list extended IN",)
    assert statements[2].path == ()


def test_cisco_blank_lines_and_end_reset_context() -> None:
    raw = "interface Gi0/1\n\n ip address 10.0.0.1 255.255.255.0\nend\nhostname r1\n"
    statements = parser.parse(raw, "cisco").statements
    assert statements[1].path == ("interface Gi0/1",)
    assert statements[2].path == ()


def test_indented_line_without_context_is_kept() -> None:
    statements = parser.parse(" hostname r1\n", "cisco").statements
    assert statements[0].flat == "|hostname=r1"


def test_vendor_is_case_insensitive() -> None:
    assert parser.parse("config system global\nend\n", "FortiGate").vendor == "fortigate"


def test_oversize_rejected() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        parser.parse("config system global\n" + "#" * parser.MAX_BYTES, "fortigate")


def test_real_fixtures_parse_without_error(config_text: Callable[[str], str]) -> None:
    for name, vendor in (
        ("fortigate_bad.conf", "fortigate"),
        ("fortigate_good.conf", "fortigate"),
        ("cisco_bad.conf", "cisco"),
        ("cisco_good.conf", "cisco"),
    ):
        config = parser.parse(config_text(name))
        assert config.vendor == vendor
        assert config.statements


def test_cisco_children_of_an_unlisted_block_stay_scoped() -> None:
    """The parent list used to be a hardcoded keyword set, so a block it did not
    know left its children as global commands: ``set peer 203.0.113.9`` under
    ``crypto map VPN 10`` came out as ``|set=peer 203.0.113.9``, invisible to any
    anchored rule and visible to every unanchored one."""

    raw = "crypto map VPN 10 ipsec-isakmp\n set peer 203.0.113.9\n!\nhostname r1\n"
    statements = parser.parse(raw, "cisco").statements
    assert statements[1].path == ("crypto map VPN 10 ipsec-isakmp",)
    assert statements[1].flat == "crypto map VPN 10 ipsec-isakmp|set=peer 203.0.113.9"
    assert statements[2].path == ()


def test_cisco_keeps_every_nesting_level() -> None:
    raw = "policy-map LLQ\n class VOICE\n  priority 100\n class class-default\n  fair-queue\n"
    statements = parser.parse(raw, "cisco").statements
    assert statements[2].path == ("policy-map LLQ", "class VOICE")
    assert statements[4].path == ("policy-map LLQ", "class class-default")


def test_cisco_tab_indentation_nests() -> None:
    raw = "interface Gi0/1\n\tip address 10.0.0.1 255.255.255.0\n"
    statements = parser.parse(raw, "cisco").statements
    assert statements[1].path == ("interface Gi0/1",)


def test_cisco_sibling_parent_opens_a_new_block() -> None:
    raw = "interface Gi0/1\n description WAN\ninterface Gi0/2\n description LAN\n"
    statements = parser.parse(raw, "cisco").statements
    assert statements[1].path == ("interface Gi0/1",)
    assert statements[3].path == ("interface Gi0/2",)


def test_cisco_bang_closes_every_open_block() -> None:
    raw = "policy-map LLQ\n class VOICE\n  priority 100\n!\nhostname r1\n"
    statements = parser.parse(raw, "cisco").statements
    assert statements[-1].path == ()


def test_fortigate_nested_edits_keep_every_object_name() -> None:
    """A secondary-IP entry has no identity of its own: ``[9]`` alone points at
    every interface's first secondary IP, not at the one that is misconfigured."""

    raw = (
        "config system interface\n"
        '    edit "port1"\n'
        "        config secondaryip\n"
        "            edit 9\n"
        "                set ip 10.0.0.9 255.255.255.0\n"
        "            next\n"
        "        end\n"
        "    next\n"
        "end\n"
    )
    statements = parser.parse(raw, "fortigate").statements
    ip = next(s for s in statements if s.key == "ip")
    assert ip.object == "port1/9"
    assert ip.evidence == "[port1/9] system.interface.secondaryip|ip=10.0.0.9 255.255.255.0"


def test_fortigate_config_statement_names_the_open_object() -> None:
    raw = (
        "config firewall policy\n    edit 3\n        config something\n        end\n    next\nend\n"
    )
    statements = parser.parse(raw, "fortigate").statements
    nested = next(s for s in statements if s.key == "config" and s.value == "something")
    assert nested.evidence == "[3] firewall.policy|config=something"
