"""Tests for mcp-lint detectors.

Positive cases mirror the DOCUMENTED config shape of each rule's pinned CVE;
negative cases are the safe shapes the rule must stay silent on. The rule is
pinned to CVE-2025-49596 (MCP Inspector unauthenticated RCE); see the docstring
in ``mcp_lint/checkers.py`` for the provenance and the honesty caveat.
"""

from __future__ import annotations

import json

from mcp_lint.checkers import check_payload


def _codes(payload, **kw) -> list[str]:
    src = json.dumps(payload)
    return [f.code for f in check_payload(payload, "t.json", source=src, **kw)]


# --------------------------------------------------------------------------- #
# MC001 -- CVE-2025-49596 (MCP Inspector unauthenticated RCE)
# Documented shape: network-reachable MCP endpoint (non-loopback url) + no auth.
# --------------------------------------------------------------------------- #


def test_mc001_fires_on_zero_dot_zero_dot_zero_dot_zero_no_auth():
    cfg = {"mcpServers": {"inspector": {"url": "http://0.0.0.0:6277/sse"}}}
    assert _codes(cfg) == ["MC001"]


def test_mc001_fires_on_public_hostname_no_auth():
    cfg = {"mcpServers": {"proxy": {"url": "https://mcp.example.com/sse"}}}
    assert _codes(cfg) == ["MC001"]


def test_mc001_fires_on_ipv6_all_interfaces_no_auth():
    cfg = {"mcpServers": {"proxy": {"url": "http://[::]:6277/sse"}}}
    assert _codes(cfg) == ["MC001"]


def test_mc001_silent_on_loopback_ipv4():
    cfg = {"mcpServers": {"inspector": {"url": "http://127.0.0.1:6277/sse"}}}
    assert _codes(cfg) == []


def test_mc001_silent_on_loopback_ipv6():
    cfg = {"mcpServers": {"inspector": {"url": "http://[::1]:6277/sse"}}}
    assert _codes(cfg) == []


def test_mc001_silent_on_localhost_name():
    cfg = {"mcpServers": {"inspector": {"url": "http://localhost:6277/sse"}}}
    assert _codes(cfg) == []


def test_mc001_silent_when_authorization_header_present():
    cfg = {
        "mcpServers": {
            "inspector": {
                "url": "http://0.0.0.0:6277/sse",
                "headers": {"Authorization": "Bearer deadbeef"},
            }
        }
    }
    assert _codes(cfg) == []


def test_mc001_silent_when_x_api_key_header_present():
    cfg = {
        "mcpServers": {
            "inspector": {
                "url": "http://0.0.0.0:6277/sse",
                "headers": {"X-API-Key": "deadbeef"},
            }
        }
    }
    assert _codes(cfg) == []


def test_mc001_silent_when_entry_level_token_present():
    cfg = {
        "mcpServers": {
            "inspector": {
                "url": "http://0.0.0.0:6277/sse",
                "token": "deadbeef",
            }
        }
    }
    assert _codes(cfg) == []


def test_mc001_silent_on_stdio_entry():
    # stdio transport (no url) is not the network surface of CVE-2025-49596.
    cfg = {
        "mcpServers": {
            "local": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-everything"],
            }
        }
    }
    assert _codes(cfg) == []


def test_mc001_silent_when_no_mservers_key():
    assert _codes({"foo": "bar"}) == []


def test_mc001_silent_when_mservers_not_dict():
    assert _codes({"mcpServers": ["not", "a", "dict"]}) == []


def test_mc001_message_cites_cve_and_advisory_url():
    cfg = {"mcpServers": {"inspector": {"url": "http://0.0.0.0:6277/sse"}}}
    findings = check_payload(cfg, "t.json", source=json.dumps(cfg))
    assert len(findings) == 1
    msg = findings[0].message
    assert "CVE-2025-49596" in msg
    assert "https://nvd.nist.gov/vuln/detail/CVE-2025-49596" in msg


def test_mc001_locates_line_of_url():
    # Multi-line source: the url value sits on line 4. The rule must recover a
    # useful line number from the raw source (stdlib JSON parser drops positions).
    src = (
        "{\n"
        '  "mcpServers": {\n'
        '    "inspector": {\n'
        '      "url": "http://0.0.0.0:6277/sse"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )
    payload = json.loads(src)
    findings = check_payload(payload, "t.json", source=src)
    assert len(findings) == 1
    assert findings[0].line == 4


def test_mc001_bite_test_red_then_green():
    # Build-honesty discipline (mirrors wildlint): the SAME rule must bite the
    # vulnerable config and stay silent on the fixed config.
    vulnerable = {"mcpServers": {"inspector": {"url": "http://0.0.0.0:6277/sse"}}}
    fixed_loopback = {"mcpServers": {"inspector": {"url": "http://127.0.0.1:6277/sse"}}}
    fixed_auth = {
        "mcpServers": {
            "inspector": {
                "url": "http://0.0.0.0:6277/sse",
                "headers": {"Authorization": "Bearer t"},
            }
        }
    }
    assert _codes(vulnerable) == ["MC001"]
    assert _codes(fixed_loopback) == []
    assert _codes(fixed_auth) == []
