"""Tests for the MC002 source-level detector (CVE-2026-30623).

Positive cases mirror the DOCUMENTED code shape of the LiteLLM pre-fix path and
the OX Security MCP-stdio CVE family; negative cases are the LiteLLM 7b7f304
fix shape (module-level frozenset allowlist), the inline-allowlist equivalent,
and literal commands. See ``source_checkers.py`` for the provenance and the
honesty caveat (scope-wide guard scan, not path-sensitive).
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from mcp_lint.source_checkers import check_source

FIX = Path(__file__).parent / "fixtures"


def _codes(src: str) -> list[str]:
    return [f.code for f in check_source(textwrap.dedent(src), "t.py")]


# --------------------------------------------------------------------------- #
# bite test: the SAME rule must bite the vulnerable shape and stay silent on
# the documented fix (build-honesty discipline, mirrors wildlint).
# --------------------------------------------------------------------------- #


def test_mc002_bites_vulnerable_user_config_to_stdio_params():
    src = """
    from mcp.client.stdio import StdioServerParameters
    def build_server(user_config):
        command = user_config["command"]
        return StdioServerParameters(command=command, args=[])
    """
    assert _codes(src) == ["MC002"]


def test_mc002_silent_on_module_level_frozenset_allowlist_liteLLM_fix():
    # The exact shape of LiteLLM commit 7b7f304 (PR #25343).
    src = """
    import os
    from mcp.client.stdio import StdioServerParameters
    MCP_STDIO_ALLOWED_COMMANDS = frozenset({"npx","uvx","python","python3","node","docker","deno"})
    def build_server(user_config):
        command = user_config["command"]
        if os.path.basename(command) not in MCP_STDIO_ALLOWED_COMMANDS:
            raise ValueError("not allowed")
        return StdioServerParameters(command=command, args=[])
    """
    assert _codes(src) == []


def test_mc002_silent_on_inline_string_set_allowlist():
    src = """
    from mcp.client.stdio import StdioServerParameters
    def build_server(user_config):
        command = user_config["command"]
        if command not in {"npx", "uvx", "python", "node"}:
            raise ValueError("not allowed")
        return StdioServerParameters(command=command, args=[])
    """
    assert _codes(src) == []


def test_mc002_silent_on_literal_command_keyword():
    src = """
    from mcp.client.stdio import StdioServerParameters
    def hardcoded():
        return StdioServerParameters(command="npx", args=["-y", "pkg"])
    """
    assert _codes(src) == []


def test_mc002_silent_on_literal_command_positional():
    # `command` is positional [0] in the SDK dataclass; literal there is safe.
    src = """
    from mcp.client.stdio import StdioServerParameters
    def hardcoded():
        return StdioServerParameters("uvx", args=["mcp-server-fetch"])
    """
    assert _codes(src) == []


def test_mc002_silent_on_fstring_with_no_interpolation():
    src = """
    from mcp.client.stdio import StdioServerParameters
    def hardcoded():
        return StdioServerParameters(command=f"python3")
    """
    assert _codes(src) == []


def test_mc002_fires_on_fstring_with_interpolation():
    # f-string with interpolation is NOT a literal -- the interpolated value is
    # the injection vector.
    src = """
    from mcp.client.stdio import StdioServerParameters
    def build(cmd):
        return StdioServerParameters(command=f"{cmd}")
    """
    assert _codes(src) == ["MC002"]


# --------------------------------------------------------------------------- #
# provenance: the finding message must cite CVE-2026-30623 + the real advisory
# URLs so a reviewer can verify provenance in one click.
# --------------------------------------------------------------------------- #


def test_mc002_message_cites_cve_and_advisory_urls():
    src = """
    from mcp.client.stdio import StdioServerParameters
    def f(cfg):
        return StdioServerParameters(command=cfg["command"])
    """
    findings = check_source(textwrap.dedent(src), "t.py")
    assert len(findings) == 1
    msg = findings[0].message
    assert "CVE-2026-30623" in msg
    assert "https://www.tenable.com/cve/CVE-2026-30623" in msg
    assert "https://docs.litellm.ai/blog/mcp-stdio-command-injection-april-2026" in msg
    assert (
        "https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/"
        in msg
    )


def test_mc002_locates_line_of_call():
    src = """from mcp.client.stdio import StdioServerParameters


def f(cfg):
    # the sink sits on line 6
    return StdioServerParameters(command=cfg["command"])
"""
    findings = check_source(src, "t.py")
    assert len(findings) == 1
    assert findings[0].line == 6


# --------------------------------------------------------------------------- #
# guard-recognition variants: the rule must recognise a guard on ANY of the
# documented fix shapes, not just the canonical LiteLLM one.
# --------------------------------------------------------------------------- #


def test_mc002_silent_on_validate_named_guard_function():
    src = """
    from mcp.client.stdio import StdioServerParameters
    def _validate_command(cmd):
        allowed = {"npx", "uvx", "python"}
        if cmd not in allowed:
            raise ValueError("nope")
    def build(cfg):
        _validate_command(cfg["command"])
        return StdioServerParameters(command=cfg["command"])
    """
    assert _codes(src) == []


def test_mc002_silent_on_set_call_allowlist():
    src = """
    from mcp.client.stdio import StdioServerParameters
    ALLOWED = set(["npx", "uvx", "python"])
    def build(cfg):
        if cfg["command"] not in ALLOWED:
            raise ValueError("nope")
        return StdioServerParameters(command=cfg["command"])
    """
    assert _codes(src) == []


def test_mc002_silent_when_no_stdio_call_present():
    # A source file with no StdioServerParameters call -> no MC002 finding.
    src = """
    import subprocess
    def f(cfg):
        return subprocess.run([cfg["command"]])
    """
    assert _codes(src) == []


def test_mc002_silent_on_unparseable_source():
    # Syntax errors are another tool's job; mcp-lint reports CVE-shaped findings.
    assert check_source("def broken(:\n", "t.py") == []


def test_mc002_fires_at_module_scope():
    # Module-scope StdioServerParameters with a non-literal command is still
    # the documented shape; the rule treats the module body as the scope.
    src = """
    from mcp.client.stdio import StdioServerParameters
    import os
    PARAMS = StdioServerParameters(command=os.environ["MCP_COMMAND"])
    """
    assert _codes(src) == ["MC002"]


# --------------------------------------------------------------------------- #
# on-disk fixture smoke tests (build-honesty: the fixtures in tests/fixtures/
# must actually bite the rule they claim to exercise -- guards against the
# silent-noop failure mode after a refactor).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "fixture,expect_codes",
    [
        ("mc002_vulnerable.py", ["MC002"]),
        ("mc002_fixed_allowlist.py", []),
        ("mc002_fixed_inline.py", []),
        ("mc002_safe_literal.py", []),
    ],
)
def test_mc002_fixture_bite(fixture, expect_codes):
    src = (FIX / fixture).read_text()
    assert [f.code for f in check_source(src, str(FIX / fixture))] == expect_codes


def test_mc002_ast_parse_succeeds_on_all_fixtures():
    # Sanity: each fixture must be valid Python (else the rule can't see it).
    for fx in FIX.glob("mc002_*.py"):
        ast.parse(fx.read_text())
