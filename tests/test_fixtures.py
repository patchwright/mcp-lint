"""Smoke-test the on-disk fixtures the README points at.

Build-honesty discipline (mirrors wildlint): a fixture file committed under
``tests/fixtures/`` must actually bite the rule it claims to exercise. This
guards against the silent-noop failure mode -- a fixture that the rule no
longer catches after a refactor, with no test failing to tell us.
"""

from __future__ import annotations

from pathlib import Path

from mcp_lint.cli import main

FIX = Path(__file__).parent / "fixtures"


def test_vulnerable_fixture_bites(capsys):
    rc = main([str(FIX / "mc001_vulnerable.json")])
    out, _ = capsys.readouterr()
    assert rc == 1
    assert "MC001" in out
    assert "CVE-2025-49596" in out


def test_safe_fixture_stays_silent(capsys):
    rc = main([str(FIX / "mc001_safe.json")])
    out, _ = capsys.readouterr()
    assert rc == 0
    assert out == ""


def test_with_auth_fixture_stays_silent(capsys):
    # Non-loopback bind, but a credential is declared -- rule must stay silent.
    rc = main([str(FIX / "mc001_with_auth.json")])
    out, _ = capsys.readouterr()
    assert rc == 0
    assert out == ""
