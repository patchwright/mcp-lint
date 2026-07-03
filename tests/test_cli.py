"""CLI-level tests for mcp-lint (main / check_file / file walking).

The checker-level tests in test_checkers.py exercise ``check_payload`` directly;
these exercise the harness: directory walking + excludes, the error/exit-code
model, ``--select``, and ``--format json``. They drive ``cli.main`` against
files on disk via the ``tmp_path`` fixture and read stdout/stderr/exit through
``capsys``.
"""

from __future__ import annotations

import json

from mcp_lint.cli import main

_VULN = json.dumps({"mcpServers": {"inspector": {"url": "http://0.0.0.0:6277/sse"}}})
_SAFE = json.dumps({"mcpServers": {"inspector": {"url": "http://127.0.0.1:6277/sse"}}})


def _run(argv, capsys):
    rc = main(argv)
    out, err = capsys.readouterr()
    return rc, out, err


# --------------------------------------------------------------------------- #
# exit codes
# --------------------------------------------------------------------------- #


def test_finds_mc001_in_vuln_config_exits_1(tmp_path, capsys):
    f = tmp_path / "vuln.json"
    f.write_text(_VULN)
    rc, out, _ = _run([str(f)], capsys)
    assert rc == 1
    assert "MC001" in out
    assert "CVE-2025-49596" in out


def test_clean_config_exits_0(tmp_path, capsys):
    f = tmp_path / "safe.json"
    f.write_text(_SAFE)
    rc, out, err = _run([str(f)], capsys)
    assert rc == 0
    assert out == ""


# --------------------------------------------------------------------------- #
# directory walking + excludes
# --------------------------------------------------------------------------- #


def test_walks_dir_for_json_files(tmp_path, capsys):
    (tmp_path / "bad.json").write_text(_VULN)
    (tmp_path / "good.json").write_text(_SAFE)
    rc, out, _ = _run([str(tmp_path)], capsys)
    assert rc == 1
    assert "bad.json" in out
    assert "good.json" not in out


def test_default_exclude_skips_node_modules(tmp_path, capsys):
    (tmp_path / "bad.json").write_text(_VULN)
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "hidden.json").write_text(_VULN)
    rc, out, _ = _run([str(tmp_path)], capsys)
    assert rc == 1
    assert "node_modules" not in out


def test_no_default_exclude_includes_node_modules(tmp_path, capsys):
    (tmp_path / "good.json").write_text(_SAFE)
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "bad.json").write_text(_VULN)
    rc, out, _ = _run(["--no-default-exclude", str(tmp_path)], capsys)
    assert "node_modules" in out


def test_explicit_file_arg_under_excluded_dir_is_scanned(tmp_path, capsys):
    # An explicit file argument is scanned as-is even when it lives under a
    # default-excluded dir (preserves the pre-commit contract).
    nm = tmp_path / "node_modules"
    nm.mkdir()
    bad = nm / "bad.json"
    bad.write_text(_VULN)
    rc, out, _ = _run([str(bad)], capsys)
    assert rc == 1
    assert "bad.json" in out


# --------------------------------------------------------------------------- #
# loud failure (parse error / missing path)
# --------------------------------------------------------------------------- #


def test_invalid_json_to_stderr_and_nonzero(tmp_path, capsys):
    f = tmp_path / "broken.json"
    f.write_text("{not json")
    rc, out, err = _run([str(f)], capsys)
    assert rc == 2  # errors-only (no findings) -> exit 2, not 1
    assert out == ""  # findings stay on stdout; nothing to find
    assert "JSONDecodeError" in err
    assert str(f) in err


def test_missing_path_to_stderr_and_nonzero(tmp_path, capsys):
    missing = tmp_path / "nope.json"
    rc, out, err = _run([str(missing)], capsys)
    assert rc == 2
    assert "no such file" in err
    assert str(missing) in err


def test_findings_present_exit_1_even_with_errors(tmp_path, capsys):
    # A real finding alongside an error -> exit 1 (findings win), so CI reads
    # "you have a finding" distinctly from "mcp-lint hit a file it couldn't parse."
    (tmp_path / "bad.json").write_text(_VULN)
    missing = tmp_path / "missing.json"
    rc, out, err = _run([str(tmp_path / "bad.json"), str(missing)], capsys)
    assert rc == 1
    assert "MC001" in out
    assert "no such file" in err


# --------------------------------------------------------------------------- #
# --select
# --------------------------------------------------------------------------- #


def test_select_unknown_code_runs_no_checkers(tmp_path, capsys):
    # MC999 does not exist -> no checkers run -> no findings -> exit 0.
    f = tmp_path / "bad.json"
    f.write_text(_VULN)
    rc, out, _ = _run(["--select", "MC999", str(f)], capsys)
    assert rc == 0
    assert "MC001" not in out


def test_select_matching_code_runs_only_that_rule(tmp_path, capsys):
    f = tmp_path / "bad.json"
    f.write_text(_VULN)
    rc, out, _ = _run(["--select", "MC001", str(f)], capsys)
    assert rc == 1
    assert "MC001" in out


# --------------------------------------------------------------------------- #
# --format json
# --------------------------------------------------------------------------- #


def test_json_output_shape(tmp_path, capsys):
    f = tmp_path / "bad.json"
    f.write_text(_VULN)
    rc, out, _ = _run(["--format", "json", str(f)], capsys)
    assert rc == 1
    payload = json.loads(out)
    assert "findings" in payload and "errors" in payload
    assert any(fnd["code"] == "MC001" for fnd in payload["findings"])
    assert payload["findings"][0].keys() == {"path", "line", "col", "code", "message"}
    assert "CVE-2025-49596" in payload["findings"][0]["message"]


def test_json_clean_is_empty(tmp_path, capsys):
    f = tmp_path / "safe.json"
    f.write_text(_SAFE)
    rc, out, _ = _run(["--format", "json", str(f)], capsys)
    assert rc == 0
    payload = json.loads(out)
    assert payload["findings"] == [] and payload["errors"] == []
