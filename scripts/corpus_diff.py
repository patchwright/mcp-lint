#!/usr/bin/env python3
"""Diff mcp-lint's finding counts over a pinned real-world corpus against a
baseline.

This is the pre-release gate that internalizes the adversarial red-team: a
checker change that explodes false positives (a guard-detection tweak that
silences a real finding, or a broadening that floods the corpus) fails here
before a tag is cut, instead of requiring an external reviewer to notice after
release. Mirrors wildlint's ``scripts/corpus_diff.py`` (RELEASING.md).

The corpus is the pip-installable site-packages of three pinned MCP packages:
the Anthropic SDK (``mcp``), the FastMCP framework, and the LangChain MCP
adapters -- together covering the transport, framework, and adapter layers
where MCP-stdio command injection (CVE-2026-30623) and its siblings actually
live. Counts are deterministic for a pinned set of versions; a package
releasing a new version would drift the counts and mask a real checker change,
so every package is pinned.

Usage (from the mcp-lint repo root):
    uv run python scripts/corpus_diff.py            # compare to baseline; exit 1 on drift
    uv run python scripts/corpus_diff.py --update    # rewrite baseline with current counts
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / "scripts" / "corpus_baseline.json"

# pip-install spec -> import name (the site-packages dir mcp-lint scans).
# Pinned for reproducibility (a new package release would otherwise drift the
# counts and mask a checker change). The three packages cover the three layers
# named in the OX Security MCP-stdio advisory: root/SDK (mcp), framework
# (fastmcp), and adapter (langchain-mcp-adapters).
CORPUS = {
    "mcp==1.28.1": "mcp",
    "fastmcp==3.4.2": "fastmcp",
    "langchain-mcp-adapters==0.3.0": "langchain_mcp_adapters",
}
RULES = ["MC001", "MC002"]


def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=REPO, capture_output=True, text=True, **kw)


def _count(imp: str, site_packages: Path) -> dict[str, int]:
    """One mcp-lint scan per package (--format json, all default-tier rules),
    count per code. Both JSON-config (MC001) and Python-source (MC002) checkers
    run; .py files exercise MC002, the (absent) .mcp.json files would exercise
    MC001 -- the corpus is Python packages, so MC001 reads 0 by construction,
    but tracking it keeps the gate honest if a JSON test corpus is added."""
    src = site_packages / imp
    r = _run(["uv", "run", "mcp-lint", "--format", "json", str(src)])
    try:
        findings = json.loads(r.stdout).get("findings", [])
    except json.JSONDecodeError:
        print(
            f"  ! could not parse JSON for {imp} (mcp-lint stdout: {r.stdout[:200]!r})",
            file=sys.stderr,
        )
        return {rule: -1 for rule in RULES}
    return {rule: sum(1 for f in findings if f.get("code") == rule) for rule in RULES}


def main() -> int:
    update = "--update" in sys.argv
    with tempfile.TemporaryDirectory() as venv:
        py = f"{venv}/bin/python"
        _run(["uv", "venv", venv, "--quiet"])
        inst = _run(["uv", "pip", "install", "--python", py, "--quiet", *CORPUS])
        if inst.returncode != 0:
            print("corpus install failed:\n" + inst.stderr, file=sys.stderr)
            return 3
        sp = subprocess.run(
            [py, "-c", "import site; print(site.getsitepackages()[0])"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        site_packages = Path(sp)
        live = {imp: _count(imp, site_packages) for imp in CORPUS.values()}

    if update:
        data = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
        data["counts"] = live  # preserves _comment / _pinned / etc.
        BASELINE.write_text(json.dumps(data, indent=2) + "\n")
        print(f"baseline rewritten: {BASELINE}")
        return 0

    expected = json.loads(BASELINE.read_text())["counts"]
    drift = []
    print(
        f"{'package':<28} " + " ".join(f"{r:>6}" for r in RULES) + "   (base -> live)"
    )
    for imp in CORPUS.values():
        cells = []
        for rule in RULES:
            base = expected[imp][rule]
            now = live[imp][rule]
            mark = "" if base == now else f" {base}->{now} *"
            if base != now:
                drift.append((imp, rule, base, now))
            cells.append(f"{now:>6}{mark}")
        print(f"{imp:<28} " + " ".join(cells))

    if drift:
        print("\ncorpus drift -- counts changed:", file=sys.stderr)
        for imp, rule, base, now in drift:
            print(f"  {imp} {rule}: {base} -> {now}", file=sys.stderr)
        print(
            "\nIf the change is intended (real fix, not an FP explosion), re-run with "
            "--update and record why in the commit message.",
            file=sys.stderr,
        )
        return 1
    print("\ncorpus stable: all counts match baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
