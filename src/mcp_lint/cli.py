"""Command-line entry point for mcp-lint."""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import json
import sys
from collections.abc import Collection, Iterator
from pathlib import Path

from .checkers import CHECKERS, Finding, check_payload
from .source_checkers import SOURCE_CHECKERS, check_source

# Junk directories never worth scanning when walking a tree. Matched against
# path *components below the walked root* (so `mcp-lint .venv` still honours an
# explicit arg), not against explicit file arguments. Mirrors wildlint.
_DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".venv",
        ".virtualenv",
        "venv",
        ".tox",
        "node_modules",
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".benchmarks",
        "build",
        "dist",
        ".eggs",
        ".idea",
        ".vscode",
        "site-packages",
    }
)


def _is_excluded(
    path: Path,
    *,
    no_default_exclude: bool,
    extra_excludes: Collection[str],
    skip_first: int = 0,
) -> bool:
    """Should a rglob-discovered ``path`` be skipped? Mirrors wildlint's contract."""
    sub_parts = path.parts[skip_first:]
    if not no_default_exclude and any(p in _DEFAULT_EXCLUDE_DIRS for p in sub_parts):
        return True
    if extra_excludes:
        full = str(path)
        rel = Path(*sub_parts).as_posix() if sub_parts else ""
        for pat in extra_excludes:
            if (
                fnmatch.fnmatch(full, pat)
                or (rel and fnmatch.fnmatch(rel, pat))
                or any(fnmatch.fnmatch(part, pat) for part in sub_parts)
            ):
                return True
    return False


_LINT_SUFFIXES = (".json", ".py")


def _iter_targets(
    paths: Collection[str],
    *,
    no_default_exclude: bool = False,
    extra_excludes: Collection[str] = (),
) -> Iterator[Path]:
    """Yield lintable files. Explicit file args are scanned as-is; directory
    args are walked with default/config excludes applied to descendants.

    v0.1 shipped JSON config only. v0.2 adds ``.py`` for the MC002 source-level
    rule (CVE-2026-30623); ast-grep multi-language pack is the template for the
    JS/TS arm (CVE-2025-6514 / mcp-remote), still deferred.
    """
    for raw in paths:
        root = Path(raw)
        if root.is_dir():
            skip = len(root.parts)
            for pat in ("*.json", "*.py"):
                for f in sorted(root.rglob(pat)):
                    if not _is_excluded(
                        f,
                        no_default_exclude=no_default_exclude,
                        extra_excludes=extra_excludes,
                        skip_first=skip,
                    ):
                        yield f
        elif root.is_file() and root.suffix in _LINT_SUFFIXES:
            yield root


def check_file(
    path: Path, *, pedantic: bool = False, codes: set[str] | None = None
) -> tuple[list[Finding], list[str]]:
    """Return ``(findings, errors)`` for one file.

    Dispatches on suffix: ``.json`` -> JSON config checkers (MC001 et al.);
    ``.py`` -> Python source checkers (MC002 et al.). Findings are CVE-pinned
    diagnostic strings. Errors are parse/decode failures -- they are *not*
    findings and surface on stderr in text mode (exit 2 when no findings
    accompany them).
    """
    errors: list[str] = []
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [], [f"{path}: error: not valid UTF-8, skipped"]
    except OSError as exc:
        return [], [f"{path}: error: {exc.strerror or exc}"]

    if path.suffix == ".py":
        findings = check_source(source, str(path), codes=codes)
        return findings, errors

    try:
        payload = json.loads(source)
    except json.JSONDecodeError as exc:
        loc = f"{path}:{exc.lineno}:{exc.colno}: "
        return [], [f"{loc}JSONDecodeError: {exc.msg}"]

    findings = check_payload(
        payload, str(path), source=source, pedantic=pedantic, codes=codes
    )
    return findings, errors


def _build_parser() -> argparse.ArgumentParser:
    from . import __version__

    all_rules = list(CHECKERS) + list(SOURCE_CHECKERS)
    rules = ", ".join(f"{c.code} ({c.name}, {c.tier})" for c in all_rules)
    parser = argparse.ArgumentParser(
        prog="mcp-cve-lint",
        description="Static checks for MCP configs and server source. Every rule "
        "is pinned to a real CVE/GHSA. Rules: " + rules + ".",
    )
    parser.add_argument(
        "paths", nargs="*", default=["."], help="files or dirs (default: .)"
    )
    parser.add_argument(
        "--pedantic",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="also run opt-in higher-false-positive rules",
    )
    parser.add_argument(
        "--select",
        metavar="CODES",
        default=None,
        help="comma-separated rule codes to run exclusively, e.g. MC001 "
        "(overridable via [tool.mcp-lint])",
    )
    parser.add_argument(
        "--no-default-exclude",
        action="store_true",
        help="do not skip common junk dirs (.venv, node_modules, build, ...) "
        "when walking directories",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        metavar="GLOB",
        default=None,
        help="additional path glob to exclude (repeatable)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    pedantic = bool(args.pedantic)
    if args.select is not None:
        codes = {c.strip().upper() for c in args.select.split(",") if c.strip()} or None
    else:
        codes = None
    extra_excludes: list[str] = list(args.exclude or ())

    paths = args.paths or ["."]

    findings: list[Finding] = []
    errors: list[str] = []
    valid_paths: list[str] = []
    for raw in paths:
        if Path(raw).exists():
            valid_paths.append(raw)
        else:
            errors.append(f"{raw}: error: no such file or directory")
    for file in _iter_targets(
        valid_paths,
        no_default_exclude=args.no_default_exclude,
        extra_excludes=tuple(extra_excludes),
    ):
        fnd, err = check_file(file, pedantic=pedantic, codes=codes)
        findings.extend(fnd)
        errors.extend(err)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "findings": [dataclasses.asdict(f) for f in findings],
                    "errors": errors,
                },
                indent=2,
            )
        )
    else:
        for f in findings:
            print(f)
        for e in errors:
            print(e, file=sys.stderr)
        if findings:
            print(f"\n{len(findings)} finding(s).", file=sys.stderr)

    # Exit codes (ruff-compatible, mirrors wildlint): 1 = lint findings present;
    # 2 = errors only (e.g. an unparseable or missing file) with no findings;
    # 0 = clean. Lets a CI consumer tell "your config has a real finding" apart
    # from "mcp-lint hit a file it couldn't parse" without parsing stderr.
    if findings:
        return 1
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
