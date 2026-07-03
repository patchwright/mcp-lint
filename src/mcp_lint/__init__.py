"""mcp-lint -- static checks for MCP server configs, each pinned to a real CVE.

Every rule in this package is born from a concrete MCP vulnerability (a CVE or
GHSA with a public advisory) and distilled into the smallest statically-detectable
shape that catches the class without flooding the user with false positives.
Each finding message carries the CVE id and advisory URL so a human reader can
verify the provenance in one click. See ``checkers.py`` for the rule provenance.
"""

from __future__ import annotations

from .checkers import CHECKERS, Finding, check_payload
from .cli import main

__version__ = "0.1.0"

__all__ = [
    "CHECKERS",
    "Finding",
    "check_payload",
    "main",
    "__version__",
]
