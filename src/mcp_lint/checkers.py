"""Detector registry for mcp-lint.

Each checker is pinned to a *real* MCP CVE or GHSA. The rule catches a concrete,
documented config/source pattern that maps to the CVE's root cause; the CVE id
and advisory URL appear in every finding message so a human reader can verify
the provenance in one click. Bug classes considered but not yet shipped live in
``DEFERRED`` so the reasoning is not lost.

A checker is any object exposing ``code``, ``name``, ``tier`` and a
``check(payload, path, source=None) -> list[Finding]`` method, where ``payload``
is the parsed document (currently a JSON object) and ``source`` is its raw text
(used to recover line/column for findings, since the stdlib JSON parser drops
positions). Register one by appending an instance to ``CHECKERS``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

DEFAULT = "default"  # low false-positive; on unless deselected
PEDANTIC = "pedantic"  # higher false-positive; opt-in via --pedantic

# Hosts that mean "this server stays on this machine" -- a network-reachable
# caller cannot reach a loopback bind without a separate compromise of the host.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"})


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    col: int
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.col}: {self.code} {self.message}"


def _line_col_of_substr(source: str, needle: str) -> tuple[int, int]:
    """Return (1-based line, 0-based col) of the first occurrence of ``needle``
    in ``source``. Falls back to ``(1, 0)`` when the needle is not present (the
    JSON parser already validated the structure, so this only happens if the
    serialized form re-encodes the URL -- a defensive case, not the common one).
    """
    idx = source.find(needle)
    if idx < 0:
        return 1, 0
    line = source.count("\n", 0, idx) + 1
    last_nl = source.rfind("\n", 0, idx)
    col = idx - (last_nl + 1) if last_nl >= 0 else idx
    return line, col


# --------------------------------------------------------------------------- #
# MC001 -- MCP HTTP/SSE server on a non-loopback interface without authentication
# Origin: CVE-2025-49596 (MCP Inspector unauthenticated RCE, fixed in 0.14.1)
# Provenance:
#   * https://nvd.nist.gov/vuln/detail/CVE-2025-49596
#   * https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596
# Documented root cause: "lack of authentication between the Inspector client
# and proxy" -- any network-reachable caller could drive the proxy to spawn MCP
# servers and execute arbitrary commands over stdio.
# --------------------------------------------------------------------------- #
class UnauthNetworkServer:
    """An ``mcpServers`` entry whose ``url`` is non-loopback and has no auth.

    Pinned to CVE-2025-49596 (MCP Inspector unauthenticated RCE, fixed in
    0.14.1). The Inspector proxy exposed an HTTP endpoint with no authentication
    between client and proxy, so any network-reachable caller could drive it to
    spawn MCP servers and execute commands over stdio. MC001 catches the
    user-controllable half of that shape: an MCP server declared in a JSON config
    whose ``url`` host is not loopback and whose entry carries no credential
    header.

    Honesty caveat: the 0.14.1 fix ships authentication *inside* the Inspector
    binary, so even a loopback bind was vulnerable pre-fix (DNS-rebinding /
    browser-origin confusion). This rule therefore flags the config-level shape
    -- a network-reachable endpoint with no credential -- which is the
    operator's controllable surface. It does NOT clear an entry as safe; it
    flags the missing credential on a non-loopback bind. A loopback-no-auth
    entry stays silent at this tier (a future PEDANTIC arm could flag it once
    the false-positive cost is measured against a corpus).

    Fires on a JSON ``mcpServers`` entry that:

    * has a ``url`` (HTTP/SSE transport) whose parsed host is NOT loopback, AND
    * carries no auth-shaped header (``Authorization``, ``X-API-Key``,
      ``X-Auth-Token``, ``Cookie``) and no entry-level token.

    Stays silent on stdio entries (no ``url``), loopback binds, and entries that
    declare a credential.
    """

    code = "MC001"
    name = "unauth-network-server"
    tier = DEFAULT

    _AUTH_HEADERS = frozenset({"authorization", "x-api-key", "x-auth-token", "cookie"})
    _AUTH_ENTRY_KEYS = frozenset({"authorization", "apikey", "api_key", "token"})

    def _has_auth(self, entry: dict[str, Any]) -> bool:
        headers = entry.get("headers")
        if isinstance(headers, dict) and any(
            str(k).lower() in self._AUTH_HEADERS for k in headers
        ):
            return True
        for key in self._AUTH_ENTRY_KEYS:
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return True
        return False

    def check(
        self, payload: Any, path: str, source: str | None = None
    ) -> list[Finding]:
        if not isinstance(payload, dict):
            return []
        servers = payload.get("mcpServers")
        if not isinstance(servers, dict):
            return []
        out: list[Finding] = []
        src = source or ""
        for name, entry in servers.items():
            if not isinstance(entry, dict):
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url.strip():
                continue  # stdio entry (command + args) is not this rule's surface
            host = (urlparse(url).hostname or "").lower()
            if not host or host in _LOOPBACK_HOSTS:
                continue
            if self._has_auth(entry):
                continue
            line, col = _line_col_of_substr(src, url)
            out.append(
                Finding(
                    path,
                    line,
                    col,
                    self.code,
                    f"MCP server {name!r} exposes a network endpoint ({url}) on a "
                    f"non-loopback host ({host}) with no authentication header; "
                    "this is the documented shape of CVE-2025-49596 (MCP Inspector "
                    "unauthenticated RCE, fixed in 0.14.1 by adding client<->proxy "
                    "auth). Bind to loopback or add a credential "
                    "(headers.Authorization). "
                    "Advisories: "
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-49596 ; "
                    "https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596",
                )
            )
        return out


CHECKERS = [
    UnauthNetworkServer(),
]


def select_checkers(
    *, pedantic: bool = False, codes: set[str] | None = None
) -> list[Any]:
    """Return the active checkers.

    ``pedantic`` includes the opt-in tier. ``codes`` (e.g. ``{"MC001"}``)
    restricts to those rules and, when given, overrides the tier filter.
    """
    if codes is not None:
        return [c for c in CHECKERS if c.code in codes]
    return [c for c in CHECKERS if c.tier == DEFAULT or pedantic]


def check_payload(
    payload: Any,
    path: str = "<unknown>",
    *,
    source: str | None = None,
    pedantic: bool = False,
    codes: set[str] | None = None,
) -> list[Finding]:
    """Run the selected checkers over one parsed JSON payload; sorted findings."""
    findings: list[Finding] = []
    for checker in select_checkers(pedantic=pedantic, codes=codes):
        findings.extend(checker.check(payload, path, source))
    findings.sort(key=lambda f: (f.line, f.col, f.code))
    return findings


# Bug classes pinned to a real CVE but NOT yet shipped. The v0.2 Python-source
# surface (MC002) is landed; the entries below remain deferred until their
# detector design and false-positive measurement land. Kept here so the CVE
# provenance is not lost -- and so the reasoning that holds each one is
# auditable rather than silent.
DEFERRED = {
    "mc001-loopback-no-auth-residual": (
        "Same CVE as MC001 (CVE-2025-49596), the loopback-and-no-auth half. "
        "HELD, with reasoning: the 0.14.1 fix ships auth inside the Inspector "
        "binary precisely because loopback alone did not protect against DNS-"
        "rebinding / browser-origin confusion. But that residual risk is a "
        "property of the server BINARY (Inspector <0.14.1), not of the JSON "
        "config -- a config-level rule cannot distinguish 'Inspector <0.14.1 on "
        "127.0.0.1' from 'any other innocent local dev server on 127.0.0.1', "
        "and the latter is the canonical MCP quickstart shape (every "
        "getting-started guide starts a server on 127.0.0.1 with no auth). "
        "Sizing via the v0.2 corpus does not help either: the corpus is MCP "
        "server LIBRARIES (pip packages), which ship no consumer .mcp.json, so "
        "BOTH arms of MC001 read 0 on it. A PEDANTIC rule here would flood "
        "every first-run developer with no way to tell the dangerous case "
        "apart at config level. Held until mcp-lint can correlate the JSON "
        "entry with the named server binary's version (out of scope for a "
        "config/source linter), at which point a PEDANTIC tier becomes a "
        "precise opt-in rather than a firehose."
    ),
    "cve-2025-6514-mcp-remote-shell-injection": (
        "CVE-2025-6514 (mcp-remote OS command injection) -- the mcp-remote "
        "CLIENT passed the OAuth `authorization_endpoint` URL into a shell "
        "command (open / xdg-open via string concatenation); a malicious MCP "
        "server could inject metacharacters for RCE. Verified in NVD and the "
        "JFrog disclosure. Surface is JS/TS source (the mcp-remote npm "
        "package), not Python and not JSON config; deferred until mcp-lint "
        "grows a TS/JS AST surface (the wildlint ast-grep multi-language pack "
        "is the template). The fix uses execFile/argument arrays instead of a "
        "shell string. Advisories: "
        "https://nvd.nist.gov/vuln/detail/CVE-2025-6514 ; "
        "https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/"
    ),
    "cve-2026-27124-fastmcp-oauth-consent": (
        "GHSA-rww4-4w9c-7733 / CVE-2026-27124 (FastMCP OAuthProxy confused "
        "deputy) -- the OAuth proxy callback did NOT verify the user's consent "
        "before completing the authorization-code exchange, enabling a confused "
        "deputy (a malicious authorization server could complete a flow without "
        "genuine consent). Verified in NVD and the FastMCP advisory. Fixed in "
        "FastMCP 3.2.0 by enforcing consent verification in the callback. The "
        "surface is Python source (FastMCP's OAuth proxy handler), and the "
        "documented signature is a MISSING consent-state check before issuing "
        "tokens -- a control-flow omission rather than a syntactic sink, which "
        "is harder to catch with a low-FP AST rule. Deferred until a "
        "control-flow-sensitive detector design lands. Advisory: "
        "https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-rww4-4w9c-7733 ; "  # noqa: E501
        "https://nvd.nist.gov/vuln/detail/CVE-2026-27124"
    ),
}
