"""Source-level detector registry for mcp-lint.

Where ``checkers.py`` lints JSON *config* (the operator-controllable surface),
this module lints MCP server/client *source code* -- the surface where most
real MCP CVEs actually live (the JSON config is only the trigger; the sink is
in Python/JS/TS source that runs whatever the config feeds it).

A source checker exposes ``code``, ``name``, ``tier`` and a
``check(source, path) -> list[Finding]`` method. ``source`` is raw UTF-8 text;
the checker parses it (Python ``ast`` for v0.2; ast-grep multi-language pack is
the template for JS/TS, deferred). Findings reuse the same ``Finding`` dataclass
as the JSON checkers so the CLI renders them identically.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from .checkers import DEFAULT, Finding


def _line_col(node: ast.AST) -> tuple[int, int]:
    """Return (1-based line, 0-based col) for a node, falling back to (1, 0)."""
    return (getattr(node, "lineno", 1), max(0, getattr(node, "col_offset", 0)))


def _is_str_literal(node: ast.AST) -> bool:
    """True for an ``ast.Constant`` string or a string-only JoinedSTR/f-string.

    A literal command (``StdioServerParameters(command="npx")``) cannot be
    attacker-controlled at construction time, so the rule stays silent on it.
    F-strings with no interpolated expressions are also statically known and
    treated as literal; f-strings WITH interpolation are NOT literal (the
    interpolated value is the injection vector).
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    return False


def _name_id(node: ast.AST) -> str | None:
    """The trailing attribute/name of a dotted call, e.g. ``mcp.client.stdio.
    StdioServerParameters`` -> ``StdioServerParameters``. Returns ``None`` for
    non-name callables (subscripts, calls, etc.)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_string_set(node: ast.AST) -> bool:
    """True when ``node`` is a set/frozenset literal of string constants -- the
    inline-allowlist shape. Recognises both ``{"a", "b"}`` and
    ``frozenset({"a", "b"})`` / ``set(("a", "b"))``."""
    if isinstance(node, ast.Set):
        return all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts
        )
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in {"frozenset", "set"} and node.args:
            arg = node.args[0]
            return _is_string_set(arg)
    return False


# Constant-name keywords that signal an MCP-stdio allowlist. Conservative: the
# LiteLLM fix constant ``MCP_STDIO_ALLOWED_COMMANDS`` matches COMMAND and ALLOW.
# A generic ``SOME_NAMES`` would not match, so unrelated membership tests do not
# silence the rule.
_ALLOWLIST_NAME_RE = re.compile(
    r"(ALLOW|COMMAND|STDIO|MCP|TOOL|PERMIT|WHITELIST)", re.IGNORECASE
)

# Function-name keywords that signal a validation guard (e.g. ``_validate_command``,
# ``check_stdio_command``, ``is_allowed_launcher``). Conservative.
_GUARD_FUNC_RE = re.compile(
    r"(validate|check|verify|allowlist|sanitize|is_allowed|_check)", re.IGNORECASE
)


def _scope_has_guard(body: list[ast.stmt], module_names: dict[str, ast.AST]) -> bool:
    """Does this function/module body contain an allowlist guard for a stdio
    command?

    Recognised guard shapes (mirroring the LiteLLM 7b7f304 fix and the inline
    equivalents an operator might write):

    * ``x (not) in {"npx", "uvx", ...}`` -- inline string set (any comparator)
    * ``x (not) in frozenset({...})`` / ``set([...])`` -- call-wrapped string set
    * ``x (not) in ALLOWED_COMMANDS`` -- a module-level name that resolves to a
      string set, OR whose name matches the allowlist-keyword regex (defensive:
      catches constants whose assignment we couldn't fully resolve)
    * ``_validate_command(x)`` / ``check_stdio(x)`` -- a call to a function whose
      name signals command validation

    Conservative in both directions: it scans the whole body (a guard on any
    path counts), so it can under-flag when a guard sits on an unrelated branch.
    That is the v0.2 discipline -- keep false positives near zero on the corpus;
    a future PEDANTIC tier can tighten to "guard dominates the call's branch."
    """
    for stmt in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(stmt, ast.Compare) and any(
            isinstance(op, (ast.In, ast.NotIn)) for op in stmt.ops
        ):
            for cmp in stmt.comparators:
                if _is_string_set(cmp):
                    return True
                if isinstance(cmp, ast.Name):
                    resolved = module_names.get(cmp.id)
                    if resolved is not None and _is_string_set(resolved):
                        return True
                    if _ALLOWLIST_NAME_RE.search(cmp.id):
                        return True
        if isinstance(stmt, ast.Call):
            fname = _name_id(stmt.func)
            if fname and _GUARD_FUNC_RE.search(fname):
                return True
    return False


def _collect_module_string_sets(tree: ast.Module) -> dict[str, ast.AST]:
    """Map module-level ``NAME = <string set>`` assignments by name. Used to
    resolve ``x in NAME`` guards where NAME is e.g.
    ``MCP_STDIO_ALLOWED_COMMANDS = frozenset({...})``."""
    out: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and _is_string_set(node.value):
                    out[tgt.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None and _is_string_set(node.value):
                out[node.target.id] = node.value
    return out


# --------------------------------------------------------------------------- #
# MC002 -- StdioServerParameters constructed from user input without an allowlist
# Origin: CVE-2026-30623 (LiteLLM authenticated RCE via MCP stdio transport)
# Provenance:
#   * https://www.tenable.com/cve/CVE-2026-30623
#   * LiteLLM advisory (fix commit 7b7f304, PR #25343):
#     https://docs.litellm.ai/blog/mcp-stdio-command-injection-april-2026
#   * OX Security cross-ecosystem advisory (10+ CVE family, same root cause):
#     https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
# Documented root cause: Anthropic's MCP SDK runs whatever ``command`` it is
# handed via ``StdioServerParameters``; LiteLLM (and LangFlow, GPT Researcher,
# Agent Zero, LangBot, Bisheng, Jaaz, Langchain-Chatchat, Fay, ...) passed
# user-supplied JSON ``command``/``args`` straight through without an allowlist.
# The LiteLLM fix added ``MCP_STDIO_ALLOWED_COMMANDS = frozenset({"npx","uvx",
# "python","python3","node","docker","deno"})`` and validates
# ``os.path.basename(command) in ALLOWED`` before construction.
# --------------------------------------------------------------------------- #
class StdioCommandInjection:
    """A ``StdioServerParameters(command=<expr>)`` call whose ``command`` is not
    a string literal and whose enclosing scope has no allowlist guard.

    Pinned to CVE-2026-30623 and the OX Security MCP-stdio CVE family. The sink
    is the MCP SDK's ``StdioServerParameters`` dataclass -- the documented shape
    across the whole CVE family is "user-controlled ``command`` reaches
    ``StdioServerParameters`` without validation, and the SDK runs it as a
    subprocess." The LiteLLM fix (commit ``7b7f304``) is the canonical patch:
    a ``frozenset`` allowlist checked via ``os.path.basename(command) not in
    ALLOWED`` before the ``StdioServerParameters`` construction.

    Stays silent when:

    * the ``command`` argument is a string literal / f-string with no
      interpolation (statically known, cannot be attacker-controlled), OR
    * the enclosing function/module body contains a recognised allowlist guard
      -- an ``in``/``not in`` test against a string set/frozenset, against a
      module-level constant whose assignment is a string set, against a name
      matching ``ALLOW|COMMAND|STDIO|MCP|TOOL|PERMIT|WHITELIST``, or a call to a
      ``validate``/``check``/``sanitize``-named function.

    Honesty caveat: the guard scan is scope-wide, not path-sensitive. A guard
    on an unrelated branch will silence the rule. That trades a few false
    negatives for near-zero false positives -- the v0.2 discipline. A PEDANTIC
    tier (v0.3) can tighten to "the guard dominates the call's branch."
    """

    code = "MC002"
    name = "unsanitized-stdio-command"
    tier = DEFAULT

    _SINK_NAME = "StdioServerParameters"

    def _extract_command(self, call: ast.Call) -> ast.AST | None:
        """The ``command`` argument: the ``command=`` keyword, else positional
        [0] (``command`` is the first field of the SDK dataclass). None if not
        found."""
        for kw in call.keywords:
            if kw.arg == "command":
                return kw.value
        if call.args:
            return call.args[0]
        return None

    def _scope_body(self, node: ast.AST, tree: ast.Module) -> list[ast.stmt]:
        """The body of the enclosing function, or the module body if the call is
        at module scope. Walks parents via a pre-computed map."""
        parent_fn = _enclosing_function(node, tree)
        if parent_fn is not None:
            return list(parent_fn.body)
        return list(tree.body)

    def check(self, source: str, path: str, **_: Any) -> list[Finding]:
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            # Unparseable source is another tool's job (ruff, syntax check).
            # mcp-lint reports CVE-shaped findings, not syntax errors.
            return []
        module_names = _collect_module_string_sets(tree)
        out: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _name_id(node.func) != self._SINK_NAME:
                continue
            command = self._extract_command(node)
            if command is None:
                continue
            if _is_str_literal(command):
                continue
            body = self._scope_body(node, tree)
            if _scope_has_guard(body, module_names):
                continue
            line, col = _line_col(node)
            out.append(
                Finding(
                    path,
                    line,
                    col,
                    self.code,
                    "StdioServerParameters constructed with a non-literal `command` "
                    "and no allowlist guard in scope; this is the documented shape "
                    "of CVE-2026-30623 (LiteLLM authenticated RCE via MCP stdio "
                    "transport -- the SDK runs whatever `command` it is handed) and "
                    "the OX Security MCP-stdio CVE family (LangFlow, GPT Researcher, "
                    "Agent Zero, LangBot, Bisheng, Jaaz, Langchain-Chatchat, Fay). "
                    "The LiteLLM fix (commit 7b7f304) added "
                    '`MCP_STDIO_ALLOWED_COMMANDS = frozenset({"npx","uvx",'
                    '"python","python3","node","docker","deno"})` and '
                    "validates `os.path.basename(command) in ALLOWED` before "
                    "construction. Validate against an allowlist before constructing "
                    "StdioServerParameters. Advisories: "
                    "https://www.tenable.com/cve/CVE-2026-30623 ; "
                    "https://docs.litellm.ai/blog/mcp-stdio-command-injection-april-2026 ; "  # noqa: E501
                    "https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/",
                )
            )
        return out


def _enclosing_function(
    node: ast.AST, tree: ast.Module
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Walk parents to find the enclosing FunctionDef/AsyncFunctionDef.

    ``ast.walk`` is preorder BFS without parents, so we build a parent map once
    a call is found. (Building it lazily -- only when a sink is found -- keeps
    the common path fast: most files have no ``StdioServerParameters``.)"""
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    cur: ast.AST | None = parents.get(id(node))
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parents.get(id(cur))
    return None


SOURCE_CHECKERS = [StdioCommandInjection()]


def check_source(
    source: str, path: str, *, codes: set[str] | None = None
) -> list[Finding]:
    """Run the active source checkers over one Python source string; sorted."""
    out: list[Finding] = []
    active = (
        SOURCE_CHECKERS
        if codes is None
        else [c for c in SOURCE_CHECKERS if c.code in codes]
    )
    for checker in active:
        out.extend(checker.check(source, path))
    out.sort(key=lambda f: (f.line, f.col, f.code))
    return out
