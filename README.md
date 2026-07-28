# mcp-lint

[![CI](https://github.com/patchwright/mcp-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/patchwright/mcp-lint/actions/workflows/ci.yml)

*Published on PyPI/CLI as **`mcp-cve-lint`** — the name `mcp-lint` was already
taken by an unrelated package. The GitHub repo keeps its original name. (No
PyPI badge yet — see RELEASING.md, publish is still pending.)*

A static linter for **MCP (Model Context Protocol) server configs and source**
where every rule is pinned to a real, public MCP CVE or GHSA. Each finding
message carries the CVE id and an advisory URL so a reviewer can verify the
provenance in one click; each rule ships with a fixture that proves it actually
bites the documented vulnerable shape (build-honesty: no silent no-ops), and a
corpus gate pins finding counts over real MCP packages so a checker change that
drifts them fails CI before release. The pattern is the one proven out by
[`wildlint`](https://github.com/patchwright/wildlint) -- provenance-pinned lint,
fail-loud exit codes, corpus-gated -- transposed to MCP security, where the
surface is moving fast and the configs that wire agents to servers are the new
privilege boundary.

This is **v0.2: two rules across two surfaces (JSON config + Python source),
CVE-pinned, corpus-gated.** It is not a complete MCP security scanner; the
JS/TS source surface and the control-flow-sensitive rules are the next bricks.
See [Honesty note](#honesty-note) below.

## Install

```bash
pip install mcp-cve-lint   # or, from a clone: uv tool install . / pip install -e .
mcp-cve-lint --version
```

## Use

```bash
mcp-cve-lint .mcp.json                  # lint one JSON config (MC001)
mcp-cve-lint server.py                  # lint one Python source file (MC002)
mcp-cve-lint .                          # walk a tree for *.json + *.py
mcp-cve-lint --format json .            # machine-readable
mcp-cve-lint --select MC002 src/        # run one rule
```

Exit codes are ruff-compatible: **0** clean, **1** findings present, **2**
errors only (e.g. an unparsable JSON file) with no findings.

## Rules

### MC001 -- unauth-network-server -- `default` tier

An `mcpServers` entry whose `url` is on a **non-loopback** host and whose entry
carries **no authentication header**. Maps to the documented root cause of:

> **CVE-2025-49596** -- MCP Inspector unauthenticated remote code execution
> (fixed in 0.14.1). Versions of MCP Inspector below 0.14.1 are vulnerable to
> remote code execution due to lack of authentication between the Inspector
> client and proxy.
>
> - NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-49596>
> - Oligo writeup: <https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596>

The Inspector proxy exposed an HTTP endpoint with no auth between client and
proxy; any network-reachable caller could drive it to spawn MCP servers and
execute commands over stdio. MC001 catches the user-controllable half of that
shape at config level.

**Bites** (red fixture: `tests/fixtures/mc001_vulnerable.json`):

```json
{
  "mcpServers": {
    "inspector": { "url": "http://0.0.0.0:6277/sse" }
  }
}
```

```
$ mcp-cve-lint tests/fixtures/mc001_vulnerable.json
tests/fixtures/mc001_vulnerable.json:4:6: MC001 MCP server 'inspector' exposes a
network endpoint (http://0.0.0.0:6277/sse) on a non-loopback host (0.0.0.0) with
no authentication header; this is the documented shape of CVE-2025-49596 ...
```

**Stays silent** (green fixtures): loopback binds (`127.0.0.1` / `::1` /
`localhost`), entries with `headers.Authorization` / `X-API-Key` / `X-Auth-Token`
/ `Cookie`, or stdio entries (no `url`). See `tests/fixtures/mc001_safe.json`
and `tests/fixtures/mc001_with_auth.json`.

### MC002 -- unsanitized-stdio-command -- `default` tier (Python source)

A `StdioServerParameters(command=<expr>)` call whose `command` is **not a string
literal** and whose enclosing scope has **no allowlist guard**. Maps to the
documented root cause of:

> **CVE-2026-30623** -- LiteLLM authenticated remote code execution via MCP
> stdio transport (fixed in v1.83.6-nightly / v1.83.7-stable, commit `7b7f304`).
> The application let users add MCP servers via JSON config with arbitrary
> `command`/`args`; LiteLLM executed these on the host without validation.
>
> - Tenable: <https://www.tenable.com/cve/CVE-2026-30623>
> - LiteLLM advisory: <https://docs.litellm.ai/blog/mcp-stdio-command-injection-april-2026>
> - OX Security cross-ecosystem advisory (10+ CVE family, same root cause):
>   <https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/>

The Anthropic MCP SDK's `StdioServerParameters` runs whatever `command` it is
handed. LiteLLM (and LangFlow, GPT Researcher, Agent Zero, LangBot, Bisheng,
Jaaz, Langchain-Chatchat, Fay -- the whole OX Security CVE family) passed
user-supplied JSON `command`/`args` straight through. The LiteLLM fix added
`MCP_STDIO_ALLOWED_COMMANDS = frozenset({"npx","uvx","python","python3","node",
"docker","deno"})` and validates `os.path.basename(command) in ALLOWED` before
construction. MC002 catches that shape in Python source: the sink with no guard.

**Bites** (red fixture: `tests/fixtures/mc002_vulnerable.py`):

```python
from mcp.client.stdio import StdioServerParameters

def build_server(user_config):
    command = user_config["command"]  # attacker-controlled
    return StdioServerParameters(command=command, args=[])  # MC002
```

```
$ mcp-cve-lint tests/fixtures/mc002_vulnerable.py
tests/fixtures/mc002_vulnerable.py:6:48: MC002 StdioServerParameters constructed
with a non-literal `command` and no allowlist guard in scope; this is the
documented shape of CVE-2026-30623 ...
```

**Stays silent** (green fixtures):

- **Module-level frozenset allowlist** (the LiteLLM 7b7f304 fix shape) --
  `tests/fixtures/mc002_fixed_allowlist.py`
- **Inline string-set allowlist** (`if cmd not in {"npx", ...}`) --
  `tests/fixtures/mc002_fixed_inline.py`
- **Literal command** (`command="npx"`, positional or keyword; f-strings with no
  interpolation) -- `tests/fixtures/mc002_safe_literal.py`
- **`validate`/`check`-named guard function** in scope

Recognised guards: an `in`/`not in` test against a string set/frozenset, a
module-level constant whose assignment is a string set, a name matching
`ALLOW|COMMAND|STDIO|MCP|TOOL|PERMIT|WHITELIST`, or a call to a
`validate`/`check`/`sanitize`-named function. Honesty caveat: the guard scan is
scope-wide, not path-sensitive (a guard on any branch silences the rule) --
this trades a few false negatives for near-zero false positives on the corpus;
a PEDANTIC tier (v0.3) can tighten to "the guard dominates the call's branch."

## Corpus gate

`scripts/corpus_diff.py` pins finding counts over a real-world MCP-package
corpus and fails on drift. The v0.2 corpus:

| package (pinned) | version | MC001 | MC002 |
| --- | --- | ---: | ---: |
| `mcp` (Anthropic SDK -- defines the sink) | 1.28.1 | 0 | 0 |
| `fastmcp` (framework) | 3.4.2 | 0 | 1 |
| `langchain-mcp-adapters` (adapter) | 0.3.0 | 0 | 1 |

The two MC002 findings in `fastmcp` and `langchain-mcp-adapters` are
**true-positives-at-the-sink**: each constructs
`StdioServerParameters(command=<param>)` with no allowlist, exactly the
CVE-2026-30623 shape. Both are transport/framework layers (OX Security lists
them under "won't patch -- caller's responsibility"), so the finding is real
but the responsibility is delegated; the count is stable and the gate's job is
to catch a checker change that moves it, not to judge the framework's design.

```bash
uv run python scripts/corpus_diff.py            # compare to baseline; exit 1 on drift
uv run python scripts/corpus_diff.py --update    # rewrite baseline (intended drift only)
```

The gate runs in CI (`.github/workflows/ci.yml`, the `corpus` job).

## Provenance tiers

Inherited from wildlint. Every rule declares a tier:

- **`default`** -- low false-positive; on unless deselected. MC001 is default.
- **`pedantic`** -- higher false-positive; opt-in via `--pedantic`. Reserved for
  rules whose class is real but whose cost on a real corpus is not yet measured.

Bug classes pinned to a real CVE but **not yet shipped** are documented in
`DEFERRED` in `src/mcp_lint/checkers.py` -- the CVE provenance is kept so a
future rule can pick it up once its detector design and false-positive
measurement land. v0.1 ships exactly one rule, on one surface (JSON config).

## Honesty note

- **Two rules, two surfaces.** v0.2 lints JSON MCP config (MC001) and Python
  source (MC002). The TypeScript/JavaScript *source* surface (where the
  mcp-remote client lives) is the next brick; the wildlint ast-grep
  multi-language pack is the template for the JS/TS arm.
- **MC001 flags the operator-controllable half of CVE-2025-49596.** The 0.14.1
  fix ships authentication *inside* the Inspector binary, so even a loopback
  bind was vulnerable pre-fix (DNS-rebinding / browser-origin confusion). MC001
  does not clear an entry as safe; it flags the missing credential on a
  non-loopback bind. The loopback-no-auth arm is **held** -- see the `DEFERRED`
  entry in `src/mcp_lint/checkers.py` for the full FP reasoning (a config-level
  rule cannot distinguish "Inspector <0.14.1 on loopback" from "any innocent
  local dev server on loopback", and the latter is the canonical quickstart
  shape; the corpus cannot size it either because MCP libraries ship no
  consumer `.mcp.json`).
- **MC002 flags the sink, not the responsibility.** The rule fires wherever
  `StdioServerParameters(command=<expr>)` has no guard in scope, including in
  framework/transport code that has explicitly declined to add an allowlist
  (OX Security's "won't patch" list). The finding is real at the sink; whether
  the framework *should* guard is a design question the rule does not answer.
- **CVEs are not invented; signatures are verified against the patch.** v0.2
  corrected three DEFERRED entries whose original CVE summaries did not match
  the actual patched code. CVE-2026-30623 was described as "eval/exec on model
  metadata" but is actually MCP stdio command injection (shipped as MC002
  against the verified LiteLLM 7b7f304 signature). CVE-2026-27124 (FastMCP)
  was described as "tool-name relay" but is actually missing OAuth-proxy
  consent verification. When a CVE's summary and its patch diverge, the patch
  is the source of truth. See `RELEASING.md` for the full honesty protocol.

## Roadmap

- **MC001 loopback arm** -- held; the `DEFERRED` entry documents why a
  config-level PEDANTIC rule would fire on every innocent local-dev quickstart
  with no way to tell the dangerous case apart at this layer.
- **CVE-2025-6514** -- `mcp-remote` OS command injection (JS/TS surface). The
  fix uses `execFile`/argument arrays instead of a shell string; deferred
  until the ast-grep multi-language surface lands.
- **CVE-2026-27124 / GHSA-rww4-4w9c-7733** -- FastMCP OAuth-proxy missing
  consent verification. A control-flow omission rather than a syntactic sink;
  deferred until a control-flow-sensitive detector design lands.
- **MC002 path-sensitivity** -- a PEDANTIC tier that requires the guard to
  dominate the call's branch (not just be present in the scope).

## CI

`.github/workflows/ci.yml` runs four jobs on every push and PR:

- **test** -- pytest matrix on Python 3.9 and 3.13
- **lint** -- `ruff check` + `ruff format --check` (ruff pinned to 0.6.9)
- **type** -- `mypy src/mcp_lint` (strict)
- **corpus** -- `scripts/corpus_diff.py` (drift vs baseline)

## License

MIT.
