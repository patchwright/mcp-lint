# mcp-lint

A static linter for **MCP (Model Context Protocol) server configs** where every
rule is pinned to a real, public MCP CVE or GHSA. Each finding message carries
the CVE id and an advisory URL so a reviewer can verify the provenance in one
click; each rule ships with a fixture that proves it actually bites the
documented vulnerable shape (build-honesty: no silent no-ops). The pattern is
the one proven out by [`wildlint`](https://github.com/patchwright/wildlint) --
provenance-pinned lint, fail-loud exit codes, corpus-gate-ready -- transposed
to MCP security, where the surface is moving fast and the configs that wire
agents to servers are the new privilege boundary.

This is **v0.1: one rule, CVE-pinned.** It is not a complete MCP security
scanner; it is the first brick. See [Honesty note](#honesty-note) below.

## Install

```bash
uv tool install .          # or: pip install -e .
mcp-lint --version
```

## Use

```bash
mcp-lint .mcp.json                  # lint one config
mcp-lint .                          # walk a tree for *.json
mcp-lint --format json .mcp.json    # machine-readable
mcp-lint --select MC001 .mcp.json   # run one rule
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
$ mcp-lint tests/fixtures/mc001_vulnerable.json
tests/fixtures/mc001_vulnerable.json:4:6: MC001 MCP server 'inspector' exposes a
network endpoint (http://0.0.0.0:6277/sse) on a non-loopback host (0.0.0.0) with
no authentication header; this is the documented shape of CVE-2025-49596 ...
```

**Stays silent** (green fixtures): loopback binds (`127.0.0.1` / `::1` /
`localhost`), entries with `headers.Authorization` / `X-API-Key` / `X-Auth-Token`
/ `Cookie`, or stdio entries (no `url`). See `tests/fixtures/mc001_safe.json`
and `tests/fixtures/mc001_with_auth.json`.

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

- **One rule, one surface.** v0.1 lints JSON MCP config files only. The Python
  and TypeScript/JavaScript *source* surfaces (where most MCP servers and
  clients live) are the next two bricks; the wildlint ast-grep multi-language
  pack is the template for the JS/TS arm.
- **MC001 flags the operator-controllable half of CVE-2025-49596.** The 0.14.1
  fix ships authentication *inside* the Inspector binary, so even a loopback
  bind was vulnerable pre-fix (DNS-rebinding / browser-origin confusion). MC001
  does not clear an entry as safe; it flags the missing credential on a
  non-loopback bind. The loopback-no-auth arm is documented in `DEFERRED`
  pending a corpus pass to size its false-positive rate.
- **CVEs are not invented.** Where a CVE's exact technical signature is
  summarized rather than quoted, the rule's docstring says so and the fixture is
  labelled with the documented shape. Every advisory URL in a finding is real.

## Roadmap

- **MC001 loopback arm** (PEDANTIC) -- same CVE, residual DNS-rebind class.
- **MC002 -- CVE-2025-6514** -- `mcp-remote` command injection (JS/TS surface).
- **MC003 -- CVE-2026-30623** -- LiteLLM RCE (Python `eval/exec` on model metadata).
- **MC004 -- GHSA-rww4-4w9c-7733** -- FastMCP confused deputy (Python source).
- **Corpus gate** -- mirror wildlint's `scripts/corpus_baseline.json` so a
  regression that loses a real-world finding fails CI.

## License

MIT.
