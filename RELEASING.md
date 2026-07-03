# Releasing mcp-lint

Two questions, kept separate:

1. **Is it ready?** — the checklist below. Deterministic; run it every time.
2. **Does it ship?** — a published PyPI version is *permanent* (yankable, not
   deletable) and ships under the **patchwright** identity. So:
   - **new public surface** (new MC rule, new exported symbol, behavior
     change) → assemble the filled checklist + diff, get a human go, then
     publish.
   - **routine patch** (test-only, docs, a fix that doesn't change a rule's
     surface) → green checklist → publish + report.

The checklist replaces "because I said so." If an item is red, it doesn't ship —
no exceptions for vibes. A gate with substance, not caution dressed as a rule.

## Readiness checklist — every release

- [ ] full suite green: `uv run python -m pytest -q`
- [ ] `ruff check src tests` clean
- [ ] `ruff format --check src tests` clean
- [ ] `mypy src/mcp_lint` clean
- [ ] **provenance pinned** to a real CVE/GHSA with a verified advisory URL
      (verify the CVE exists in NVD before citing; do NOT invent CVEs or
      signatures). Recorded in the rule's docstring + the finding message +
      the README row.
- [ ] **build-honesty gate**: the checker goes RED on the vulnerable fixture
      and GREEN on the fixed fixture — `mcp-lint tests/fixtures/<rule>_vulnerable.*`
      exits 1, `mcp-lint tests/fixtures/<rule>_fixed.*` exits 0. Mirrors wildlint.
- [ ] version bumped in `src/mcp_lint/__init__.py` **and** `pyproject.toml`
      (semver: new rule/surface = minor; internal fix = patch)
- [ ] new public symbols exported from `src/mcp_lint/__init__.py` (`__all__`)
- [ ] `python -m build` succeeds; `twine check dist/*` PASSED
- [ ] `git status` clean apart from the release diff (no stray unrelated changes)
- [ ] **push access verified** — ensure you can push to `patchwright/mcp-lint`
      (via `gh auth`, a credential helper, or a PAT stored outside the repo)

### additionally — MC static rules (lint that fires on real code/config)

- [ ] **corpus_diff gate green**: `uv run python scripts/corpus_diff.py` shows no
      drift vs `scripts/corpus_baseline.json` (finding counts over a pinned
      mcp/fastmcp/langchain-mcp-adapters corpus). A jump — e.g. an MC002
      guard-detection regression taking fastmcp from 1 to 20 hits — fails here
      before the tag, not after release via external red-teaming. If a count
      change is intended (a real fix), re-run with `--update` and record why in
      the commit. Default tier must stay FP-near-zero on the corpus; pedantic-tier
      counts are tracked but advisory.
- [ ] **CVE verified in NVD** before the rule ships. If a CVE's exact signature
      is summarized rather than quoted, the fixture is labelled with the
      DOCUMENTED shape and the rule's docstring says so honestly. (v0.2's MC002
      cites CVE-2026-30623, verified via Tenable + the LiteLLM advisory + the
      OX Security cross-ecosystem advisory; the fixture mirrors LiteLLM commit
      7b7f304.)

## CVE-signature honesty

The DEFERRED entries in `src/mcp_lint/checkers.py` exist because a CVE's public
description sometimes does not match the actual patched code shape. v0.2
corrected three DEFERRED entries whose original signatures were wrong:

- **CVE-2026-30623** was described as "eval/exec on model metadata" but is
  actually MCP stdio command injection via `StdioServerParameters`. Shipped as
  MC002 against the verified signature (LiteLLM 7b7f304).
- **CVE-2026-27124 / GHSA-rww4-4w9c-7733** (FastMCP) was described as
  "tool-name relay across tenants" but is actually missing OAuth-proxy consent
  verification. Corrected in DEFERRED; the real signature is a control-flow
  omission (harder to AST-catch with low FP), still deferred.
- **CVE-2025-6514** (mcp-remote) surface correctly identified as JS/TS; the
  fix (execFile/argument arrays instead of a shell string) is documented in
  DEFERRED pending the ast-grep multi-language surface.

Lesson: when a CVE's summary and its patch diverge, the patch is the source of
truth. A rule written against a guessed signature is fiction even if the CVE id
is real.

## Publish mechanics (OIDC trusted publishing — no token in the workflow)

Push a tag → `.github/workflows/release.yml` builds + publishes via trusted
publishing (no stored PyPI token).

```bash
git commit -am "release: vX.Y.Z"        # or stage precisely
git tag -a vX.Y.Z -m "vX.Y.Z — <one-line>"
git push origin main vX.Y.Z             # gh auth / credential helper handles auth
```

`skip-existing: true` makes a re-tag idempotent (a version already on PyPI is a
no-op). Release notes live in the **tag annotation** (or an optional GitHub
Release) — there is no CHANGELOG file by project convention.

## Post-publish smoke (runs AFTER publish — the closing item)

- [ ] fresh install in a clean venv: `pip install mcp-lint==X.Y.Z`
- [ ] `mcp-lint --version` reports the new version
- [ ] the new rule fires: `mcp-lint tests/fixtures/<rule>_vulnerable.*` exits 1
- [ ] `python -c "import mcp_lint; print(mcp_lint.__version__, [c.code for c in mcp_lint.CHECKERS + mcp_lint.SOURCE_CHECKERS])"`

## What this gate is not

- Not a substitute for judgment on *what* ships under patchwright's name — that
  is the human-go tier for new surfaces.
- Not static — amend this file when the release process changes, so the gate
  reflects reality rather than rotting into a fiction.
