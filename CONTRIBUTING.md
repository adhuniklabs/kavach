# Contributing to Adhunik Kavach

Thanks for helping harden Adhunik Kavach. This guide gets you productive fast.

## Project shape

- `core/kavach/` - the deterministic Python engine (recon, scanner adapters, finding model,
  scoring/gate, renderers). Pure stdlib, no runtime dependencies.
- `skill/` - the Claude Code skill (`SKILL.md`) and its progressive-disclosure reference files.
- `agents/` - the eight domain subagent definitions.
- `core/corpus/fixtures/` - deliberately-vulnerable apps that gate detection.
- `core/tests/` - unit tests (zero dependencies).

## Dev setup

```bash
git clone https://github.com/adhuniklabs/kavach.git && cd kavach/core
python3 -m unittest discover -s tests -v        # 30 tests, no deps
PYTHONPATH=. python3 -m kavach corpus           # corpus self-validation gate
PYTHONPATH=. python3 -m kavach scan . --format md   # try it on this repo
```

Docker is optional for local dev - the suite and corpus gate run without it. Install Docker to
exercise the full scanner set.

## Adding a scanner (the common contribution)

A scanner is one file in `core/kavach/scanners/`:

1. Subclass `Scanner` (`base.py`). Declare `id`, `title`, the Docker `image` and/or
   `native_binary`, and `network` (`"none"` for offline tools, `"default"` for advisory-DB tools).
2. Implement `applies(recon)` - when the detected stack earns this tool.
3. Implement `docker_args(recon)` and, if there's a native fallback, `native_cmd(...)`.
4. Implement `normalize(result, target, recon)` → a list of canonical `Finding`s. Be defensive:
   tolerate non-zero exit codes and shape drift; a broken parser must not abort the sweep.
5. Register it in `scanners/__init__.py`.
6. Add a fixture (or extend one) under `core/corpus/fixtures/` and a normalizer unit test with
   canned tool output. **Grow the corpus alongside the detector.**

See `skill/references/tool-catalog.md` for how tools map to the audit, and
`skill/references/tool-research.md` for license notes (some tools carry restrictions for
commercial/hosted use - check before adding).

## Style & conventions

- TypeScript-free; pure Python, `from __future__ import annotations`, stdlib only in the core.
- Match the surrounding file - no defensive boilerplate, no comments that restate the code.
- Never invent CVE IDs. Findings cite only what a scanner returned or a line you can point to.
- Fixtures use **fake, non-functional** secrets that our patterns catch but that don't trip real
  provider detectors (keep GitHub push protection green).

## Versioning

`kavach.__version__` is the only place a version number is written. `pyproject.toml` reads it via
`dynamic = ["version"]`, and a test fails if a literal reappears there or if `CHANGELOG.md` has no
section for the current version.

SemVer, read for a 0.x project — **the minor is the breaking axis**:

| Change | Bump |
|---|---|
| A phase id, the prereq graph, a gate artifact, or a CLI verb's output shape | **minor** |
| A python API a harness calls (`dispatch.ingest`, `modes.*`) | **minor** |
| A new verb, a new flag, a new scanner, a new agent | patch |
| A fix with no contract change | patch |

That mapping is not stylistic. `kavach resume` refuses to continue an audit whose recorded
`engine_version` differs from the running engine in `major.minor`, because resume re-derives what
is left from the phase contract — and finishing an audit under a contract different from the one
that wrote its artifacts reports an incoherent result as a complete one. A minor bump is how you
say "existing audits cannot be finished by this."

Releasing: bump `__version__`, move `[Unreleased]` to the new version with a date, run the gates
below, then tag `v<version>` and cut a GitHub release. The tag must match the version — the module
manifest that installs kavach pins a tag and expects the version inside to agree.

## Before you open a PR

```bash
cd core
python3 -m unittest discover -s tests           # must pass
PYTHONPATH=. python3 -m kavach corpus           # must pass (exit 0)
```

Then open a PR against `main` with a clear description. CI runs the suite + corpus gate on
Python 3.9 / 3.11 / 3.12. Conventional-commit style (`feat:`, `fix:`, `docs:`, `test:`) is
appreciated but not required.

Security issues → **do not** open a public PR/issue; see [`SECURITY.md`](./SECURITY.md).
