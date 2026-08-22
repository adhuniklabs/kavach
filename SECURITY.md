# Security Policy

Adhunik Kavach is a security tool, so we hold its own posture to the standard it enforces.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via GitHub's [**Report a vulnerability**](https://github.com/adhuniklabs/kavach/security/advisories/new)
(Security → Advisories), or email **security@adhuniklabs.com**.

Please include: affected version/commit, a description, reproduction steps, and impact. We aim to
acknowledge within **72 hours** and to agree on a disclosure timeline with you.

## Scope

In scope:

- The deterministic core (`core/kavach`) - e.g. a scanner adapter that mishandles untrusted tool
  output, a path-traversal in artifact writing, or a way to make a report misrepresent findings.
- The skill and subagent definitions (`skill/`, `agents/`) - e.g. an injection that subverts the
  audit or leaks a scoped file outside its target.
- The installer (`install.sh`).

Out of scope:

- Vulnerabilities in the third-party scanners Adhunik Kavach orchestrates (gitleaks, trivy, semgrep,
  etc.) - report those upstream. We invoke them via their official Docker images and do not vendor
  their code.
- Findings produced by running Adhunik Kavach against *your own* codebase - that is the tool working
  as intended.
- The deliberately-vulnerable fixtures under `core/corpus/fixtures/` - they contain fake,
  non-functional secrets on purpose, to test detection.

## Handling the audit output

An audit's `.kavach/` directory is raw evidence about the target codebase, and one scanner stores a
credential verbatim: trivy's secret rows are normalised with `snippet` set to the **raw matched
value** (`core/kavach/scanners/deps.py`), where gitleaks and trufflehog pass a redacted one. So
`.kavach/findings.json` - and an aggregate's `findings/G*/rows.json` - can contain a live secret
from the audited repo.

- **Gitignore `.kavach/` in the audited repository.** It is working state, not a deliverable to
  commit. The deliverables live in `.kavach/reports/`, and you choose which to share.
- Treat `reports/report.json` and `reports/report.sarif` as sensitive - they carry the finding set,
  snippets included - rather than as generic CI artifacts to publish.
- KAVACH's own outbound path is redacted by contract: `kavach issues plan/push` exports a
  `secret`-class finding as `file:line` + class + remediation only, with the matched value withheld,
  and a test asserts no member of that class leaks a matched value. Do not defeat it by pasting
  evidence into an issue or comment by hand.

This is documented in full, with the durable-vs-transient rules for confirm mode's credential-
bearing working files, in [`docs/output-structure.md`](./docs/output-structure.md).

## Supported versions

Until 1.0, only the latest `0.x` release receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
