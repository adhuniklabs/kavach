# Tool Landscape - verified OSS security tools for KAVACH (2025-2026)

Curated from a verified research pass. Use this to (a) know what the deterministic layer covers,
(b) decide what to integrate next, and (c) let the LLM/supply subagents **recommend** the right
runtime defenses as remediations. Only tools confirmed maintained + open-source + machine-readable
output are listed; rejected/unmaintained ones are named so we don't re-litigate them.

## Integrated in the core

gitleaks · **trufflehog** (verified secrets) · builtin-secrets · trivy · semgrep · bandit ·
**gosec** (Go) · pip-audit · npm-audit · osv-scanner · **guarddog** (malicious deps) · checkov ·
**kics** (broad IaC) · hadolint. See `tool-catalog.md` for the routing.

## Recommended next (clean fit, not yet wired)

| Tool | Adds | Image / install | Feeds | Effort | Flag |
|---|---|---|---|---|---|
| **OWASP dep-scan** | Dependency-confusion + reachability + SBOM/VEX; offline | `ghcr.io/owasp-dep-scan/dep-scan` · `pip install owasp-depscan` | supply | LOW | - |
| **cisco mcp-scanner** | MCP tool-poisoning / agent-security, static JSON mode | `uv tool install cisco-ai-mcp-scanner` / docker | llm, config | MED | keys optional |
| **Dockle** | Container **image** CIS + secrets-in-layers (needs a built image) | `goodwithtech/dockle` | config | LOW | - |
| **Grype + Syft** | 2nd-opinion CVE engine + SBOM (SPDX/CycloneDX) | `anchore/grype`, `anchore/syft` | supply | LOW | redundant w/ trivy |
| **Bearer** | SSRF + PII/sensitive-data flow across 6 languages | `bearer/bearer` | sast, api, crypto | LOW-MED | **Elastic License 2.0** |
| **opengrep + semgrep `/ai` rules** | Prompt-injection, LLM keys, MCP rules, SARIF | `opengrep` binary + `semgrep/semgrep-rules` `/ai` | llm | LOW | see license flags |

## Runtime-only - KAVACH RECOMMENDS these, does NOT run them

These need a **live model endpoint or run inside the app**, so they can't scan a checked-out repo.
When the LLM/config subagents find an unguarded AI surface, recommend the fitting one as a
remediation (name it in the finding's `remediation`), and never claim KAVACH "ran" it.

- **garak** (NVIDIA) - LLM vulnerability/red-team probing of a live model. Active.
- **PyRIT** (Microsoft) - AI red-teaming framework; needs a live endpoint. Active.
- **NeMo Guardrails** (NVIDIA), **Guardrails AI** - runtime output/input rails for the app to adopt.
- **Snyk Agent Scan** (ex-Invariant `mcp-scan`) - launches the live MCP server; paid token.
- Cloud/cluster posture (**Prowler**, **ScoutSuite**, **kube-bench**, **kube-hunter**) - need a live
  cloud account / running cluster; belong to the DAST/live-audit phase KAVACH's report flags as
  out-of-scope for static analysis.

Dead / archived (do not use): **rebuff** (archived 2025), **llm-guard** (archived 2026),
**packj**, **dodgy**, **terrascan** (archived 2025), **tfsec** (folding into trivy), **Horusec**.

## License flags before shipping KAVACH as a commercial product

Running these tools via Docker and consuming their output is fine; the flags matter for
**redistributing their code** or **offering KAVACH as a hosted SaaS over customer code**:

- **CodeQL** - CLI license forbids automated/CI analysis of non-OSS code without paid GitHub
  Advanced Security. **Do not integrate** for commercial/automated scanning. (Excellent for SSRF/
  IDOR taint if you gate it to "OSS repos only / user brings GHAS".)
- **Semgrep Rules License v1.0** - the `/ai` and `owasp-top-ten` **rules** are source-available, not
  OSI. The opengrep/semgrep **engine** is fine (LGPL-2.1); review before bundling the rules.
- **Bearer** - Elastic License 2.0 (no hosted-service resale without approval).
- **trufflehog**, **vulnhuntr** - AGPL-3.0 (we invoke trufflehog as a container, not bundle its
  source, so KAVACH's own license is unaffected; note it if you ever vendor the code).
- **brakeman** - ambiguous "free for non-commercial" wording; verify before commercial bundling.

## Coverage gaps that stay with the subagents (no tool does them well)

IDOR/BOLA, billing-bypass, and business-logic abuse have **no reliable off-the-shelf detector** -
they need code-flow reasoning. That is exactly why `kavach-api`, `kavach-billing`, and `kavach-logic`
exist: the tools seed them; the judgment is theirs.
