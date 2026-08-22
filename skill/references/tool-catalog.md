# Tool Catalog - deterministic scanners by technology

Phase 1 (`kavach sweep`) reads `recon.json` and runs only the scanners whose `applies()` matches
the detected stack. Docker-first: each tool runs from its pinned image (nothing to install); if
the image can't run, a native binary is tried; if neither, the scanner is marked **unavailable**
and its domain subagent does deeper manual review at lower confidence. You do not run these by
hand - the core does. This table is the map so you know what evidence to expect and what's missing.

## Always-on (every target)

| Scanner | Catches | Runner | Network |
|---|---|---|---|
| `builtin-secrets` | Provider/payment/DB keys, private keys, creds-in-URL | pure Python (no deps) | none |
| `gitleaks` | Broader committed-secret ruleset | docker `zricethezav/gitleaks` → native | none |
| `trufflehog` | **Verified** secrets - validates the key is *live* → confirmed key theft | docker `trufflesecurity/trufflehog` → native | default (verify; detects offline) |
| `trivy` (fs) | Dependency CVEs · secrets · IaC misconfig | docker `aquasec/trivy` → native | default (DB pull) |

`builtin-secrets` is the guaranteed floor for the key-theft nightmare - it runs even with zero
Docker/tooling. gitleaks + trivy widen the net; trufflehog **verifies** hits (a verified secret is
`confirmed` + Critical; unverified is `suspected` + High).

## By language / stack

| Condition (from recon) | Scanner | Catches | Image |
|---|---|---|---|
| any language | `semgrep` | Multi-language SAST (injection, XSS, SSRF, …). Runs KAVACH's **bundled offline ruleset** (never a silent zero) + `--config auto`; falls back to offline-only if the registry is unreachable. | `semgrep/semgrep` (native fallback) |
| Python | `bandit` | Python SAST | native `bandit` (no reliable image) |
| Python + reqs | `pip-audit` | Python dependency CVEs | native `pip-audit` |
| **Go** | `gosec` | **Go SAST** (SSRF, injection, weak crypto, hardcoded creds) | `ghcr.io/securego/gosec` → native |
| Node + lockfile | `npm-audit` | Node dependency CVEs | native `npm` |
| any lockfile | `osv-scanner` | Cross-ecosystem lockfile CVEs | `ghcr.io/google/osv-scanner` |
| **pip/npm manifest** | `guarddog` | **Malicious dependencies** - install-script exfil, typosquats, obfuscation (NOT just CVEs) | `ghcr.io/datadog/guarddog` → native · needs network |
| IaC / Dockerfile / compose | `checkov` | IaC misconfiguration | `bridgecrew/checkov` (native fallback) |
| IaC / Dockerfile / compose | `kics` | **Broader IaC** (Terraform, K8s, Ansible, Helm, OpenAPI, CDK) | `checkmarx/kics` |
| Dockerfile present | `hadolint` | Dockerfile hardening | `hadolint/hadolint` (native fallback) |

**Malware note:** `guarddog` is the supply-chain *malware* layer - the CVE scanners
(trivy/pip-audit/npm-audit/osv) find *known-vulnerable* packages, not *malicious* ones. A guarddog
hit with an exfiltration/backdoor/code-execution rule is a Critical key-theft kill-chain step.

## Semgrep ruleset selection (adapts piolium's semgrep third-party-ruleset reference)

The generic `semgrep` row above (bundled offline ruleset + `--config auto`) is the fail-safe floor.
When the registry *is* reachable, the domain subagent's `semgrep` pass should be widened with the
rulesets below, selected from `recon.json`'s detected languages/frameworks - this is what
"`--config auto`" is standing in for when network is unavailable.

**Baseline (always, regardless of language):** `p/security-audit` (comprehensive, higher-FP -
manual-review grade, which is what a subagent is doing) + `p/secrets` (hardcoded creds/keys/tokens
- overlaps `gitleaks`/`trufflehog`, redundancy here is intentional).

**Primary + framework ruleset per detected language:**

| Language | Primary | Framework rulesets (if detected) |
|---|---|---|
| Python | `p/python` | `p/django`, `p/flask`, `p/fastapi` |
| JS/JSX | `p/javascript` | `p/react`, `p/nodejs`, `p/express`, `p/nextjs`, `p/angular` |
| TS/TSX | `p/typescript` | `p/react`, `p/nodejs`, `p/express`, `p/nextjs`, `p/angular` |
| Go | `p/golang` | - |
| Java | `p/java` | `p/spring`, `p/findsecbugs` |
| Kotlin | `p/kotlin` | `p/spring` |
| Ruby | `p/ruby` | `p/rails` |
| PHP | `p/php` | `p/symfony`, `p/laravel`, `p/phpcs-security-audit` |
| C/C++ | `p/c` | - |
| Rust | `p/rust` | - |
| C# | `p/csharp` | - |
| Swift | `p/swift` | - |
| Solidity | no official ruleset | see third-party table below |

**Infra rulesets:** Dockerfile → `p/dockerfile` (in addition to `hadolint`); `.tf`/`.hcl` →
`p/terraform`; k8s manifests → `p/kubernetes`; CloudFormation → `p/cloudformation`; GitHub Actions
workflows → `p/github-actions`; generic `.yaml`/`.yml` → `p/yaml`; AWS IAM JSON → `r/json.aws`.

**Third-party rulesets - NOT optional.** Include automatically whenever the matching language is
present; these catch patterns the official registry rules miss:

| Languages | Source | Why mandatory |
|---|---|---|
| Python, Go, Ruby, JS/TS, Terraform, HCL | Trail of Bits (`trailofbits/semgrep-rules`) | Security-audit patterns from real engagements |
| C, C++ | 0xdea (`0xdea/semgrep-rules`) | Memory-safety, low-level vulnerabilities |
| Solidity, Cairo, Rust | Decurity (`Decurity/semgrep-smart-contracts`) | Smart-contract/DeFi exploit patterns - the only real coverage for Solidity, which has no official ruleset |
| Go | dgryski (`dgryski/semgrep-go`) | Additional Go-specific patterns |
| Android (Java/Kotlin) | MindedSecurity (`mindedsecurity/semgrep-rules-android-security`) | OWASP MASTG-derived mobile rules |
| Java, Go, JS/TS, C#, Python, PHP | elttam (`elttam/semgrep-rules`) | Security-consulting patterns |
| Dockerfile, PHP, Go, Java | kondukto (`kondukto-io/semgrep-rules`) | Container + web-app security |
| PHP, Kotlin, Java | dotta (`federicodotta/semgrep-rules`) | Pentest-derived web/mobile rules |
| Terraform, HCL | HashiCorp (`hashicorp-forge/semgrep-rules`) | HashiCorp infra patterns |
| Swift, Java, Cobol | akabe1 (`akabe1/akabe1-semgrep-rules`) | iOS + legacy-system patterns |
| Java | Atlassian Labs (`atlassian-labs/atlassian-sast-ruleset`) | Atlassian-maintained Java rules |
| Python, JS/TS, Java, Ruby, Go, PHP | Apiiro (`apiiro/malicious-code-ruleset`) | Malicious-code/supply-chain detection - cross-links with `guarddog` above |

A finding produced only by a third-party ruleset is still a scanner *lead*, not a verdict - the
domain subagent confirms or refutes it against the actual code exactly like any other scanner hit
(`severity-model.md`, `persona.md`). When the registry is unreachable and only the bundled offline
ruleset ran, note that in `sweep-summary.json` so the reconciler knows third-party coverage was
skipped for this run, not silently absent.

## CVE honesty

`trivy`, `pip-audit`, `npm-audit`, and `osv-scanner` return **real, current CVE ids**. Subagents
cite those ids. Never invent a CVE number for anything a scanner did not report - flag the risk
and say "verify against current advisories" instead (persona banned behavior).

## Reading the sweep summary

`sweep-summary.json` lists each scanner's status (`ok` / `unavailable` / `error`), runner, and
finding count. When a scanner is `unavailable`, the matching domain subagent is told to review
that surface manually and mark findings `suspected` unless it reads the proving line.

## Adding a scanner (extending the core)

One file in `core/kavach/scanners/`: subclass `Scanner`, declare `applies(recon)`, the Docker
`image` / `native_binary`, `docker_args`, and a `normalize()` that maps raw output → canonical
`Finding`s. Register it in `scanners/__init__.py`. No other code changes.
