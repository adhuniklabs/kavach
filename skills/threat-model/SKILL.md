---
name: threat-model
description: KAVACH companion skill for repository-grounded threat modeling - enumerates trust boundaries, assets, attacker capabilities, abuse paths, and mitigations, then writes a concise, evidence-anchored Markdown threat model. Use when the user explicitly asks to threat-model a codebase or path, enumerate threats/abuse paths, or perform AppSec threat modeling as a standalone deliverable. Do not trigger for general architecture summaries, code review, or non-security design work - and do not fold this into a zero-input full KAVACH audit, since it requires a user check-in KAVACH's other domain agents don't.
tools: Read, Grep, Glob, Bash, Write
model: inherit
---

> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Threat Model Source Code Repo

Deliver an actionable AppSec-grade threat model that is specific to the repository or a project
path, not a generic checklist. Anchor every architectural claim to evidence in the repo and keep
assumptions explicit. Prioritize realistic attacker goals and concrete impacts over generic
checklists.

This is a **distinct deliverable** from a full KAVACH audit - it produces a design-review artifact
(trust boundaries, abuse paths, a Mermaid system diagram) rather than a list of confirmed/suspected
vulnerabilities, and it has a **mandatory user check-in** (step 6 below) before the final report is
produced. Do not skip the check-in to make this run zero-input like `kavach`'s main audit modes -
the check-in is exactly what makes the priority ranking trustworthy.

## Quick Start

1) Collect (or infer) inputs:
   - Repo root path and any in-scope paths.
   - Intended usage, deployment model, internet exposure, and auth expectations (if known).
   - Any existing repository summary or architecture spec.
   - **If `.kavach/recon.json` already exists** (this skill is being run against a repo that has
     had a KAVACH recon pass, or inside a broader KAVACH audit), read it first and use it as the
     seed system model instead of re-discovering the stack from scratch: `recon.json`'s
     `frameworks`, `datastores`, `auth`, `llm_providers`, `payment_processors`, `cloud`, and `iac`
     fields answer most of the "Repository summary" prompt's Objective 1 (languages/frameworks/
     components) directly - spend your own reading budget on Objective 2 (entry points, trust
     boundaries, security layers) instead of re-deriving what recon already found.
   - Otherwise, use the prompts in `references/prompt-template.md` to generate a repository summary
     from scratch.
   - Follow the required output contract in `references/prompt-template.md`. Use it verbatim when
     possible.

## Workflow

### 1) Scope and extract the system model

- Identify primary components, data stores, and external integrations from the repo summary (or
  `recon.json` if available).
- Identify how the system runs (server, CLI, library, worker) and its entrypoints.
- Separate runtime behavior from CI/build/dev tooling and from tests/examples.
- Map the in-scope locations to those components and exclude out-of-scope items explicitly.
- Do not claim components, flows, or controls without evidence.

### 2) Derive boundaries, assets, and entry points

- Enumerate trust boundaries as concrete edges between components, noting protocol, auth,
  encryption, validation, and rate limiting.
- List assets that drive risk (data, credentials, models, config, compute resources, audit logs).
- Identify entry points (endpoints, upload surfaces, parsers/decoders, job triggers, admin tooling,
  logging/error sinks).

### 3) Calibrate assets and attacker capabilities

- List the assets that drive risk (credentials, PII, integrity-critical state,
  availability-critical components, build artifacts).
- Describe realistic attacker capabilities based on exposure and intended usage.
- Explicitly note non-capabilities to avoid inflated severity.

### 4) Enumerate threats as abuse paths

- Prefer attacker goals that map to assets and boundaries (exfiltration, privilege escalation,
  integrity compromise, denial of service).
- Classify each threat and tie it to impacted assets.
- Keep the number of threats small but high quality.

### 5) Prioritize with explicit likelihood and impact reasoning

- Use qualitative likelihood and impact (low/medium/high) with short justifications.
- Set overall priority (critical/high/medium/low) using likelihood x impact, adjusted for existing
  controls.
- State which assumptions most influence the ranking.

### 6) Validate service context and assumptions with the user (mandatory pause)

- Summarize key assumptions that materially affect threat ranking or scope, then ask the user to
  confirm or correct them.
- Ask 1-3 targeted questions to resolve missing context (service owner and environment,
  scale/users, deployment model, authn/authz, internet exposure, data sensitivity,
  multi-tenancy).
- **Pause and wait for user feedback before producing the final report.** This is the one place
  this skill is not zero-input, and it is deliberate - a threat model's priority ranking is only as
  good as the deployment-context assumptions underneath it.
- If the user declines or can't answer, state which assumptions remain and how they influence
  priority, then proceed.

### 7) Recommend mitigations and focus paths

- Distinguish existing mitigations (with evidence) from recommended mitigations.
- Tie mitigations to concrete locations (component, boundary, or entry point) and control types
  (authZ checks, input validation, schema enforcement, sandboxing, rate limits, secrets isolation,
  audit logging). See `references/security-controls-and-assets.md` for the control/asset taxonomy
  and mitigation-phrasing patterns.
- Prefer specific implementation hints over generic advice (e.g., "enforce schema at gateway for
  upload payloads" vs "validate inputs").
- Base recommendations on validated user context; if assumptions remain unresolved, mark
  recommendations as conditional.

### 8) Run a quality check before finalizing

- Confirm all discovered entrypoints are covered.
- Confirm each trust boundary is represented in threats.
- Confirm runtime vs CI/dev separation.
- Confirm user clarifications (or explicit non-responses) are reflected.
- Confirm assumptions and open questions are explicit.
- Confirm that the format of the report matches closely the required output format defined in the
  prompt template: `references/prompt-template.md`.
- Write the final Markdown. If the target has a `.kavach/` directory (this skill is running inside
  or alongside a KAVACH audit), write to
  `.kavach/attack-surface/threat-model-<repo-or-dir-name>.md`. Otherwise write
  `<repo-or-dir-name>-threat-model.md` at the repo root (use the basename of the repo root, or the
  in-scope directory if asked to model a subpath).

## Risk prioritization guidance (illustrative, not exhaustive)

- High: pre-auth RCE, auth bypass, cross-tenant access, sensitive data exfiltration, key or token
  theft, model or config integrity compromise, sandbox escape.
- Medium: targeted DoS of critical components, partial data exposure, rate-limit bypass with
  measurable impact, log/metrics poisoning that affects detection.
- Low: low-sensitivity info leaks, noisy DoS with easy mitigation, issues requiring unlikely
  preconditions.

If this deliverable feeds a downstream KAVACH audit's kill-chain analysis, the same four-level
scale (critical/high/medium/low) is compatible with the CVSS-band severity model in
`skill/references/severity-model.md` - a threat ranked "critical" here should be re-scored with an
honest CVSS vector before it's carried into a `findings/` entry; this skill's own output stays
qualitative (likelihood x impact) because it is a design-review artifact, not a proven vulnerability
list, and it deliberately does not claim `confirmed`/`suspected` status per finding - that
distinction only applies once a concrete abuse path here is actually investigated as a finding.

## References

- Output contract and full prompt template: `references/prompt-template.md`
- Control/asset taxonomy: `references/security-controls-and-assets.md`

Only load the reference files you need. Keep the final result concise, grounded, and reviewable.
