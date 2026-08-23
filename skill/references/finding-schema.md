# Finding Schema - the subagent input/output contract

Every domain subagent reads the same evidence and emits the same JSON shape. This forced
structure is what makes weaker models reliable: they fill fields, they don't free-write.

## What a subagent receives

1. `recon.json` - the stack dossier (languages, frameworks, datastores, auth, LLM providers,
   payment processors, cloud, IaC, capabilities).
2. Its **slice of `findings.json`** - the deterministic scanner hits in its domain (confirm or
   refute each; a scanner hit is a lead, not a verdict).
3. The **scoped file list** its domain reference tells it to read (e.g. AGENT-API reads every
   route/controller; AGENT-BILLING reads every webhook/checkout/credit path).
4. The list of **unavailable scanners** - for those, the subagent does deeper manual review and
   marks findings `suspected` unless it reads the proving line.

## What a subagent emits

A JSON file `agent-<domain>.json` (e.g. `agent-billing.json`) in the `.kavach` dir:

```json
{
  "domain": "billing",
  "controls": { "billing_server_side_enforced": true, "webhooks_verified_and_idempotent": false },
  "findings": [
    {
      "title": "Client-controlled price honored at checkout",
      "severity": "critical",
      "category": "Billing-Bypass",
      "source": "kavach-billing",
      "confidence": "confirmed",
      "cvss_score": 9.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
      "rule_id": "OWASP-API3",
      "locations": [{ "file": "src/api/checkout.js", "line": 42, "snippet": "amount: req.body.price" }],
      "what_it_is": "The server charges req.body.price without recomputing from its own catalog.",
      "how_exploited": "POST /api/checkout with price=1 buys any plan for one cent.",
      "business_impact": "Direct revenue loss; any plan/add-on obtainable for near-zero.",
      "remediation": "Look up the price server-side by plan id; ignore any client amount. <diff>",
      "fix_impact": "Client price becomes advisory only; no client can set the charge.",
      "effort": "S",
      "references": ["OWASP-API3", "CWE-840"],
      "kill_chain": "bypass-billing"
    }
  ]
}
```

### Field rules

- **severity**: `critical | high | medium | low | info` - from CVSS band (§ severity-model). Never inflate/deflate.
- **source**: your own agent name (`kavach-sast`, `kavach-billing`, …). This is what marks the
  finding as reasoned rather than scanner output, and only reasoned findings are promotable.
  Omit it and the engine attributes it to your dispatch for you - but say it.
- **confidence**: `confirmed` only if you read the enforcing/violating line. Else `suspected`.
- **category**: OWASP/CWE tag (`A01`, `API1:BOLA`, `LLM01`, `Billing-Bypass`, `A07:Secrets`, …).
- **locations**: at least one `{file, line}`. `file` is repo-relative. Cite every location.
- **cvss_score/vector**: compute honestly; leave `0.0`/`""` only for INFO.
- **remediation**: copy-pasteable fix for *this* codebase (show the diff), not generic advice.
- **kill_chain** (optional): one of `steal-keys`, `free-chatbot`, `bypass-billing`, `mint-tokens`,
  `read-others-data`, `hijack-ai` when the finding is a step in that attack tree.

**Fields not on this list are dropped.** The schema is the whole contract - an extra key you
invented (`exploitability`, `classification`, `control_status`) is discarded on ingest, so
whatever you put there is simply lost. Put it in `what_it_is` or `how_exploited` instead.

## Control booleans (feed the production-readiness gate)

Each subagent sets the controls it can judge; the reconciler merges them into `controls.json`
which `kavach gate`/`kavach render` consume. Unset = unproven = fail-closed.

| Control | Owner domain |
|---|---|
| `no_client_reachable_secret` | sast (secrets) |
| `billing_server_side_enforced` | billing |
| `webhooks_verified_and_idempotent` | billing / supply |
| `authz_on_every_object_and_function` | api |
| `ai_guardrails_present` | llm |
| `encryption_tls_and_at_rest` | crypto |
| `rate_limits_on_expensive_endpoints` | api / llm |
| `no_debug_or_secret_leak_in_prod` | config |

A control is `true` only when you cite the line that enforces it across the whole surface - one
unprotected route means the control is `false`.

## Draft frontmatter (`findings-draft/<prefix>-NNN-<slug>.md`)

Before a finding is merged and consolidated, each subagent's raw findings also get written one-per-
file as a transient draft (`findings-draft/`, cleaned up at the end of the run). The draft file is
plain YAML frontmatter over a short human-readable body - not the full schema above, just enough to
route and dedupe it:

```yaml
---
id: sast-003          # <prefix>-<NNN>, prefix = phase/domain lowercased, NNN zero-padded per-phase counter
phase: sast           # the domain/phase that produced it (sast, billing, api, llm, crypto, …)
slug: client-controlled-price-honored-at-checkout   # slugify(title), lowercase-hyphenated, ≤50 chars
severity: critical    # critical | high | medium | low | info - same values as the full schema
confidence: confirmed # confirmed | suspected - same discipline as the full schema
kavach_id: KAVACH-a1b2c3d4e5   # finding.fingerprint() - stable across runs, line-independent
---

# Client-controlled price honored at checkout

<what_it_is, one paragraph>
```

`id` is a per-run label (renumbers if phases re-run); `kavach_id` is the stable identity carried
through to `metadata.json` after promotion (see `report-template.md` §6) - always set both, never
substitute one for the other. `write_draft` produces exactly these six fields; do not add ad-hoc
keys to the draft frontmatter - extra detail belongs in the body or in the full JSON finding.

## `match_type` (adapts piolium's spec-to-code-compliance alignment taxonomy)

When a subagent is doing spec-vs-code alignment (RFC/framework-contract conformance, documented
invariant vs. implementation, whitepaper vs. contract - the `kavach-spec` playbook) rather than
plain vulnerability hunting, each spec requirement it checks against the code gets exactly one
`match_type`, in addition to (never instead of) the normal `severity`/`confidence` fields:

| `match_type` | Meaning | Finding action |
|---|---|---|
| `full_match` | Code implements the spec requirement faithfully | No finding. |
| `partial_match` | Code implements part of the requirement; some condition/edge case is unhandled | Finding at the severity the gap's impact justifies. |
| `mismatch` | Code does something different from what the spec requires | Finding - the gap is the vulnerability. |
| `missing_in_code` | Spec requires it; nothing in the code implements it | Finding - usually the most severe of the four, since there is zero control. |
| `code_stronger_than_spec` | Code enforces more than the spec requires (extra check, tighter bound) | No finding; note it in `attack-surface/spec-gap-summary.md` as an observation, not a gap. |
| `code_weaker_than_spec` | Code enforces the requirement but with a materially weaker bound/condition than specified | Finding - score by how much weaker (e.g. spec says 1% max slippage, code allows 5%). |

`mismatch`, `missing_in_code`, `partial_match`, and `code_weaker_than_spec` are the four that
produce a normal finding object (full schema above) - `match_type` rides alongside `category` as
extra metadata on that finding, it does not replace `severity` or `confidence` and it is never a
second severity axis. Every `match_type` call carries a one-line `reasoning` citing the exact spec
excerpt (section/page) and the exact code location - never infer or guess; if the spec is silent on
a point, that is `missing_in_code` only if the spec's surrounding language implies the behavior is
mandatory, otherwise don't force a call - flag the ambiguity instead and drop `confidence` below the
threshold that would let it ship as `confirmed`.
