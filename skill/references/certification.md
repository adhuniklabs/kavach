# The Certification - "Certified by Madhav"

The final block of every KAVACH report. It is **conditional and honest**: a real banking
auditor never signs a falling system. Its worth comes entirely from the fact that it can be
withheld. A signature that is always granted certifies nothing.

## The gate decides - not the author

The certification is a pure function of the § production-readiness gate (§6). Do not narrate,
soften, or override it. Render **GRANTED** only when the gate passes; otherwise render
**WITHHELD**. There is no third state and no discretion.

The gate passes only if **all** of these hold:

- **Zero** open Critical findings.
- **Zero** open High findings.
- Every control boolean is `true` (§ finding-schema - unset means unproven means fail-closed):
  - `no_client_reachable_secret`
  - `billing_server_side_enforced`
  - `webhooks_verified_and_idempotent`
  - `authz_on_every_object_and_function`
  - `ai_guardrails_present`
  - `encryption_tls_and_at_rest`
  - `rate_limits_on_expensive_endpoints`
  - `no_debug_or_secret_leak_in_prod`

One open High, or one control that could not be proven true across the whole surface, fails the
gate. No exceptions, no "accepted risk," no author's judgment call.

## GRANTED block - only when the gate passes

Emit verbatim in intent (fill the `<...>` from recon + run metadata):

> **✅ KAVACH CERTIFIED - STATIC SECURITY POSTURE VERIFIED**
> Codebase: `<auto-detected name>` · Commit: `<hash>` · Date: `<date>`
>
> This codebase has passed the KAVACH zero-input adversarial code audit across all applicable
> domains. No Critical or High vulnerabilities remain open at static / code-review level. The
> key-management, billing-integrity, and AI-guardrail controls were each verified by direct code
> inspection, with the enforcing `file:line` cited in the findings above. **Certified by Madhav**
> under the KAVACH standard.
>
> Scope note: this certifies code & architecture. Live penetration testing per § residual-risk
> (§9) is recommended before external production sign-off.

## WITHHELD block - whenever the gate fails

Emit verbatim in intent, listing every Critical/High finding and every unproven control as a
named blocker:

> **⛔ KAVACH CERTIFICATION WITHHELD - NOT PRODUCTION-READY**
>
> Certification cannot be granted. The following ship-blockers must be remediated and re-audited:
>
> - `<KAVACH-### · severity · title · file:line>` for each open Critical and High finding.
> - `<control name>` for each control boolean not proven `true`.
>
> Re-run KAVACH after the fixes land. **Madhav's certification is not issued on a system with
> open critical exposure - that is the entire point of the standard.**

## The law of this block

- Certification is **never** granted while a single Critical or High is open. Ever. (§ persona -
  banned behaviors.)
- Every blocker in the WITHHELD list must name a real finding id or control, each tied to the
  `file:line` recorded in the findings. No vague "harden the app" language.
- Do not hedge the verdict and do not editorialize to reassure the operator. State it plainly.
- **Withholding when warranted is the certification's value.** The signature means something only
  because VAJRA will refuse to sign a system that would fall.
