# Severity Model & Scoring - how to score a finding

Load this whenever you assign `severity`, `cvss_score`, or `cvss_vector` in a finding (see
`finding-schema.md`). The rule is simple: **the CVSS base score decides the band - you do not
pick the band by feel.** Compute the vector, read the score off the calculator logic below, map
it to the band. Never inflate to alarm, never soften to reassure - calibration is the whole point
of VAJRA's signature (`persona.md`).

## Every finding MUST carry (non-negotiable)

- [ ] `cvss_vector` - a full CVSS v3.1 base vector string (all 8 metrics). Empty `""` **only** for INFO.
- [ ] `cvss_score` - the base score that vector produces, `0.1`-`10.0`. `0.0` **only** for INFO.
- [ ] `severity` - the band the score falls in (table below). Must match the score, always.
- [ ] Likelihood × Impact - one line: how likely to be hit × what it costs if hit.
- [ ] `exploitability` - `trivial` | `moderate` | `hard` (how much attacker skill/conditions the leaf needs).
- [ ] `confidence` - `confirmed` (you read the line that proves it) | `suspected` (needs runtime/DAST).
      When `suspected`, name the exact runtime test that would confirm it.

If any of these is missing, the finding is not done. Do not emit it.

## The band table (CVSS v3.1 → meaning for THIS system)

| Band | CVSS | Meaning for THIS system |
|---|---|---|
| **CRITICAL** | 9.0-10.0 | Direct key/LLM-key theft, free-chatbot/billing bypass, mass data or multi-tenant exposure, RCE, full auth bypass. **Ship-blocker.** |
| **HIGH** | 7.0-8.9 | Serious exploit needing minor conditions: privilege escalation, single-tenant sensitive leak, IDOR on one object class, system-prompt leak exposing business logic. **Ship-blocker.** |
| **MEDIUM** | 4.0-6.9 | Exploitable with real effort or bounded impact; hardening gaps with a plausible attack path. |
| **LOW** | 0.1-3.9 | Minor / edge-condition / defense-in-depth only; no direct path to the operator's nightmares. |
| **INFO** | 0.0 | Observation or best-practice note, no direct risk. Vector may be `""`, score `0.0`. |

Sanity check against the kill chains: if a finding is a leaf on `steal-keys`, `free-chatbot`,
`bypass-billing`, `mint-tokens`, `read-others-data`, or `hijack-ai` **with no blocking control**,
it is Critical regardless of how "unlikely" it feels. The vector should reflect that - if it
scores lower, your metrics are wrong, re-examine C/I/A and Scope.

## CVSS v3.1 vector cheat-sheet (build a real vector, don't guess)

Format: `CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?` - all 8 base metrics, in this order.

| Metric | Values | Pick the higher-severity value when… |
|---|---|---|
| **AV** Attack Vector | `N` network · `A` adjacent · `L` local · `P` physical | Reachable over the internet/API → `N`. |
| **AC** Attack Complexity | `L` low · `H` high | No special conditions/timing/config needed → `L`. |
| **PR** Privileges Required | `N` none · `L` low · `H` high | Unauthenticated endpoint → `N`; any logged-in user → `L`; admin only → `H`. |
| **UI** User Interaction | `N` none · `R` required | Attacker acts alone (no victim click) → `N`. |
| **S** Scope | `U` unchanged · `C` changed | Impact crosses a trust/security boundary (one tenant → others, app → host, sandbox escape) → `C`. |
| **C** Confidentiality | `N` none · `L` low · `H` high | Keys/PII/prompts/other tenants' data fully disclosed → `H`. |
| **I** Integrity | `N` none · `L` low · `H` high | Attacker can alter balances, plans, entitlements, records → `H`. |
| **A** Availability | `N` none · `L` low · `H` high | Can take the service/endpoint down or exhaust the operator's spend → `H`. |

Reference anchors (calibrate against these, don't reinvent):

- **Client-controlled price honored / free billing bypass** → `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` ≈ **9.1 Critical**.
- **LLM/provider key exposed to the browser** → `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` ≈ **10.0 Critical**.
- **IDOR reading another user's data (auth'd)** → `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` ≈ **6.5 Medium**; make it `S:C` if it crosses tenants → **7.7 High**.
- **Unauthenticated /api/chat proxy (free chatbot, runaway spend)** → `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H` ≈ **8.2 High**.
- **Missing webhook signature verification (forge payment success)** → `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` ≈ **7.5 High**.
- **Verbose stack traces / debug leak** → `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` ≈ **5.3 Medium** (often Low if bounded).

### Rough score-band intuition (to catch a mistyped vector, not to replace the vector)

- Network + low complexity + no privileges + high on two or more of C/I/A → lands **9.0+ Critical**.
- One of PR:L or a single high impact → typically **7.x-8.x High**.
- Bounded single impact, some privilege or complexity → **4.x-6.x Medium**.
- Requires local access, heavy conditions, or only marginal impact → **Low**.

If your typed score and this intuition disagree by a whole band, you mis-set a metric - fix the
vector, then re-read the band off the table. The score is the source of truth; the label follows it.

## Severity chaining - score a primitive by the chain it enables

A finding that looks minor in isolation but is a **step in a kill chain** is scored by the impact
of the *chain outcome*, not the primitive. Score the leaf, then ask: "what does this unlock, and is
that unlock also unblocked?" If the chain reaches a high-impact goal with no blocking control, the
finding inherits that severity.

- Example (from a real run): an endpoint that **reflects the raw `Cookie`/`Authorization` header**
  into its response body reads like an info leak (Low). But it **defeats `httpOnly`** - any XSS then
  exfiltrates the session token → account takeover. Score it **High**, not Low, and record the chain
  in `how_exploited` + set `kill_chain`.
- A commented-out auth check on a route that only reads "public" data is Low **until** you notice the
  same route also writes, or leaks a `user_id` that feeds an IDOR elsewhere - then it is the first
  leaf of a cross-tenant chain and scores by that.

Rule: **do not score leaves in isolation when they compose.** During reconciliation, walk each
finding into the attack trees (`attack-trees.md`); if it advances a chain whose goal is EXPLOITABLE,
raise its severity to match and cross-link it. Under-scoring a chain primitive is the calibration
error that lets a "Low" hide a Critical path.

## Confirmed vs. suspected (never blur them)

- **confirmed** - you read the exact line that proves the flaw exists AND that no cited control
  blocks it. Cite the `file:line` in `locations`.
- **suspected** - the pattern is present but you could not prove exploitability from static code
  (e.g. authz enforced by runtime middleware you can't trace, or a race that needs load to trigger).
  Mark `suspected` and state the one runtime/DAST test that would confirm it. Do not upgrade a
  suspected finding to confirmed to make it look stronger.

Do not use hedging ("might / possibly / in some cases") to dodge a call. Make the determination,
set `confidence`, and name the test. That is the discipline the signature depends on.

## Gate review before you emit a finding (adapts piolium's fp-check gate-review model)

A finding does not get written to `agent-<domain>.json` until it clears all six gates below. This
is orthogonal to `confidence` (confirmed/suspected is about whether you read the proving line;
these gates are about whether the thing is real and worth reporting at all). Run them in order;
the first gate that fails kills the finding - drop it, do not soften it to Low and keep it.

| Gate | Criterion | Fail looks like |
|---|---|---|
| **1. Process** | You actually read the sink, the caller chain, and the surrounding controls - not just the scanner hit | You are pattern-matching a rule name, not the code |
| **2. Reachability** | Attacker-controlled input reaches the sink, and you can name the path | "Looks reachable" with no traced call chain |
| **3. Real impact** | Exploitation yields a concrete security effect (data disclosure, integrity loss, availability loss, privilege gain) | Only a robustness/style complaint dressed as a vuln |
| **4. PoC validation** | A PoC (pseudocode, script, or the exact request/payload) demonstrates control → trigger → impact | PoC does not actually reach the sink or is hand-waved |
| **5. Math/logic bounds** | Where the flaw is a bound/overflow/off-by-one/race window, work the algebra or the interleaving and show the vulnerable state is reachable | You asserted "could overflow" without checking the actual bounds/validation |
| **6. Environment** | No control you can cite (framework auto-escaping, ORM parameterization, middleware, sandbox, network segmentation) fully blocks it | You didn't check for an upstream/framework control before flagging |

Verdict is binary and file-scoped, not a new severity axis: **emit** (all six pass - proceed to score
it per the band table above) or **drop as false positive**, citing the first gate that failed and
why, e.g. `DROP - Gate 5 (math bounds) fails: validation at auth.py:88 ensures amount > 0, the
underflow this finding claims is not reachable.` A dropped finding is not "Low severity" - it does
not exist. Do not carry it into `findings.json` at any severity.

Note on `confirm_status`: the `confirm_status` field in a promoted finding's `metadata.json`
(`unconfirmed` → `confirmed-live` etc., set only under the live-validation charter in `persona.md`)
is orthogonal bookkeeping about whether a *runtime* reproduction has since happened. It never
substitutes for, or gets blended into, `severity`/`cvss_score` - those stay CVSS-vector-derived.

## Audit triage calibration (adapts piolium's audit triage-and-prereqs calibration)

Use this to sanity-check severity and confidence before you set the CVSS metrics, not instead of
computing the vector. The vector is still the source of truth; this section catches the common
ways a model over- or under-calls a finding.

**Default-low principle.** When you are not yet sure, start your working assumption at MEDIUM and
require evidence to move it. Do not anchor on CRITICAL because the pattern "looks scary."

**Upgrade signals** (need evidence, not vibes) - move toward HIGH when all three hold: remotely
triggerable with no physical/local access; crosses a real trust boundary (user→admin, tenant→
tenant, unauth→authed); no material precondition beyond the attacker's starting position. Move
toward CRITICAL when, in addition: it reaches RCE, full auth bypass, or mass data exfiltration, and
is reachable by any unauthenticated or low-privilege actor on an internet-facing surface. These map
directly onto the AV/PR/S metrics in the vector - if you believe the signals but the vector doesn't
score that high, you mis-set a metric, not the other way round.

**Downgrade signals** - any of these should pull your metrics down (higher AC, PR, or lower C/I/A),
and should show up in your `exploitability` call:
- requires local machine access or physical proximity → `AV:L`/`AV:P`, not `AV:N`
- requires admin/operator privilege to trigger → `PR:H`
- requires a non-default configuration to be vulnerable → raise `AC` or note it explicitly in `how_exploited`
- impact confined to the attacker's own session/data → not a real finding at all (see prerequisite rules below)
- DoS-only with no confidentiality/integrity impact → `A` only, `C:N/I:N`
- requires chaining several individually-inert issues → score each leaf honestly; only the chain (see
  "Severity chaining" above) inherits the higher number, not each primitive in isolation
- a theoretical crypto weakness with no practical exploitation path → note it as INFO/Low with the
  gap named, not inflated to alarm

**Prerequisite minimums.** Every finding states, explicitly: the attacker's starting position, the
capabilities that position already has, the trust boundary it crosses, and the concrete thing the
attacker gains. If you cannot fill in all four, you do not have a finding yet - keep tracing.

**Invalid-by-precondition.** Do not report a finding whose only prerequisite is that the attacker
already has one of: write access to the app's config/data files, control over CI/CD or deploy
infra, control over runtime environment variables, or ownership of unrelated external
infrastructure as the sole enabling step. Those preconditions mean the environment is already
compromised - the "finding" isn't adding attack surface. Escalate only if the codebase itself gives
a realistic path *to* that prerequisite (then the path-to-precondition is the finding).

**Token/secret-possession claims.** "Whoever holds this token/secret can do X" is not a finding by
itself - every secret grants access to whoever holds it. Report it only when you can also name a
feasible *acquisition* path: exfiltration via XSS/injection, leakage into logs/URLs/telemetry/
third-party endpoints, or a misconfiguration that exposes the material. Cite both halves.

**Noise filters** - deprioritize (usually to Low/INFO, or drop) unless chained into concrete
impact: CORS weakness with no data exposure or state change; missing rate limiting with no abuse
chain; enumeration with no takeover/sensitive-data access; verbose errors with no sensitive
disclosure; a bare scanner hit with no source-to-sink trace of your own.

**Claude-specific false-positive patterns** - check every finding against these before you finalize
`confidence`:
1. Flagging a dangerous sink without tracing that attacker input actually reaches it.
2. Claiming validation is "missing" when it lives in a helper/middleware/parent caller you didn't
   read.
3. Missing framework-level protection: ORM parameterization, template auto-escaping, CSRF
   middleware, etc.
4. Treating same-origin/same-session interaction as if it crossed a trust boundary.
5. Reporting a dependency CVE without confirming the vulnerable function is reachable with
   attacker-controlled input.
6. Treating an insecure *default* config as the finding when every realistic deployment overrides
   it, or when changing it requires admin access anyway.
7. Flagging test fixtures, doc examples, or dev-only scripts that never ship to production.
8. Double-counting one root cause as multiple findings under different surface symptoms - one root
   cause, one finding (cross-link it into every kill chain it touches instead).

If a finding matches one of these eight and you don't have independent evidence ruling the pattern
out, it fails Gate 1 or Gate 2 above - drop it or fix the trace, don't ship it as-is.
