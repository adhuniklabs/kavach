# Attack Trees - the six kill chains

VAJRA thinks in kill chains, not checklists (persona.md). These are the six named nightmares,
each drawn as a tree: **root goal → branches → leaf techniques**.
Every leaf carries a verdict:

- **EXPLOITABLE** - a subagent confirmed a path with no blocking control. Cite the finding.
- **BLOCKED** - a control stops this leaf. Cite the exact `file:line` that enforces it (prove it
  or flag it - a leaf is never BLOCKED on faith).
- **UNKNOWN-needs-runtime** - cannot be settled by static review; name the DAST/runtime test.

## The zero-blocking-control rule

**A root goal reachable through even one branch whose leaves are all EXPLOITABLE or
UNKNOWN - i.e. with zero BLOCKING control on that path - is automatically Critical**, regardless
of how "unlikely" it seems. Attackers specialize in the unlikely. A single fully-blocked path
does not save the goal if another path is open. The goal is only safe when *every* branch that
reaches it has at least one BLOCKED leaf on it.

## How these map to the schema and who fills them

- Each leaf that a subagent proves EXPLOITABLE becomes a finding whose **`kill_chain`** field
  (finding-schema.md) is set to that tree's id: `steal-keys`, `free-chatbot`, `bypass-billing`,
  `mint-tokens`, `read-others-data`, `hijack-ai`.
- Subagents do **not** own the trees - they emit atomic findings tagged with `kill_chain`. The
  **reconciler** (VAJRA lead, Phase 2) fills each tree from those findings: it drops each finding
  onto its leaf, marks that leaf EXPLOITABLE, marks leaves covered by a cited control BLOCKED, and
  leaves the rest UNKNOWN-needs-runtime. It then applies the zero-blocking-control rule to score
  the root and cross-correlates (a SAST leaf that feeds a billing leaf is ONE chain, not two).
- The control booleans in finding-schema (`no_client_reachable_secret`,
  `billing_server_side_enforced`, `authz_on_every_object_and_function`, `ai_guardrails_present`,
  …) are the evidence a leaf is BLOCKED. An unset/false boolean = that leaf stays open.

Leaf verdicts below ship as `UNKNOWN-needs-runtime` templates; the reconciler overwrites them.

---

## 1. steal-keys - steal & reuse the operator's API/LLM keys
- Extract key from client-reachable surface
  - Key hardcoded in frontend bundle / mobile binary - `[UNKNOWN-needs-runtime]`
  - Key in git-tracked `.env`, config, or CI log - `[UNKNOWN-needs-runtime]`
  - Client calls LLM/payment provider directly with real key - `[UNKNOWN-needs-runtime]`
- Extract key from server
  - Secret in source/Dockerfile/IaC layer instead of vault - `[UNKNOWN-needs-runtime]`
  - SSRF to cloud metadata `169.254.169.254` yields role creds - `[UNKNOWN-needs-runtime]`
  - Verbose error / debug page leaks env - `[UNKNOWN-needs-runtime]`
- Coax key out at runtime
  - System-prompt / tool config leak reveals embedded key - `[UNKNOWN-needs-runtime]`
  - Log/trace writes the key in plaintext - `[UNKNOWN-needs-runtime]`
- *Blocking controls: `no_client_reachable_secret`, `no_debug_or_secret_leak_in_prod`.*

## 2. free-chatbot - run the operator's paid chatbot for free, at scale
- Reach the LLM proxy without paying
  - `/api/chat` (or equiv) reachable unauthenticated - `[UNKNOWN-needs-runtime]`
  - Auth present but no per-identity quota / rate limit - `[UNKNOWN-needs-runtime]`
  - No output/token cap → runaway spend per call - `[UNKNOWN-needs-runtime]`
- Amplify volume
  - No payload-size / prompt-length cap - `[UNKNOWN-needs-runtime]`
  - Recursive/agentic loop unbounded - `[UNKNOWN-needs-runtime]`
  - Multi-account / trial farming to multiply free calls - `[UNKNOWN-needs-runtime]`
- *Blocking controls: `authz_on_every_object_and_function`, `rate_limits_on_expensive_endpoints`.*

## 3. bypass-billing - obtain any plan or add-on without paying
- Tamper the money on the wire
  - Server honors client-sent `price` / `amount` / `currency` - `[UNKNOWN-needs-runtime]`
  - Mass assignment sets `plan` / `is_premium` / `credits` on a model - `[UNKNOWN-needs-runtime]`
  - Numeric abuse: negative qty, zero/blank, overflow, rounding skim - `[UNKNOWN-needs-runtime]`
- Forge or replay the payment signal
  - Webhook signature not verified with secret - `[UNKNOWN-needs-runtime]`
  - Client "success" redirect trusted without re-fetch from processor - `[UNKNOWN-needs-runtime]`
  - Replayed webhook double-credits (non-idempotent) - `[UNKNOWN-needs-runtime]`
- Abuse entitlement logic
  - Privileged-looking but unauthenticated entitlement endpoint (BFLA) - `[UNKNOWN-needs-runtime]`
  - IDOR attaches someone else's paid plan to your account - `[UNKNOWN-needs-runtime]`
  - Downgrade-but-keep-access; coupon stacking/reuse; refund-and-retain - `[UNKNOWN-needs-runtime]`
- *Blocking controls: `billing_server_side_enforced`, `webhooks_verified_and_idempotent`.*

## 4. mint-tokens - mint or reset free-tier tokens indefinitely
- Re-trigger the grant
  - Re-call claim/grant endpoint re-mints (not idempotent) - `[UNKNOWN-needs-runtime]`
  - Re-registration / new-account farming resets free tier - `[UNKNOWN-needs-runtime]`
  - Timestamp/clock manipulation forces a reset - `[UNKNOWN-needs-runtime]`
- Tamper the balance directly
  - Mass assignment sets `credits`/`tokens` on profile - `[UNKNOWN-needs-runtime]`
  - TOCTOU: parallel spends both pass `balance ≥ cost` before either deducts - `[UNKNOWN-needs-runtime]`
  - Client-reported usage under-counts consumption - `[UNKNOWN-needs-runtime]`
- *Blocking controls: `billing_server_side_enforced`, `rate_limits_on_expensive_endpoints`.*

## 5. read-others-data - read/alter another user's or tenant's data via tampering
- Object-level (BOLA/IDOR)
  - Endpoint takes `:id`/`userId` with no server-side ownership check - `[UNKNOWN-needs-runtime]`
  - Predictable/sequential ids enable enumeration - `[UNKNOWN-needs-runtime]`
- Function-level (BFLA)
  - Normal user reaches admin route by guessing path/verb - `[UNKNOWN-needs-runtime]`
- Identity/session tampering
  - JWT `alg:none` / RS↔HS confusion / weak secret forges identity - `[UNKNOWN-needs-runtime]`
  - Token in URL, or no expiry/revocation - `[UNKNOWN-needs-runtime]`
- Tenant isolation
  - One tenant reads another's rows/keys/conversations - `[UNKNOWN-needs-runtime]`
- *Blocking controls: `authz_on_every_object_and_function`, `encryption_tls_and_at_rest`.*

## 6. hijack-ai - hijack the AI to leak, exfiltrate, or act
- Direct prompt injection
  - User input concatenated into system context unguarded - `[UNKNOWN-needs-runtime]`
  - "Ignore previous instructions" / persona swap succeeds - `[UNKNOWN-needs-runtime]`
  - System-prompt leak exposes logic/keys/guardrails - `[UNKNOWN-needs-runtime]`
- Indirect / project injection
  - RAG doc / uploaded file / fetched page carries obeyed instructions - `[UNKNOWN-needs-runtime]`
  - Lower-resourced language (e.g. AR) bypasses EN-only guardrail - `[UNKNOWN-needs-runtime]`
- Excessive agency
  - AI tool grants credits / changes plan / calls paid API per attacker - `[UNKNOWN-needs-runtime]`
  - Action not authorized per-user / not rate-limited / not confirmable - `[UNKNOWN-needs-runtime]`
- Insecure output handling
  - Model output rendered as HTML/MD unsanitized (XSS) or used in SQL/shell - `[UNKNOWN-needs-runtime]`
- *Blocking controls: `ai_guardrails_present`, `authz_on_every_object_and_function`.*
