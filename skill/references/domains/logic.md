# AGENT-LOGIC - Business Logic & Abuse Cases

## Mission
Hunt the flaws no scanner can see: workflow/state-machine bypass, race conditions (beyond
billing), cross-model mass assignment, enumeration, and timing/error leakage. Priority: any
"trust the client" in a state-changing flow, and any way to reach a privileged state without
passing the step that guards it.

## Restate the stakes
This is where the bank gets robbed by someone who read your rules and simply skipped step 3 -
a missed logic hole is a breach, and the attacker only needs you to miss once. Prove it or flag it.

## Deterministic signals you are handed
- Business logic is **not** scanner-detectable. Expect an **empty or near-empty** slice of
  `findings.json` for this domain - that is normal, not an all-clear.
- You may receive leads from other scanners as context: mass-assignment / over-binding hints
  (API domain), missing-lock or non-atomic patterns, auth/route maps in `recon.json`.
- Any scanner hit here is a **lead to confirm or refute by reading the code**, never a verdict.
  Absence of hits means you must read the sinks yourself - mark findings `suspected` unless you
  read the enforcing/violating line.

## Checklist
Each bullet: what to look for · where · how to confirm with `file:line`.

- **State-machine skip** - an order/account/KYC/onboarding object that moves through states
  (draft→paid→shipped, pending→approved, unverified→verified) · state field + the handler that
  advances it · confirm the transition handler **checks the current state** before writing the
  next. Flag if any endpoint sets the terminal/privileged state directly without asserting the
  prior state (e.g. sets `status='approved'` with no check it was `pending`).
- **Skip a required step** - multi-step flows (cart→checkout→pay, signup→verify-email→activate) ·
  each step's controller · confirm step N verifies step N-1 completed server-side (a stored flag),
  not a client-sent "I already did it". Flag reachable later-step endpoints.
- **Reorder / replay steps** - can you call the finalize endpoint twice, or before the guard
  endpoint? · confirm idempotency + precondition checks on the terminal action.
- **Race condition beyond billing** - any read-check-write on a shared resource: concurrent KYC
  submit, concurrent role/invite grant, one-time coupon/seat/slot claim, "first N users" grants,
  inventory decrement · confirm **atomic** update (DB transaction, `SELECT ... FOR UPDATE`,
  conditional `UPDATE ... WHERE count < limit`, unique constraint). Flag any `if (count < max) {
  … save() }` with no lock - two parallel calls both pass the check (TOCTOU / double-grant).
- **Mass assignment across ALL models** (not just billing) · every create/update that spreads the
  request body (`{...req.body}`, `Model(**data)`, `Object.assign(entity, body)`, `update_attributes`,
  `save(req.body)`) · confirm an allowlist / DTO / `fillable`/`guarded` / `select` strips
  privileged fields. Flag any body-bound write that can set `role`, `is_admin`, `is_verified`,
  `owner_id`, `tenant_id`, `status`, `email_verified`, `kyc_status`, foreign keys, or timestamps.
- **Ownership / foreign-key tampering via body** - can the client set `user_id`/`owner_id`/
  `tenant_id`/`account_id` in a create or update to attach a record to someone else, or move their
  own record under another owner? · confirm the server derives the owner from the **session**, not
  the body.
- **Enumeration** - sequential/guessable ids (users, orders, invoices, tickets) exposed in URLs or
  responses · list/detail endpoints · confirm authz on each object AND that non-owned ids are
  indistinguishable. Flag incrementing integer ids without authz, or endpoints that leak existence.
- **Timing/error-difference leakage** - login, password-reset, "email exists?", coupon-check,
  invite-lookup · confirm the response and **latency** are identical for exists vs. not-exists
  (generic message, constant-time compare on secrets/tokens). Flag "user not found" vs. "wrong
  password" divergence, or a fast reject on unknown vs. slow hash on known.
- **Client-trusted authority in a state change** - any decision that grants access, changes tier,
  approves, or unlocks based on a value the client supplied (hidden field, header, query param,
  cookie, JWT claim the server doesn't re-verify, `isAdmin` in body, `verified=true`) · confirm the
  server recomputes/looks up the fact from its own source of truth. Flag every honored client
  assertion of privilege or state.
- **Negative / boundary / type abuse in logic** - quantities, counts, indices, date ranges, array
  lengths · confirm bounds + sign checks (negative seats refund, huge page size, `limit=-1`
  bypassing a cap, count wraparound). Cross-ref billing for money paths.
- **Workflow guard on the wrong layer** - a required check enforced only in the UI/SPA or only on
  one entry path while a second API/route reaches the same mutation · confirm the guard sits on the
  server mutation itself, so every caller hits it.
- **Saga/workflow compensation gaps** (adapts state-concurrency-auditor) - a multi-step business
  operation that touches money or an external service (book + reserve + charge) · if a later step
  fails, confirm earlier steps are rolled back or compensated · orphaned partial state (money moved,
  resource not delivered, or vice versa) is a real finding, not an edge case to wave off.
- **Stale-read / lost-update on collaborative or user-editable entities** (adapts
  state-concurrency-auditor) - an ORM `.save()`/`update()` that overwrites the whole row with no
  version/etag/optimistic-lock comparison · confirm a concurrent edit doesn't silently clobber another
  user's write; flag when the entity is shared or collaboratively edited.
- **Client-provided timestamp manipulation** (adapts state-concurrency-auditor) - a handler that
  accepts `timestamp`/`expires_at`/`scheduled_at` from the request body and uses it directly in an
  authorization or quota decision · the attacker controls the clock; confirm the server derives time
  from its own clock, not from client input, for any decision that grants or extends access.
- **Replay windows on signed tokens outside the primary auth path** - one-time codes, invite links,
  TOTP/OTP codes, email-verification tokens · confirm each is invalidated on first use (not just
  time-limited) and that a race between "check unused" and "mark used" is atomic - a token usable
  twice by racing two requests is the same TOCTOU class as a balance double-spend, just on a token
  table instead of a ledger.

## Systematic state & concurrency discovery method (adapts state-concurrency-auditor)

Before you go hunting for a specific bypass, build an inventory - the bugs above are found by walking
this inventory exhaustively, not by spot-checking the handlers that happen to look suspicious.

1. **Schema-level state columns**: grep migrations/schema/ORM models for
   `status, state, lifecycle_stage, phase, step, workflow_state`, `approved_at/rejected_at/deleted_at/
   verified_at`, and boolean `is_active/is_deleted/is_published/is_verified` fields. For each, record
   the table, column, allowed values, and every handler that writes it.
2. **Financial/quota/capacity entities**: `balance, credit, debit, quota, limit, remaining, available`,
   virtual currency (`tokens, points, coins`), and `inventory/stock/count`. These are where a TOCTOU
   becomes a double-spend - prioritize them.
3. **Idempotency/dedup infrastructure**: search for `idempotency_key`, `request_id` (stored, not just
   logged), dedup tables/redis keys (`*dedupe*`, `*seen*`), `jti`/`event_id` tracking. If the app
   handles payments or webhooks and this infrastructure doesn't exist anywhere, that absence is itself
   a finding - don't wait to find a specific replay to file it.
4. **Lifecycle transition functions**: `transition_to_*`, `advance_*`, `approve_*`, `reject_*`,
   `publish_*`, `cancel_*`, `refund_*` - for each, record which state column it mutates and what
   precondition it checks before doing so. This is your state graph; look for an edge that skips a
   guard (the state-machine-skip finding above).
5. **Concurrency primitives actually present**: grep for language-level locks (`Mutex`, `synchronized`,
   `threading.Lock`, `sync.Mutex`), DB-level controls (`SELECT ... FOR UPDATE`, `.select_for_update(`,
   transaction boundaries `@Transactional`/`transaction.atomic`/`BEGIN`), and distributed locks
   (`SETNX`, `Redlock`, `pg_advisory_lock`). The absence of any of these around a shared-state
   read-then-write is what makes it a TOCTOU - cite the absence as directly as you'd cite a present lock.

## Wooyun logic-flaws checklist (adapts wooyun-legacy's logic-flaws corpus)

High-risk parameters to prioritize when reading handlers: `code`/`validatecode` (verification codes),
`password`/`newPwd`, `sign`/`timestamp` (request signing), `amount`/`price`, `token`/`newMobile`
(binding flows), `flag`/`phone` (recovery flow control).

- **Password/credential reset flow** - walk the full flow end to end, then specifically check: (a) is
  the verification code ever echoed back in the response body (`{"data":{"verifyCode":"123456"}}`) -
  a leak that lets an attacker skip the out-of-band channel entirely; (b) is the code checked for
  validity only, or also bound to the account it was issued for (an attacker who requests their own
  code for their own phone, then submits it against a victim's account, must be rejected); (c) can a
  later step in the flow (e.g. "set new password") be reached directly by URL/route without the
  server having recorded that the prior verification step actually completed for this session.
- **CAPTCHA/verification-code hygiene** - is the code forced to refresh after a failed attempt, or
  does the same code remain valid for repeated guesses (enables brute force since the space is only
  4-6 digits)? Is there a rate limit (5 attempts/minute is the reference figure) and an expiry
  (60 seconds is the reference figure)? A code that's both long-lived and unlimited-attempt is a
  brute-forceable auth bypass, not just a UX nit.
- **Systematic parameter-tampering table** - for every state-changing endpoint, test the tamper
  direction the parameter's *type* invites, and confirm the server rejects it:

  | Parameter type | Tamper direction | Confirm server rejects |
  |---|---|---|
  | User/object id | Substitute another user's id | Ownership check server-side, not id-based trust |
  | Amount/price | Reduce, zero, negative, scientific-notation | Server recomputes from its own catalog |
  | Quantity | Negative or huge | Sign + bound check before use in any arithmetic |
  | Status/boolean flag | Flip (`isPaid=false→true`, `verified=false→true`) | Server re-derives the fact, never trusts the client's assertion |
  | Role | Escalate (`role=user→admin`, `aid=3→aid=1`) | Role re-derived from session, never from body |
  | Time | Extend/rewind (`expireTime=2099-...`) | Server clock is authoritative, not a client-supplied value (cross-ref the client-timestamp bullet above) |

## Creative attack ideation pass (adapts audit's creative-attack-modes)

Run this pass **after** the systematic checklists above, once you understand the app's actual
workflows - it's how you catch the chained/non-obvious bug a checklist alone won't surface. For each
business-critical flow, cycle through these prompts and write down anything that doesn't have an
obvious "no" answer:

1. **Chaining** - does a low-severity finding elsewhere (an IDOR that leaks metadata, an SSRF limited
   to internal DNS) combine with something here to cross a trust boundary that neither crosses alone?
2. **Business-logic abuse** - can you refund more than was paid? Invite yourself to a higher role?
   Skip step 2 and go straight from step 1 to step 3? Exhaust another tenant's quota by manipulating
   the accounting? Abuse a legitimate export/share/webhook feature as an exfiltration channel?
3. **Race/TOCTOU** - is any check-then-act pair separated by network/DB round-trips with no lock -
   what happens if two requests hit the gap at once?
4. **Second-order/stored** - is a value stored under one trust level and later consumed at a
   different, weaker one (stored value re-used in a query/render/shell context that assumes it was
   already sanitized on the way in)?
5. **Trust-boundary confusion** - does one component trust another's claim without re-verifying it
   (service-to-service, gateway-to-backend, "internal" endpoint reachable externally)?
6. **Parser/protocol differentials** - do two components (a security check and the actual consumer)
   parse the same input with different logic, such that one sees something safe and the other acts on
   something else?
7. **State-machine attacks** - can a step be replayed, reordered, or can the flow jump straight from
   state A to state C skipping the state-B check?
8. **Supply-chain/dependency interaction** - does a dependency's unsafe API get used where the safe
   one was available, or does the app override an insecure library default incompletely? (Hand the
   dependency-specific verdict to AGENT-SUPPLY; report the interaction here.)

Prioritize hypotheses that combine two modes (e.g. a race condition chained into an IDOR) - those are
exactly the findings a single linear pass through the checklist misses, and exactly what a scanner
cannot produce.

## Read these sinks manually
Scanners cannot reason about intent or order - you must read:
- The **state field + every handler that writes it** - build the real state graph and find edges
  that skip a guard.
- **AuthZ at each object and function** for logic flows: does step/endpoint check *who* AND *what
  state* before acting? (Object-level authz overlaps API domain - coordinate, don't assume they
  covered it.)
- **Concurrency**: read the actual read→check→write window on shared counters/claims and decide if
  it's atomic. No scanner proves this - reason about two simultaneous requests.
- **The full happy-path flow end to end** to spot the step a determined user reaches out of order.

## Kill-chain focus
Feeds primarily:
- **read-others-data** - ownership/FK tampering, enumeration, object-authz gaps.
- **bypass-billing** - workflow/state skips and mass assignment that flip entitlement/plan/credits
  (hand the money-specific mechanics to AGENT-BILLING; report the logic bridge).
- **mint-tokens** - race/replay on one-time grants, claims, invites, "first N" bonuses.
- **hijack-ai** - only if a logic/state bypass lets an unprivileged actor reach an AI action
  (coordinate with AGENT-LLM).

## Controls you own
This domain owns **no exclusive** control boolean, but its findings **gate** shared controls -
set to `false` (with the violating `file:line`) whenever you prove a bypass:
- `authz_on_every_object_and_function` - set `false` on any workflow/state-machine skip,
  mass-assignment privilege set, or ownership/FK tampering you confirm. One bypass = `false`.
- `rate_limits_on_expensive_endpoints` - set `false` if an enumeration or race abuse path has no
  per-identity limit. Leave unset if you cannot judge the full surface.
Never set a control `true` for a route you did not read - unset = unproven = fail-closed.

## Output
Emit `agent-logic.json` per `finding-schema.md` - fill fields, do not free-write. Every finding is
`confirmed` only if you read the enforcing/violating line; otherwise `suspected` and name the exact
runtime test (e.g. "fire 50 parallel claim requests, expect 1 grant") that would confirm it.
