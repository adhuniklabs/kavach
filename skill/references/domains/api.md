# AGENT-API - API Authorization, Authentication & Session

## Mission
Hunt broken object- and function-level authorization (BOLA/IDOR/BFLA), mass assignment,
broken authentication/session, and the naive "our API only talks to our frontend" assumption.
Priority: authz on every object/function is the #1 cause of "change the URL and read another
user's data" - treat it as top of your list.

## Restate the stakes
An unchecked `:id` is 11,000 drained accounts. One route that trusts the client over who you are
or what tier you are is a breach, not a finding. Prove each gate or flag it.

## Deterministic signals you are handed
- Your slice of `findings.json` - scanner hits for missing-auth routes, CORS `*`, JWT misconfig,
  `alg:none`. **A scanner hit is a lead to confirm or refute, never a verdict.**
- `recon.json` - the framework, router style, auth library, and where routes/middleware live.
- Scoped file list: every route/controller/handler, auth middleware, and session/JWT config.
- Note: **scanners barely help here.** BOLA/IDOR/BFLA/mass-assignment need manual route reading -
  a scanner cannot know that `order.userId` should equal the caller. Read the routes yourself.

## Checklist
Each bullet: what to look for · where · how to confirm (cite `file:line`).

BOLA / IDOR (API #1):
- Every endpoint taking an object id (`:id`, `userId`, `orderId`, resource lookups) · route
  handlers · confirm an ownership/tenant check runs server-side **before** the read/write
  (`WHERE user_id = session.user`, or `if resource.owner != caller → 403`). Trace each id param.
- Nested/implicit ids in body, query, headers, or JWT claims used as the authority · same.
- "Looks up by id then returns" with no owner comparison = BOLA. Cite the missing line.
- **Parameter pollution on the identity/owner param** (adapts wooyun-legacy's authorization-bypass corpus) · repeat the same param with two values (`?uid=1&uid=2`), as an array (`uid[]=<target>`), or nested in JSON (`{"user":{"id":<target>}}`) · confirm the framework's dedup behavior ("last wins"/"first wins"/array-coerced) doesn't let a second value smuggle past a check performed on the first · cite the parsing behavior or its absence.

Broken authentication (API #2):
- Token issuance, expiry, refresh, revocation · auth module · confirm each exists and is enforced.
- Signature verification on every protected request · confirm the verify call, not just decode.
- Algorithm confusion - `alg:none` accepted, RS256↔HS256 confusion (public key used as HMAC
  secret) · JWT verify config · confirm algorithm is pinned.
- Session fixation - session id rotated on login/privilege change · confirm the regenerate call.

BOPLA / mass assignment & excessive exposure (API #3):
- Can the client set `is_admin`, `is_premium`, `role`, `credits`, `plan`, `price` via request
  body? · create/update handlers · confirm a whitelist/DTO/`pick()` - flag blanket
  `Model(req.body)`, `Object.assign(user, req.body)`, `**request.data`, spread of raw body.
- Over-return - API sends fields the UI hides but the wire reveals (password hash, other-user
  data, internal flags) · serializers/responses · confirm field selection.

Unrestricted resource consumption (API #4):
- Missing rate limits, pagination caps, payload-size limits, per-identity quotas · route/middleware
  · confirm each on expensive + AI + auth endpoints. Absence directly enables "run the chatbot
  free at scale." (Co-own with AGENT-LLM.)

BFLA (API #5):
- Admin/privileged routes reachable by a normal user guessing path or HTTP verb · admin routers,
  role-gated handlers · confirm a role/permission check on every privileged route and every verb
  (a route may guard GET but not DELETE). Cite the gate or its absence.

## Authorization matrix method (adapts piolium's authz-auditor)

Route-by-route reading doesn't scale on a large surface and misses the copy-paste omission pattern.
Build an explicit matrix before you file findings:

1. **Enumerate every request-handling boundary** - not just HTTP routes: gRPC/proto methods, GraphQL
   resolvers, WebSocket message handlers, queue/topic consumers (Kafka/SQS/RabbitMQ/Celery/Sidekiq),
   cron/scheduled jobs, and event/webhook callbacks. A route framework grep only finds the first kind.
2. **For each endpoint, record three guard layers plus one bypass layer**, not just "has auth y/n":
   - **Layer 1 - declarative**: middleware/decorator/annotation (`@login_required`, `@PreAuthorize`,
     `before_action :authenticate`, `@UseGuards`).
   - **Layer 2 - in-body**: `current_user`/`request.user`/`ctx.user` compared against the resource
     owner inside the handler (`.filter(owner=...)`, `.can(...)`, `Pundit.policy`).
   - **Layer 3 - router-level composition**: guards mounted on a parent router (`router.use(auth)`
     before a sub-router) that the endpoint inherits but never re-checks.
   - **Layer 4 - hidden control channels**: request-controlled or proxy/framework-derived signals that
     can *alter* identity, tenant, method, or path before Layers 1-3 run - `X-Forwarded-*`,
     `X-Real-IP`, `X-Original-URL`/`X-Rewrite-URL`, `X-HTTP-Method-Override`, `X-User-*`/`X-Tenant-*`/
     `X-Admin`/`X-Internal`/`X-Debug` headers, and rewrite/fallback rules in the router config. If a
     route is protected only by one of these and the handler performs no re-check, that is a finding
     on its own (`hidden-control-channel` bypass), not a caveat.
3. **Derive an Expected Scope per endpoint** - `public`, `self` (owner-only), `org`/`team` (tenant-scoped),
   `role:<name>`, `admin`, or `unknown` (insufficient signal → flag for manual review, never assume safe).
4. **Flag the outlier, not just the miss**: group endpoints by controller/prefix/proto-service; if 90%+
   of siblings share a guard and one lacks it, that lone gap is a high-signal finding class on its own
   (`inconsistent-guard`) - it is how copy-paste omissions happen.
5. **Produce the unauthenticated-surface view**: every endpoint where `Expected Scope = public`, OR the
   combined Layer 1-3 guard stack is empty, OR the only guard is a bypassable Layer-4 channel. This is
   the exhaustive answer to "what can an anonymous attacker reach" - do not eyeball it, derive it from
   the matrix.

## Wooyun unauthorized-access checklist (adapts wooyun-legacy's unauthorized-access corpus)

- **Backend/admin path exposure without auth** · probe for `/admin`, `/manager`, `/console`,
  `/actuator/env`, `/actuator/heapdump`, `swagger-ui.html`/`/api-docs` mounted with no guard · a
  directly-reachable admin interface is Critical regardless of "nobody would guess the URL."
- **Unauthenticated internal datastores** · Redis (6379), MongoDB (27017), Elasticsearch (9200),
  Memcached (11211) reachable from outside the app's own network segment with no auth configured ·
  a Redis instance reachable without auth can be used to write a webshell or cron job - Critical.
- **Weak/default credentials left enabled** · admin/admin, vendor defaults, seeded fixture accounts
  reachable in a non-test environment · cite the seed/fixture and whether it is guarded by an
  environment check.
- **Header-based identity/IP trust** · `X-Forwarded-For`/`X-Real-IP`/`Client-IP` accepted as the
  source of truth for an IP allowlist or audit log · these are attacker-supplied; confirm the
  app trusts only the value set by its own trusted proxy, not an arbitrary client header.

Cross-refs (note, then hand to owner):
- SSRF on server-side fetch (API #7) → AGENT-SAST.
- Security misconfig / headers / CORS (API #8) → AGENT-CONFIG; CORS also below.
- Shadow / zombie / undocumented endpoints (API #9) · route inventory · flag deprecated,
  debug, or version-drift routes still mounted.
- Unsafe consumption of 3rd-party APIs (API #10) → AGENT-SUPPLY.
- **Spec/contract-vs-enforcement drift** (adapts spec-to-code-compliance's alignment method) · if an
  OpenAPI/GraphQL SDL/proto spec declares required scopes, roles, or auth schemes per endpoint · read
  the spec's claim and the handler's actual enforcement side by side and classify: `full_match`,
  `code_weaker_than_spec` (handler accepts less than the spec promises - the dangerous direction, file
  it), `code_stronger_than_spec` (note only), or `missing_in_code` (spec declares an endpoint you can't
  find enforcement for - flag as coverage gap). Never infer intent from the spec being silent - treat
  spec-silent-on-auth as `unknown`, not `public`.

"Frontend-only" honesty test - judge, do not hand-wave:
- It is **impossible** to cryptographically guarantee only your SPA calls your API - anyone can
  replay an HTTP request. So evaluate defense-in-depth and flag naive trust.
- **FLAG** if the app relies on `Origin`/`Referer` headers alone as a security control (spoofed
  trivially) · confirm at the check.
- **Verify present:** strict CORS allowlist (no `*` with credentials, no reflected origin);
  authenticated short-lived tokens on every request; anti-CSRF tokens for cookie sessions;
  per-identity rate limiting + abuse detection; API gateway/WAF; for service-to-service, mTLS or
  signed (HMAC) requests with nonce + timestamp to defeat replay.
- State residual risk plainly: **client-side secrets are not secret.** Any API key or privileged
  logic in the frontend bundle = **Critical** (hand secret location to AGENT-SAST; keep the authz
  consequence here).

Authentication, Authorization & Session (§3.3):
- Password storage - argon2id / bcrypt / scrypt with proper cost · user/auth model · flag
  MD5 / SHA1 / unsalted SHA256 / plaintext as **Critical**.
- JWT/session - secret strength & storage, expiry, rotation, revocation; cookies
  `Secure` + `HttpOnly` + `SameSite`; **token in URL/query = banned** · confirm each flag/line.
- Privilege escalation - horizontal (other users) and vertical (higher role); RBAC enforced at
  every gate; multi-tenant isolation (one tenant cannot read another's data/keys/usage) · confirm.
- MFA present for privileged actions; account-recovery & password-reset tokens have entropy, are
  single-use, and expire · reset flow · confirm each property.
- Parameter/URL tampering generally - every place the URL, query, header, cookie, or body can be
  edited to change **who you are** or **what tier you are** · confirm server re-derives identity
  and tier from the session, never from client input.

## Read these sinks manually
Scanners cannot reason about ownership, role, or tenant intent. You must read:
- Each resource lookup - does it constrain to the caller's id/tenant, or fetch by raw id alone?
- Each mutating handler - is the body whitelisted, or spread wholesale into the model?
- Each privileged route across **all** verbs - is authz on every one, or only the happy path?
- Session/JWT verify path - is the signature actually verified and the algorithm pinned?
- The full request→identity→tier chain - is identity re-derived server-side every time?

## Kill-chain focus
Primary: **read-others-data** (BOLA/IDOR/tenant break, param tampering). Also feeds:
**mint-tokens** and **bypass-billing** (mass assignment of `credits`/`plan`/`role`, BFLA on
entitlement routes), **free-chatbot** (unauthenticated or unlimited proxy endpoints - missing
rate limits/quota), and **steal-keys** (client-reachable key or privileged logic in the bundle).

## Controls you own
Set these booleans in `agent-api.json` (per finding-schema.md). A control is `true` **only** when
you cite the enforcing line across the **whole** surface - one unprotected route makes it `false`.
Unset = unproven = fail-closed.
- `authz_on_every_object_and_function` - every object read/write is ownership/tenant-checked and
  every function/route is role-checked, server-side.
- `rate_limits_on_expensive_endpoints` - co-owned with AGENT-LLM; set from the API-side controls.

## Output
Emit `agent-api.json` per finding-schema.md - one finding per issue, controls set as above.
`confirmed` only when you read the enforcing/violating line; else `suspected` with the exact
runtime test (e.g. "replay POST with another user's id") that would confirm it.
