> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Creative Attack Generation Modes

Eight structured thinking modes for generating attack hypotheses that a purely syntactic scan will
never surface. Cycle through all 8 for each threat cluster or component, generating at least one
hypothesis per applicable mode. Hypotheses spanning multiple modes (chaining + race condition, say)
are the most valuable - prioritize them.

**Who uses this:** `kavach-ideator` (the chamber's hypothesis generator, `chamber-protocol.md`),
the two deep-probe reasoners (`kavach-reasoner-backward`, `kavach-reasoner-contradiction`,
`probe-protocol.md` - these modes supply raw material alongside their Pre-Mortem/Abductive/
TRIZ/Game-Theory reasoning lenses), and `kavach-logic` (the domain agent absorbs this catalog for
its own solo pass over business-logic surfaces during static analysis, before any chamber or probe
runs).

## Mode 1: Vulnerability Chaining

Chain individually-low-severity issues into a high-severity exploit path. No single issue may
qualify as a finding alone, but the combination crosses a trust boundary. This is exactly the
severity-chaining rule in `severity-model.md` - the creative step is spotting the chain, the
scoring step is already defined there.

**Thinking prompts:**
- "If an IDOR gives read access to user metadata, and that metadata contains session tokens, then
  IDOR + token reuse = account takeover."
- "If SSRF is limited to internal DNS resolution, and internal DNS resolves to the cloud metadata
  endpoint, then SSRF + metadata = credential theft (`steal-keys`)."
- "This CVE's patch only covers the HTTP path. Does the WebSocket path use the same parser without
  the fix?"
- "`attack-surface/advisory-summary.md` flags a known CVE; `attack-surface/spec-gap-summary.md`
  flags a protocol-compliance gap - does the gap bypass the patch?"
- "A low-severity info-disclosure plus a low-severity injection can equal a high-severity
  authenticated RCE."

**Cross-reference inputs:**
- `attack-surface/advisory-summary.md` (known CVEs, patch commits)
- `attack-surface/spec-gap-summary.md` (protocol-compliance gaps)
- `findings.json` dropped/low-severity leads that a domain agent's Inline-Enrichment triage set
  aside individually
- `attack-surface/knowledge-base-report.md`'s domain attack research section

## Mode 2: Business Logic Abuse

Think about what the application is *designed* to do, and how that design can be abused. Business
logic bugs are invisible to SAST - `kavach-logic`'s primary domain, and the mode `kavach-ideator`
should lean on hardest for billing/entitlement/workflow clusters.

**Thinking prompts:**
- "Can I refund more than I paid? Process a negative quantity?"
- "Can I invite myself to a higher-privilege role?"
- "Can I skip step 2 and go directly from step 1 to step 3?"
- "Can I exhaust another tenant's quota by manipulating the accounting?"
- "Can I register the same resource twice and exploit the race between checks?"
- "Can I abuse a legitimate feature (export, share, webhook) as an exfiltration channel?"
- "Can I reorder operations to bypass a check that assumes sequential execution?"
- "Can I abuse an undo/rollback mechanism to restore a revoked privilege?"

**Focus areas:** multi-step workflows (payment, registration, approval, provisioning); quota/rate
systems (credits, API limits, storage - feeds `mint-tokens`/`free-chatbot`); invitation and
delegation systems; state machines with transitions (draft -> published -> archived).

## Mode 3: Race Conditions and TOCTOU

Identify state-dependent operations and ask "what if the state changes between check and use?"
Races resist static analysis - this is `kavach-state`'s deep specialty and a primary
Pre-Mortem/TRIZ target for the probe reasoners.

**Thinking prompts:**
- "The balance check and the deduction aren't atomic - double-spend?"
- "Role is checked, then 100ms later the privileged action executes. Can the role change between?"
- "Symlink substitution between `stat()` and `open()`?"
- "The isolation level is READ COMMITTED - phantom reads in this multi-query operation?"
- "The session is validated, then the request body is parsed. Can the session be invalidated
  mid-parse?"
- "Two concurrent requests to the same endpoint - does the second see the first's uncommitted
  state?"
- "The file is written, then permissions are set. Is there a window where it's world-readable?"

**Detection strategy:** look for check-then-act patterns without locking or atomic transactions;
identify shared mutable state accessed by concurrent handlers; find operations spanning multiple
I/O calls (DB, file, network); check for non-atomic read-modify-write sequences.

## Mode 4: Second-Order and Stored Attacks

Look for inputs stored before being used in a dangerous context - the storage creates temporal and
spatial separation that hides the attack from simple source-to-sink analysis.

**Thinking prompts:**
- "User input stored in a profile field, later rendered unescaped in an admin dashboard (stored
  XSS)."
- "Username stored in table A, later concatenated into a query when joining table B (second-order
  SQLi)."
- "A webhook URL stored in config, later fetched by a background job (stored SSRF)."
- "A template variable stored in the DB, later rendered by the email templating engine (stored
  SSTI)."
- "A filename stored at upload time, later used in a shell command during processing (stored
  command injection)."
- "A JSON payload stored in an event queue, later deserialized by a consumer at a different trust
  level."

**Detection strategy:** identify every write path (user input -> DB/file/cache/queue); for each
stored value, trace every read path and its consumption context; check whether the read context
applies weaker sanitization than the write context; pay special attention to cross-service data
flows where the consuming service trusts stored data as if it were already validated.

## Mode 5: Trust Boundary Confusion

Identify where identity, authorization, or trust assumptions change across component boundaries.

**Thinking prompts:**
- "Service A trusts Service B's claims without re-verification."
- "Frontend validation is assumed present by the backend."
- "An 'internal' API is exposed through a public reverse proxy with no re-auth."
- "Plugin/extension code runs with host-level privileges."
- "The auth middleware checks tokens, but this endpoint is registered before the middleware in the
  route chain."
- "The API gateway validates the JWT, but the downstream service accepts any request from the
  gateway's IP."
- "The admin panel is 'internal only' but shares the same origin as the public app (CORS,
  cookies)."
- "The CLI runs with user privileges but shells out to a helper that runs as root."

**Detection strategy:** map every trust boundary from `attack-surface/knowledge-base-report.md`;
for each, check whether crossing it requires re-authentication or re-authorization; identify
implicit trust assumptions (IP-based trust, shared-origin trust, process-level trust); check
middleware ordering - are security checks applied before or after route registration? Look for
"internal" APIs reachable from external networks (cross-check
`attack-surface/unauthenticated-surface.md` if it exists).

## Mode 6: Parser and Protocol Differentials

Look for places where two components interpret the same input differently. Parser differentials
are high-severity because they bypass controls that look correct in isolation - see
`parser-differentials.md` for the canonicalization-bypass catalog this mode feeds into.

**Thinking prompts:**
- "HTTP request smuggling between a proxy and the backend (CL vs. TE)."
- "JSON parser differential - duplicate keys, which value wins?"
- "URL parser differential - authority parsing, percent-encoding, backslash handling."
- "A Content-Type mismatch between what the validator checks and what the processor consumes."
- "XML namespace-aware vs. namespace-unaware parser (signature-wrapping attacks)."
- "A multipart-boundary parsing difference between the framework and application code."
- "Header folding - a proxy treats a continuation line as part of the previous header; the backend
  treats it as a new one."
- "Path normalization - the security check uses one library, the router uses another."

**Cross-reference inputs:** `attack-surface/spec-gap-summary.md` (RFC-compliance gaps in parsers);
`attack-surface/knowledge-base-report.md`'s domain attack research (protocol-specific patterns);
`parser-differentials.md`.

**Detection strategy:** identify every parser in the system (URL, JSON, XML, multipart, headers,
cookies, query strings); for each, check whether the same parser instance backs both the security
check and the consumer; look for double-encoding, normalization-order issues, and
spec-non-compliant behavior; check for polyglot inputs valid in multiple formats simultaneously.

## Mode 7: State Machine Attacks

Analyze multi-step protocols and state machines for out-of-order, replay, or missing-transition
attacks.

**Thinking prompts:**
- "Can I replay step 3 of the OAuth flow to get a second access token?"
- "Can I redirect the password-reset link to a different email by modifying the request between
  steps?"
- "What happens if I send an API request during the 'pending deletion' grace period?"
- "Session invalidation is async - is there a window where the old session still works?"
- "Can I reuse a one-time code (TOTP, email verification, invite link) by racing the
  invalidation?"
- "Can I transition from 'suspended' back to 'active' by calling an endpoint that assumes
  'pending'?"
- "Can I bypass the email-verification step by calling the post-verification endpoint directly?"
- "The payment flow assumes A -> B -> C. Can I go A -> C directly?"

**Detection strategy:** map every state machine (user lifecycle, order lifecycle, auth flow,
payment flow); for each transition, verify the previous state is checked, and that the check is
atomic; look for state stored in client-side tokens (JWT, cookies) that can be replayed; check for
async state updates where the old state stays valid during propagation; identify one-time tokens
and verify they are actually invalidated after use.

## Mode 8: Supply Chain and Dependency Interaction

Use `attack-surface/advisory-summary.md` and `attack-surface/sbom.json` to generate hypotheses
about how dependencies interact with application code - `kavach-supply`'s primary domain, and a
priority mode when the SBOM shows an out-of-date or gadget-chain-capable library.

**Thinking prompts:**
- "This dependency has a known deserialization gadget. Does the application ever deserialize
  user-controlled data with it?"
- "This transitive dependency is years out of date. What security fixes shipped since?"
- "The application monkey-patches this library's validation function. Does the patch weaken it?"
- "The library exposes both a safe API and an unsafe one - which does the application use?"
- "The library's default configuration is insecure - does the application override the defaults?"
- "Two dependencies implement the same protocol differently. Does the app use both on the same
  data path?"
- "The library was designed for server-side use; the application uses it in a browser context."
- "The library's error handling returns sensitive information - does the application expose it?"

**Cross-reference inputs:** `attack-surface/advisory-summary.md` (CVEs, GHSAs, patch commits);
`attack-surface/knowledge-base-report.md`'s domain attack research; `kavach-supply`'s
maintainer-health assessment.

**Detection strategy:** for each security-relevant dependency, trace how the application actually
uses it; check whether the app uses the safe or unsafe API surface; verify insecure defaults are
overridden appropriately; look for version-pinning gaps and dependency-confusion opportunities.

## Applying multiple modes

The most creative and impactful hypotheses combine modes. When generating a batch, explicitly
attempt at least 2 cross-mode combinations:

- Mode 1 (chaining) + Mode 3 (TOCTOU): "Chain a race condition in the payment check with an IDOR
  to achieve an unauthorized fund transfer."
- Mode 4 (stored) + Mode 5 (trust boundary): "Store a payload via the low-trust user API that gets
  executed by the high-trust admin renderer."
- Mode 6 (parser differential) + Mode 7 (state machine): "Use a URL parser differential to bypass
  the OAuth `redirect_uri` check, then replay the authorization code."
- Mode 2 (business logic) + Mode 8 (supply chain): "The caching library serves stale responses -
  abuse this to serve a revoked user's data to a new user inheriting the same cache key."

## Hypothesis output format

Each hypothesis carries every one of these fields - `kavach-ideator` uses this shape for `H-NN`
entries in `debate.md`, and `kavach-logic` uses the same shape for its own solo pass:

```markdown
**H-<NN>: <hypothesis title>**
- Attack class: <primary mode used>
- Cross-modes: <secondary modes if applicable, or "none">
- Chain: <multi-step chain description, or "single-step">
- Preconditions: <attacker starting position and required capabilities>
- Target asset: <what the attacker gains>
- Entry point: <suspected entry point in the code>
- Sink: <suspected sensitive operation>
- Creativity signal: <why a solo agent would miss this - what makes it non-obvious>
```

`Creativity signal` is mandatory. If a hypothesis is obvious ("SQL injection in a query that
concatenates user input"), it doesn't need this catalog - the scanner sweep already found it. This
catalog's value is in hypotheses that require lateral thinking a syntactic pass structurally can't
produce.
