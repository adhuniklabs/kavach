> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Verification Gates - False-Positive Elimination Deep-Dive

`severity-model.md` carries the condensed six-gate table every domain agent applies inline before
it writes a finding. This file is the full-depth companion: the 13-item false-positive checklist,
per-bug-class verification requirements, evidence templates, and the devil's-advocate protocol
that back those six gates up. Load it whenever a finding needs more than the one-paragraph inline
check - a CRITICAL/HIGH survivor going to `kavach-verifier`, a hypothesis `kavach-advocate` is
building a defense brief against inside a chamber debate, or `kavach-triager` deciding whether a
finding is even worth a PoC slot. Any domain agent may also load this directly when a lead is
ambiguous enough that the six-gate table alone doesn't settle it.

**Who this governs:** `kavach-verifier` (cold, zero-context re-verification of Critical/High
survivors - this file supplies its rejected-rationalizations list), `kavach-advocate` (the 5-layer
protection search inside a chamber debate is Gate 6 done adversarially - see `chamber-protocol.md`),
`kavach-triager` (the cheap P0/P1/P2/skip gate reads Gate 2/3 before spending PoC budget), and any
domain agent verifying a scanner lead or a probe hypothesis before emitting it.

## Rationalizations to reject

If you catch yourself thinking any of these mid-verification, stop and go back to the checklist.
This is the list `kavach-verifier` carries forward into its output as the rejected-rationalizations
record - the point is not just to avoid these, but to name the ones you almost fell for.

| Rationalization | Why it's wrong | Required action |
|---|---|---|
| "Rapid pass on the rest of the queue" | Every candidate gets the full verification it's routed to | Return to the queue, verify the next candidate through every gate |
| "This pattern looks dangerous, so it's a vulnerability" | Pattern recognition is not analysis | Complete data-flow tracing before any conclusion |
| "Skipping steps for efficiency" | No partial verification - Standard and Deep both run to completion | Execute every step in the routed path |
| "The code looks unsafe, so I'll report without tracing the data flow" | Unsafe-looking code may have upstream validation | Trace the complete path from source to sink |
| "Similar code was vulnerable elsewhere" | Each call site has different validation, callers, and protections | Verify this specific instance independently |
| "This is obviously critical" | Models are biased toward seeing bugs and over-rating severity | Complete the devil's-advocate pass; prove it with evidence, then score per `severity-model.md` |

## Step 0: understand the claim before touching a gate

Restate the candidate in your own words before any analysis. Half of false positives collapse the
moment you try to restate them precisely - the claim stops making coherent sense. KAVACH runs
zero-input: if the claim cannot be restated clearly from the evidence you already have, that
incoherence is itself grounds to **DROP** it. Do not invent a clearer claim than the evidence
supports, and do not stop to ask the operator - resolve it from the code or drop it.

Document, in your own scratch notes (not necessarily the finding body):

- **Exact vulnerability claim** - e.g. "SSRF in `fetch_webhook()` when the target host is
  attacker-supplied and unresolved before the request fires."
- **Alleged root cause** - the missing check, e.g. "no allowlist check before `requests.get(url)`."
- **Supposed trigger** - e.g. "attacker sets their webhook URL to `http://169.254.169.254/...`."
- **Claimed impact** - e.g. "cloud metadata credential theft, feeds `steal-keys`."
- **Threat model** - what privilege level does this code run at? What can the attacker already do
  before triggering it? Unauthenticated caller vs. an already-logged-in tenant vs. an admin-only
  path all carry different weight.
- **Bug class** - classify it and pull the matching section from Bug-Class-Specific Verification
  below; it supplements every generic step that follows.
- **Execution context** - when and how is this code path reached in normal operation?
- **Caller analysis** - what functions call this code, and what input constraints do they impose
  before the call?
- **Architectural context** - is this one link in a chain of protections (see `attack-trees.md`),
  or the sole control?
- **Historical context** - does `attack-surface/commit-recon-report.md` or
  `attack-surface/patch-bypass-summary.md` (if either exists) say anything about this code area?

## Route: standard vs. deep verification

After Step 0, choose a path. This is a checklist choice, not a task-graph to build - KAVACH does
not spin up a tracked task list for this; you work the chosen checklist directly and document
evidence inline as you go.

### Standard verification

Use when **all** of these hold:

- Clear, specific claim (not vague or multiply-interpretable)
- Single component - no cross-component interaction in the bug path
- Well-understood bug class (injection, XSS, SSRF, integer issue, path traversal, etc.)
- No concurrency or async in the trigger
- Straightforward source-to-sink data flow

Work the checklist below (Steps 1-6) linearly, document findings inline, and reach a verdict.
Two escalation checkpoints route out to Deep:

1. **After the data-flow step**: escalate if you found 3+ trust boundaries, callback/async control
   flow in the path, or an ambiguous validation chain.
2. **After the devil's-advocate spot-check**: escalate if any of the five questions produces
   genuine uncertainty you cannot resolve with the evidence at hand.

### Deep verification

Use when **any** of these hold:

- Ambiguous claim admitting multiple interpretations
- Cross-component bug path (data flows through 3+ modules or services)
- Race conditions, TOCTOU, or concurrency in the trigger mechanism
- A logic bug with no clear spec to verify against
- Standard verification was inconclusive or escalated
- The candidate is a Critical/High survivor headed to `kavach-verifier`, or a chamber hypothesis
  `kavach-advocate` is building a full defense brief against

For component-level ambiguity (the claim spans a whole component's trust surface, not one
function), dispatch `kavach-probe` per `probe-protocol.md` first - its layer-trust-chain mapping
and Bayesian stop loop produce VALIDATED/INVALIDATED/NEEDS-DEEPER hypotheses with the causal
challenge already applied, which this checklist can then gate-review directly instead of re-tracing
from scratch. For a claim that needs adversarial argument from both sides, escalate into a
`kavach-chamber` debate per `chamber-protocol.md` - the Ideator/Tracer/Advocate/Chamber roles work
Steps 1-5 below as structured argumentation instead of one agent working alone.

When escalating mid-pass, carry every piece of evidence already gathered forward - never repeat
completed tracing.

## Deep verification checklist (Steps 1-5, then Gate Review)

Work through these as an ordered checklist, not a task-management system. Each numbered step below
names the pitfall to watch for - that is the part you are likely to get wrong.

**Step 1 - Data flow.** Map trust boundaries (internal/trusted vs. external/untrusted) crossed, and
trace data from source to the alleged vulnerability. Apply the class-specific checks below. Check
API/framework contracts before claiming an overflow or an injection - many APIs and ORMs have
built-in bounds/escaping protection that prevents the alleged issue regardless of input. Check for
language, runtime, framework, or infra protections that eliminate the exploit entirely (not merely
raise the bar - ASLR and ORM parameterization are different categories of "protected").
**Key pitfall:** analyzing the vulnerable-looking line in isolation. Conditional logic upstream may
make it mathematically unreachable - trace the full validation chain, not the snippet (checklist
items 1 and 1a below).

**Step 2 - Exploitability.** Prove the attacker controls the data reaching the operation - internal
storage set by a trusted component (config store, install-time value) is not attacker-controlled
just because it "came from somewhere." For bounds/overflow/underflow claims, build the explicit
algebraic proof (template below): `IF validation_check_passes THEN bounds_guarantee_holds`. For
race conditions, prove concurrent access is actually possible - single-threaded init paths and
correctly-synchronized sections cannot race regardless of how the code reads.

**Step 3 - Impact.** Distinguish real security impact (RCE, privilege escalation, cross-tenant or
cross-user data exposure, key theft, billing bypass, meaningful DoS) from an operational-robustness
issue (crash recovery, cleanup failure, retry hygiene). Distinguish a primary control from
defense-in-depth - a defense-in-depth failure is not a vulnerability while the primary control
holds.

**Step 4 - PoC.** Always build the pseudocode PoC with a data-flow diagram (template below). Build
an executable or unit-test PoC when feasible - this is the draft that `kavach-poc` later formalizes
into `poc.py` / `poc.theoretical.md` per the finding-dir contract, so keep it concrete and minimal,
not a weaponized exploit kit. Also build the **negative PoC**: state the preconditions the exploit
needs and show why normal traffic never satisfies them - this is what makes Gate 4 falsifiable
instead of rhetorical.

**Step 5 - Devil's advocate.** Before any verdict, challenge the claim. Assume you are biased toward
finding bugs and over-rating them - work against that bias explicitly.

*Against the vulnerability:*
1. What non-vulnerability explanation exists for this code pattern?
2. How would the original author justify this implementation?
3. What architectural context might be missing from your view?
4. Am I calling this a vulnerability because the pattern "looks dangerous," not because it is?
5. Even if validation looks thin, does it actually prevent the claimed condition?
6. Am I assuming attacker control over data that is actually trusted/internal?
7. Have I rigorously proven the mathematical or state condition can occur, not just asserted it?
8. Beyond theoretical possibility, is this practically exploitable by the threat model in scope?
9. Am I confusing a defense-in-depth failure with a primary-control failure?
10. What compiler/runtime/framework/infra protection might block this outright?
11. Am I pattern-matching on scary-looking code rather than proving an exploit?

*For the vulnerability (false-negative protection - always ask):*
12. Am I dismissing a real bug because the exploit path seems complex or unlikely?
13. Am I inventing a mitigation or validation I have not actually re-read in the source? Re-read
    the code after reaching a conclusion, before you write it down.

### Standard verification's 7-question spot-check (lighter version of Step 5)

Standard verification runs a shorter spot-check instead of the full 13:

1. Am I pattern-matching on a scary-looking construct rather than proving an exploit?
2. Am I assuming attacker control over trusted/internal data?
3. Have I rigorously proven the condition can occur?
4. Am I confusing defense-in-depth failure with a primary-control failure?
5. Am I over-rating this because models are biased toward seeing bugs everywhere?
6. (always ask) Am I dismissing something real because it seems complex or unlikely?
7. (always ask) Am I inventing mitigations I haven't actually re-read in the source?

If any of the seven produces genuine uncertainty, escalate to Deep.

## The six gates (full form)

`severity-model.md` states these condensed; this is the elaborated form with the pitfall each gate
exists to catch. Evaluate all six after the checklist above is complete - do not gate-review a
partial pass.

| Gate | Criterion | Passes when | Fails when |
|---|---|---|---|
| **1. Process** | Every step above ran with documented evidence | Each step has concrete evidence, not an assertion | Any step was skipped or asserted without a citation |
| **2. Reachability** | Attacker-controlled input reaches the exact line in question | Clear evidence of a controlled path, traced end-to-end | Cannot show attacker control or a path to the sink |
| **3. Real impact** | Exploitation produces a genuine security consequence | Concrete: RCE, privesc, cross-tenant/cross-user exposure, key theft, billing bypass, meaningful DoS | Only a robustness/cleanup/operational issue, no trust boundary crossed |
| **4. PoC validation** | A PoC (pseudocode at minimum) shows control → trigger → impact | PoC demonstrates the full path | PoC cannot be built or fails to show the attack |
| **5. Math/logic bounds** | For bounds/overflow/off-by-one/state-transition claims, an algebraic or state proof shows the vulnerable condition is reachable | Proof shows the condition is possible | Proof shows validation prevents it |
| **6. Environment** | No language/runtime/framework/infra control fully eliminates the exploit | Any protection found only raises the bar, doesn't block it | A control (type system, ORM parameterization, sandbox with no escape, unbypassable WAF rule) fully prevents it |

**Verdict is emit-or-drop, and it is not a second severity axis** (`severity-model.md` already
states this - repeated here because it's the whole point): all six gates pass → **emit** the
finding and proceed to score it (`severity-model.md`); any gate fails decisively → **DROP as false
positive**, one line naming the failed gate and why, e.g. `DROP - Gate 5 (math/logic bounds) fails:
validation at auth.py:88 ensures amount > 0, the underflow this claim needs is unreachable.` A
dropped finding does not exist - never carry it into `findings.json` at any severity, not even Low.

**Gate 6 and `confidence` are not the same question.** Gate 6 fails only when a protection is
*proven* to fully block the exploit. If you cannot determine from static reading alone whether a
protection blocks it - authz enforced by runtime middleware you can't trace, a race that needs load
to trigger, a WAF ruleset you can't read - that is unresolved uncertainty, not a Gate 6 fail. Emit
the finding with `confidence: suspected` and name the exact runtime/DAST test that would resolve
it. Reserve `confidence: confirmed` for when you read the line that proves both the flaw and the
absence of a blocking control.

## 13-item false-positive checklist

Apply every item to every candidate. Having a checklist doesn't prevent false positives if you run
it superficially - work all 13 before concluding, every time (item 13 exists because this failure
mode is common enough to name).

1. **Trace the full validation chain.** Don't analyze an isolated snippet. Trace backward for all
   validation preceding a dangerous operation - a size-manipulation site that looks dangerous often
   has bounds validation earlier in the same function or an upstream caller.
2. **Map the complete conditional logic flow.** Vulnerable-looking code may be unreachable because
   conditional logic upstream creates a mathematical guarantee (e.g. `buffer[length-4]` looks unsafe
   for `length < 4`, but if the function is only ever reached when `length > 12`, it's impossible).
   Verify: what conditions must hold to reach this line? Do they mathematically prevent the claimed
   scenario? Are there minimum-size/length requirements that guarantee safe access?
3. **Identify defensive programming patterns.** Distinguish an actual vulnerability from a
   defensive assertion or validation. `assert(size == expected_size)` followed by a size-controlled
   operation is a guard, not a bug - verify the check genuinely prevents the claimed condition.
4. **Confirm exploitable data paths.** Only report CONFIRMED exploitable flow. Don't assume
   network- or client-controlled data reaches a sink without tracing the actual path step by step.
5. **Understand data-source trust context.** API return values, compile-time constants, and network
   data carry different risk profiles - determine the actual source and whether it is genuinely
   attacker-controlled, not just "external-sounding."
6. **Analyze bounds-validation math.** Look for the relationship between the check and the
   operation. If `size >= MIN_SIZE` is checked and `MIN_SIZE >= sizeof(header)`, then
   `size - sizeof(header)` cannot underflow - work the algebra, don't eyeball it.
7. **Verify TOCTOU claims with proof.** A time-of-check/time-of-use claim requires proof the
   checked value can actually change between check and use. A value checked and immediately used in
   the same function, with no external mutation window, has no TOCTOU regardless of how it reads.
8. **Understand the API contract before claiming an overflow.** Some APIs have built-in bounds
   protection and cannot write past the buffer no matter the input.
9. **Distinguish internal storage from external input.** Config stores and registries set by
   trusted components at install/deploy time are not attacker-controlled just because a scanner
   flagged them as "data."
10. **Don't confuse pattern recognition with analysis.** Code that "looks vulnerable" may be safe
    given its context and API contract - a size parameter being mutated is not an overflow if the
    API prevents writing past bounds regardless.
11. **Verify concurrent access is actually possible.** Don't assume a race exists without proving
    concurrent access. Single-threaded init contexts cannot race - verify the actual threading model
    and synchronization primitives in use.
12. **Assess real vs. theoretical impact.** Ask: would this lead to code execution, privilege
    escalation, or information disclosure? A non-critical operational storage failure is not a
    security finding.
13. **Understand defense-in-depth vs. primary control.** A defense-in-depth failure is not a
    vulnerability if the primary control is intact - e.g. failed token cleanup is not critical if
    the token is single-use at the server regardless.
14. **Apply this checklist rigorously, not superficially.** A checklist run in name only doesn't
    catch anything - work all items above before concluding, on every candidate, every time.

### Red flags for false positives

**Pattern-based:** reporting a vulnerability inside validation/bounds-checking code itself; claiming
TOCTOU without proving the value can change; ignoring preceding validation; assuming network data
reaches a sink without tracing it; confusing an assertion/guard for a vulnerability; skipping the
conditional-logic-reachability check; reporting "vulnerabilities" in error/cleanup code; flagging a
size calculation without checking its mathematical constraints; flagging a "dangerous" function
without checking whether its inputs are bounded; claiming overflow in a fixed-size,
compile-time-bounded operation; reporting a race in a single-threaded or fully-synchronized context.

**Context-blind analysis:** analyzing a snippet without the surrounding system design; ignoring an
architectural guarantee (single-writer, trusted-input-only); missing that the code is unreachable
due to earlier validation; confusing a debug/dev-only path with production; flagging code that only
runs during trusted install/setup; flagging a theoretical issue the system's architecture actually
prevents; missing a framework or language guarantee that blocks the claim; reporting a test-only or
debug-only path as if it shipped to production.

**Mathematical/bounds analysis:** claiming underflow without proving the mathematical condition can
occur; claiming overflow when bounds are mathematically guaranteed by validation; missing that
conditional logic makes the vulnerable state impossible; claiming an off-by-one without checking
whether loop bounds prevent it; claiming corruption when allocation sizes are verified sufficient;
claiming arithmetic overflow without checking whether input ranges prevent it.

**API-contract misunderstanding:** claiming an overflow when the API has built-in bounds checking;
claiming memory corruption for an API that manages its own memory safely; missing that a return
value is already validated by the API's contract; confusing parameter mutation with a vulnerability
when the API prevents unsafe mutation; reporting something the API's own safety guarantee already
handles; missing that an operation is safe due to the API's actual implementation.

## Bug-class-specific verification

Apply the section matching the classified bug class **in addition to** the generic steps above.
The KAVACH domain column names which domain agent (or the chamber/probe team) typically owns this
class, so you know where to route a fresh candidate of the same shape.

### Memory corruption
*Buffer/heap/stack overflow, OOB read/write, use-after-free, double-free, type confusion.*
**KAVACH domain:** `kavach-sast` (native modules, FFI boundaries), `kavach-supply` (vendored C
dependencies), `kavach-crypto` (unsafe Rust secret-handling - see `rust_secret_apis` scanner).

**Language-safety check first:** memory corruption in safe Rust, Go without `unsafe.Pointer`/cgo, or
a managed runtime (JVM, CLR, Python, Node) is almost always a false positive - the language or
runtime prevents it. Verify whether the code is inside an `unsafe` block, uses cgo/`unsafe.Pointer`,
or calls native code via JNI/P-Invoke/FFI. If the code is entirely in the safe subset, reject the
claim unless it involves a documented compiler bug or soundness hole.

**Verify:** exactly what gets corrupted (object, field, region); the corruption's size/offset and
whether the attacker controls them; whether the corruption is a useful primitive (arbitrary
read/write, vtable/function-pointer overwrite) or just a crash; the allocator in use and whether it
hardens against exploitation; for UAF, the object's lifetime - what frees it, what reuses the
memory, can the attacker control the replacement object; for type confusion, that the mismatch
exists and that misinterpreting the data yields a useful primitive.

### Logic bugs
*Auth bypass, access-control errors, incorrect state transitions, confused deputy, privesc via API
misuse.* **KAVACH domain:** `kavach-api` (authz), `kavach-logic` (business logic), `kavach-billing`
(entitlement/payment logic), `kavach-state` (state-machine transitions).

**Verify:** check against the spec or design intent, not just the code as written - does the
implementation match the intended behavior? Map all state transitions - can the system reach a
state the developer didn't anticipate? Identify implicit assumptions never enforced in code. For
auth bugs, verify **every** auth/authz path, not just the one that appears broken - is there a
secondary check that catches it? Logic bugs pass every bounds check and mathematical proof - clean
static analysis is not evidence of a false positive here.

### Race conditions
*TOCTOU, data races, signal-handling races, concurrent state modification.* **KAVACH domain:**
`kavach-state` (financial/idempotency races), `kavach-probe` (race hypotheses from
Pre-Mortem/TRIZ reasoning).

**Verify:** the actual race window - nanoseconds or seconds? Can the attacker widen it (stalling a
thread with a slow request, a large allocation, CPU contention)? Verify the threading model - what
threads/processes/workers can actually touch this data concurrently? Check every synchronization
primitive in play - mutexes, atomics, DB isolation level, optimistic locking. For filesystem TOCTOU,
can the attacker control the path between check and use (symlink race)?

### Integer issues
*Overflow, underflow, truncation, signedness errors, wraparound.* **KAVACH domain:** `kavach-sast`,
`kavach-billing` (amount/quantity arithmetic).

**Verify:** the exact integer types and ranges at every point in the computation; whether the
overflow is signed (UB in C/C++) or unsigned (defined wraparound); how the value moves through casts,
conversions, and promotions - where does truncation or sign extension occur? After the integer
issue occurs, is the result actually used dangerously (allocation size, array index, loop bound,
monetary amount)?

### Crypto weaknesses
*Weak algorithms, bad parameters, nonce reuse, padding oracle, insufficient randomness, timing
side channels.* **KAVACH domain:** `kavach-crypto`.

**Verify:** parameter choices against current standards (NIST, IETF) and known attacks - "AES-128"
is fine, "DES"/ECB-mode/MD5-for-integrity are not. Verify the randomness source - is the PRNG
cryptographically secure and properly seeded? For nonce reuse, prove the same nonce can actually
recur in practice, not just in theory. For timing side channels, is the code reachable by an
attacker who can actually measure timing with the needed precision, or does network jitter make it
impractical? Compare against a reference implementation or spec test vectors.

### Injection
*SQL/NoSQL injection, XSS, command injection, SSTI, path traversal, LDAP injection.* **KAVACH
domain:** `kavach-sast` (primary owner), `kavach-api` (route-level input handling).

**Verify:** trace attacker input from entry to sink (query/command/template/path). Is there
sanitization or escaping anywhere on the path? Does the framework auto-escape (parameterized
queries, template auto-escaping) - and is it actually enabled, not disabled or bypassed? For XSS,
what context does the input land in (HTML body, attribute, JS, URL) - each needs different
escaping. For path traversal, is the path canonicalized before the access check - can `../` or a
null byte bypass it? Test the payload through every intermediate transform - encoding/decoding
steps can neutralize or re-enable it.

### Information disclosure
*Uninitialized-memory reads, error-message leaks, timing side channels, padding oracles.* **KAVACH
domain:** `kavach-sast`, `kavach-config` (debug/verbose-error leaks).

**Verify:** what specific data leaks - a stack leak revealing an ASLR base or a session token is
critical; one revealing a static string is worthless. Is the leaked data actually useful for further
exploitation (ASLR bypass, session token, crypto key, other tenant's data)? For uninitialized
memory, prove it's actually uninitialized at the read point, not just potentially so on some path.
For error messages, does the leak actually reach the attacker, or only server-side logs?

### Denial of service
*Algorithmic complexity, resource exhaustion, crash bugs, infinite loops, memory bombs.* **KAVACH
domain:** `kavach-api` (rate-limit gaps), `kavach-llm` (unbounded token/loop spend, feeds
`free-chatbot`).

**Verify:** the resource-consumption ratio - attacker sends X, server spends Y; is the amplification
meaningful? Can the resource be reclaimed, or is exhaustion permanent? For algorithmic complexity,
what is the actual worst-case input, and does it provably trigger worst-case behavior (not just
"looks O(n²)")? For crashes, is it reliably triggerable, or dependent on specific heap/stack layout?
Does the service auto-restart - a crash causing a 100ms restart differs from one needing manual
intervention.

### Deserialization
*Unsafe deserialization, object injection, gadget-chain exploitation.* **KAVACH domain:**
`kavach-sast`, `kavach-supply` (gadget-chain-capable dependencies).

**Verify:** does the attacker actually control the serialized data reaching the deserializer? Does a
usable gadget chain exist in the classpath/import graph - without one, unsafe deserialization is a
design smell, not an exploitable bug yet. What library/version is in use, and are there known gadget
chains for it? Are there type restrictions, allowlists, or look-ahead filters blocking dangerous
classes? Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`, .NET `BinaryFormatter` each
have different exploitation characteristics - don't generalize across them.

## Evidence templates

Use these when documenting verification evidence. They feed directly into a finding's
`what_it_is`/`how_exploited` fields (`finding-schema.md`) and into the PoC draft `kavach-poc` later
formalizes.

**Data flow:**
```
Source: <exact location> - Trust level: <trusted/untrusted>
Path: Source -> Validation1[file:line] -> Transform[file:line] -> Vulnerability[file:line]
Validation points:
  - Check1: <condition> at <file:line> - <passes/fails/bypassed>
  - Check2: <condition> at <file:line> - <passes/fails/bypassed>
```

**Mathematical bounds proof:**
```
Claim: Operation X is vulnerable to <overflow/underflow/bounds violation>
Given constraints: <every validation condition in play>

1. <first constraint from validation>
2. <constant or known value>
3. <derived inequality>
...
N. Therefore: <vulnerability confirmed/debunked> (Q.E.D.)
```
Example:
```
Given: validation ensures (input_size >= MIN_SIZE); MIN_SIZE = 16, header_size = 8
Prove: (input_size - header_size) cannot underflow
1. input_size >= MIN_SIZE            (from validation)
2. MIN_SIZE = 16, header_size = 8    (constants)
3. input_size >= 16                  (substitution)
4. input_size - 8 >= 16 - 8          (subtract header_size)
5. input_size - header_size >= 8     (simplification)
6. Therefore: underflow impossible   (Q.E.D.)
```

**Attacker control:**
```
Input vector: <how the attacker supplies the input>
Control level: <full/partial/none>
Constraints: <limits on attacker input>
Reachability: <can attacker-controlled data reach the vulnerable operation?>
```

**PoC - pseudocode with data-flow diagram:**
```
[External Input] -> [Validation Point] -> [Processing] -> [Vulnerable Operation]
     |                     |                    |                    |
  Attacker           (may be bypassed)    (transforms data)    (unsafe op)
  controlled               |                    |                    |
     |                     v                    v                    v
  [Malicious Data] -> [Insufficient Check] -> [Processed Data] -> [Impact]

function vulnerable_operation(user_data):
    validation_result = weak_validation(user_data)   # why this fails, cite the line
    processed_data = transform_data(user_data)       # show the transform
    unsafe_operation(processed_data)                 # show the trigger
```

**Negative PoC** (the falsifiability half of Gate 4): state the exact preconditions the exploit
needs, then show why ordinary, non-adversarial traffic never satisfies them - the gap between
normal operation and the exploit path is what makes the PoC evidence rather than assertion.

**Devil's-advocate record:**
```
Vulnerability claim: <brief description>
1-11. <answers to the arguing-against questions>
12-13. <answers to the arguing-for/false-negative-protection questions>
Final assessment: <confirmed/debunked, with reasoning tied to the six gates>
```

## Batch triage

When verifying multiple candidates at once - a scanner sweep's raw hit list, or a chamber's
hypothesis batch:

1. Run Step 0 for every candidate first - restating each claim collapses obvious false positives
   immediately, before spending checklist time on them.
2. Route each candidate independently - some standard, some deep.
3. Process standard-routed candidates first, then deep-routed ones.
4. After all are verified, check for **exploit chains**: findings that individually failed Gate 3
   (Real Impact) alone may combine into a viable attack. Score the chain per `severity-model.md`'s
   severity-chaining rule, not each primitive in isolation.

## Final summary

After processing every candidate in a batch, report:

1. **Counts** - N confirmed, N suspected, N dropped.
2. **Confirmed/suspected list** - each with a one-line description and the gate evidence.
3. **Dropped list** - each with the one-line reason (which gate failed, or which checklist item
   caught it) - this is the rejected-rationalizations record for anything that almost looked real.
