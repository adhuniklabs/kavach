> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Parser & Encoding Differentials - Canonicalization Bypass Catalog

Load this whenever you are about to mark a security check "confirmed enforcing" and it involves
parsing, decoding, or normalizing attacker-controlled input - a URL, a path, a header, a filename,
a content-type, a token, or a protocol message. **A control that is correct in isolation is not
the same as a control that agrees with the code downstream of it.** Most of the highest-severity
findings in this catalog are not missing controls - they are two pieces of code (the gate and the
sink) that each parse the same bytes differently, and an attacker who lives in that gap.

## The core question

For every check-then-use pattern (validate a path, then open a file; validate a URL, then fetch
it; strip a header, then trust it; verify a signature, then extract the signed data), ask: **do
the check and the use share one parser, or two?** If two, they can disagree, and disagreement is
a bypass. This is the single highest-value question in this reference - ask it before moving on
from any control you are about to mark BLOCKED in the attack trees (`attack-trees.md`).

## 1. Reading a control before you trust it

Do not accept a control's name or comment as proof. Read the implementation and extract, in this
order:

- **Exact mechanism** - is it an allowlist, a parser, a policy engine, a sanitizer, a signature
  verifier? Name the concrete function.
- **Assumptions it makes** - type of the input, expected encoding, order of operations, caller
  privilege.
- **Preconditions required** for the control to work at all.
- **Failure mode** when one of those assumptions is violated - does it fail open or fail closed
  (cross-ref `insecure-defaults.md`)?

Only once you can state the mechanism and its assumptions in one sentence are you positioned to
generate hypotheses about how it breaks.

## 2. Generating attack hypotheses against a control

From the assumptions above, derive concrete hypotheses. Each one must name the attacker capability
and the target asset - "attacker can X, which reaches Y" - not a vague "might be bypassable":

- Encoding/normalization mismatches between the check and the sink
- Alternative syntax paths that reach the same sink
- Parser differential behavior (two parsers, one input, two interpretations)
- Policy bypass via composition or ordering (each check alone holds; stacked, a gap opens)
- TOCTOU and async race windows between check and use
- Cross-boundary trust confusion (a value trusted on one side of a trust boundary, unchecked on
  the other)
- Identity propagation drift across hops (auth context that doesn't survive a proxy/queue/service
  boundary intact)
- Schema or IDL drift between producer and consumer (proto/OpenAPI/GraphQL schema says one thing,
  code enforces another)
- Control-plane action triggered from a lower-trust surface than the control assumes
- Plugin, tool, or extension capability exposure beyond the scope the control was designed for

Every hypothesis you cannot immediately refute by reading the sink becomes a `suspected` finding
naming the runtime test that would settle it (`severity-model.md`).

## 3. Spec/RFC gap analysis - when code implements a protocol or format

Use this whenever a component's job is to parse or produce a standardized format (JWT, SAML,
OAuth, XML, HTTP, a serialization format, a custom wire protocol).

1. **Identify the spec's footprint in code** - locate the parser/serializer/state-machine module(s)
   and map which sections of the spec they implement. Note what is unsupported and any explicit
   deviation the code documents.
2. **Pull the security-relevant normative clauses** - the MUST/SHOULD/MAY constraints that govern
   validation, canonicalization, auth, replay, downgrade, and interoperability. Treat every MUST as
   a required check to locate in code.
3. **Map historical attack patterns** - check `domain-attack-playbooks.md` first for the identified
   protocol/format; it catalogs known attack classes, detection strategy, and a manual review
   checklist per domain (JWT, OAuth, SAML, XML, HTTP smuggling, and more). Only reach for external
   research when the domain isn't already covered there.
4. **Classify each clause/pattern** against the implementation:
   - Implemented correctly
   - Partially implemented
   - Missing
   - Implemented but bypassable under composition (the single most dangerous class - each piece
     looks fine, the combination doesn't)
5. **Report each gap as a finding** per `finding-schema.md` - not a separate file. Cite the spec
   clause, the exact code path, the gap classification, the condition under which it's exploitable,
   and the impact. `confirmed` only if you read the line that fails to enforce the MUST; otherwise
   `suspected` with the runtime test that would prove it (e.g. "send a JWT with `alg: none`").

## 4. Parsing, normalization, and sanitization discrepancy catalog

Many historical vulnerabilities stem not from a *missing* security control but from the security
control and the dangerous operation using **different interpretations of the same input**. These
bypass controls that look correct in isolation - they are often the highest-severity class in this
reference because a code reviewer skimming the control alone sees nothing wrong.

### URL and path parsing discrepancies

The security check and the router/file handler may parse the same URL differently:

- **Percent-encoding** - a check that decodes `%2F` → `/` may be bypassed with double encoding
  `%252F` if the check only decodes once but the handler decodes twice.
- **Unicode normalization** - `%EF%BC%8F` (fullwidth solidus) may normalize to `/` after the
  security check has already run.
- **Null bytes** - `path\x00.jpg` may pass an extension check but be truncated by the OS to `path`.
- **Trailing slashes and dots** - `/admin` vs `/admin/` vs `/admin.` may be treated differently by
  the router than by the auth check sitting in front of it.
- **Backslash normalization** - `path\..\..\etc\passwd` on Windows may not be caught by a
  Unix-style path-traversal check.

### Header injection via spec-non-compliant parsing

- **CRLF injection** - if a header value isn't stripped of `\r\n`, an attacker injects additional
  headers.
- **Header folding** - obsolete HTTP/1.1 header folding (continuation lines starting with
  whitespace) may be parsed differently by proxies and backends.
- **Multiple header values** - `Authorization: Bearer token1\r\nAuthorization: Bearer token2` -
  which value does each layer actually use?
- **`X-Forwarded-For` / IP spoofing** - rate limiting or access control keyed on the "client IP"
  read from `X-Forwarded-For` can be bypassed by simply adding the header.

### Content-type and format confusion

- **ZIP/Office confusion** - `.docx`, `.xlsx`, `.jar` are ZIP files. A content-type check that
  allows `application/zip` may allow Office files, and vice versa.
- **Polyglot files** - a file simultaneously valid in two formats (e.g. a JPEG that is also a valid
  ZIP) can bypass format-specific checks.
- **Multipart boundary tricks** - a multipart body with a crafted boundary may be parsed
  differently by the framework than by the application code reading it.
- **JSON/XML type confusion** - a field expected to be a string that also accepts an object or
  array may bypass string-specific sanitization.

### Sanitization applied at the wrong stage

- **Sanitize-then-parse** - sanitizing HTML before parsing means the parser can reconstruct
  dangerous markup from sanitized fragments (mutation XSS).
- **Parse-then-sanitize** - parsing before sanitizing means the sanitizer operates on the parsed
  DOM, which may differ from what the browser re-parses.
- **Double sanitization** - applying HTML-encoding twice can produce encoded entities the browser
  then decodes into dangerous content.
- **Context mismatch** - sanitizing for an HTML context but inserting the value into a JavaScript
  or CSS context.

### Spec-non-compliant behavior as a vulnerability source

When a project implements a standard protocol or format, deviations from the spec are a primary
source of exploitable bugs:

- **JWT algorithm confusion** - accepting `alg: none`, or allowing an RS256 token to be verified as
  HS256 (using the public key as the HMAC secret).
- **OAuth `redirect_uri` validation** - accepting prefix matches, subdomains, or not validating the
  scheme enables open redirect and authorization-code theft.
- **OAuth `state` parameter omission** - missing or non-validated `state` enables CSRF on the OAuth
  callback.
- **XML namespace handling** - namespace-aware and namespace-unaware parsers may interpret the same
  document differently, enabling signature-wrapping attacks.
- **SAML assertion validation** - checking the wrong element, accepting unsigned assertions, or not
  validating `InResponseTo`.
- **HTTP request smuggling** - discrepancies between `Content-Length` and `Transfer-Encoding`
  handling between a proxy and a backend.
- **Cookie attribute parsing** - browsers and servers may parse `SameSite`, `Secure`, and `HttpOnly`
  differently for malformed cookie headers.

### Canonicalization attacks

- **Case normalization** - a check for `script` may miss `SCRIPT` or `Script` if case
  normalization runs after the check, not before.
- **Unicode case folding** - `ı` (Turkish dotless i) uppercases to `I` in some locales, which can
  bypass case-insensitive checks.
- **Homoglyph substitution** - visually similar Unicode characters (e.g. Cyrillic `а` vs Latin `a`)
  may bypass string-equality checks.
- **IDN homograph** - internationalized domain names can bypass domain allowlists.

## 5. Validating in context (when runtime checks are authorized)

- Use deterministic, minimal tests - one crafted input, one observed outcome.
- Verify both the isolated path and the composed path (a check that holds alone can still fail
  once two controls are chained).
- Re-check under the deployment's real assumptions (is there a proxy in front that already
  normalizes what you're testing against the origin?).

## 6. Evidence quality bar

A parser-differential finding is only `confirmed` when you can show, with two cited lines, that
the check-side parse and the sink-side parse genuinely diverge on the same input - not merely that
they *could* in theory. High-quality evidence has all of:

- An explicit trust-boundary crossing (the input comes from the attacker's side of it).
- A concrete attacker-controlled input path reaching both the check and the sink.
- A demonstrated or strongly justified divergence between what the check validated and what the
  sink actually consumed.
- A concrete attacker gain tied to a protected asset - not just "different behavior," but "this
  divergence gets me a file outside the upload dir / an admin route / another tenant's row."

Without all four, mark the finding `suspected` and name the exact runtime test that would supply
the missing piece (`severity-model.md`'s confirmed/suspected discipline). Never inflate a
plausible-sounding divergence to `confirmed` on the strength of the pattern alone - that is exactly
the kind of hedge the persona's banned behaviors forbid (`persona.md`).

## Where this catalog gets used

This is general-purpose technique reference, not one domain's property - pull it whenever a
control you're evaluating does any parsing, decoding, routing, or canonicalization:

- **kavach-sast** - path traversal, SSRF allowlist bypass, XSS sanitizer-stage bugs, deserialization
  format confusion.
- **kavach-api** - route/authz checks that parse the path or headers differently than the router
  that dispatches to the handler.
- **kavach-config** - proxy/CDN/header-handling misconfiguration, cookie attribute parsing,
  `X-Forwarded-*` trust.
- **kavach-crypto** - JWT/SAML/OAuth spec-gap analysis (§3 above) sits at the crypto/authn boundary.
- **kavach-logic** - policy bypass via composition or ordering, TOCTOU windows.
