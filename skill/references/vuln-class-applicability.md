> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Vulnerability-Class Applicability - APPLICABLE / ADAPT / NOT_APPLICABLE

Load this the moment `tool-catalog.md`'s sweep summary lists a scanner as **unavailable** for a
language or framework actually present in the repo, or when a domain checklist item names a
pattern (`domains/*.md`, `domain-attack-playbooks.md`) that was clearly written with one language's
idioms in mind and you're now staring at a different stack. The failure mode this reference exists
to prevent is binary and silent either way: **skipping a checklist item because "that's a Python
thing" when it isn't**, or **manually re-deriving a whole vulnerability class from scratch when a
scanner already proved the equivalent construct is absent**. Neither is acceptable - reason it out,
write the verdict, then act on it.

## Why this matters when a scanner is unavailable

`tool-catalog.md` explains what runs by stack. When the sweep marks a scanner `unavailable` (no
Docker, no native binary, or the language simply has no bundled rule for it), the matching domain
subagent is told to "review manually and mark suspected." That instruction is not license to grep
blindly for the pattern the scanner *would* have used - it's an instruction to first ask whether
the vulnerability class is even reachable in this stack, and if so, by what construct. Answer that
before spending review budget hunting for it.

## The three verdicts

### APPLICABLE

The vulnerability class exists in this language/stack and the checklist pattern (or its scanner
signature) translates with only minor syntax adjustment. Manually check the equivalent construct
with the same confidence bar as if a scanner had flagged it.

**Criteria:**
- An equivalent dangerous construct exists with the same semantics.
- The vulnerability manifests identically to the way the checklist/scanner rule describes it.
- The detection logic (what "safe" looks like) carries over unchanged.

**Example**
```
CHECKLIST ITEM: command injection via subprocess.call(cmd, shell=True) (Python-flavored)
STACK: Go, no gosec available for this build

VERDICT: APPLICABLE
REASONING: Command injection is a fully general vulnerability class - any language with a shell-
exec primitive fed attacker input has it. Go's exec.Command / exec.CommandContext is the direct
equivalent of subprocess.call.
EQUIVALENT CONSTRUCT: exec.Command(cmd) or exec.Command("sh", "-c", cmd) where cmd contains
attacker-controlled data.
MANUAL CHECK: grep for exec.Command/CommandContext, trace each argument back to a request handler;
confirm no argument is built by string concatenation from user input.
```

### ADAPT

The vulnerability class exists, but the concrete pattern needs real translation - different API
shape, different idiom, or additional patterns specific to this language's ecosystem. Do not
pattern-match the original checklist wording literally; derive the target-language equivalent
first, then check for it.

**Criteria:**
- The vulnerability class is present but manifests through a structurally different API.
- Equivalent constructs exist but their names/shapes differ enough that literal string-matching
  the original wording would miss real instances.
- Additional idioms specific to this language need their own check.

**Example**
```
CHECKLIST ITEM: insecure deserialization via pickle.loads(untrusted) (Python-flavored)
STACK: Java, no scanner rule loaded for this codebase's serialization library

VERDICT: ADAPT
REASONING: Both detect deserialization vulnerabilities, but the APIs differ enough that a literal
translation misses real hits. Java's risk surface is ObjectInputStream.readObject(), not a single
function call - and the safe/unsafe line depends on whether a look-ahead filter is installed.
ADAPTATIONS NEEDED:
  - Check for ObjectInputStream construction AND readObject()/readUnshared() call sites, not one
    line.
  - Confirm whether a serialization filter (ObjectInputFilter, since Java 9) constrains accepted
    classes - absence of a filter on untrusted input is the finding, not the readObject() call
    itself.
  - Also check readObject() overrides that call back into deserialization recursively.
```

### NOT_APPLICABLE

The vulnerability class does not exist in this language/stack, or no equivalent construct exists.
Document why and move on - do not force a checklist item onto a stack that can't host the bug.
This is itself a reportable determination (a documented "no gap here, and here's why"), not silence.

**Criteria:**
- The vulnerability class requires a language feature this stack doesn't have (manual memory
  management, dynamic typing, prototype-based inheritance, etc).
- No equivalent construct exists anywhere in the stack's standard library or common ecosystem.
- Forcing the pattern would be meaningless or actively misleading in a report.

**Example**
```
CHECKLIST ITEM: buffer overflow detection (C-flavored)
STACK: Python application, no unsafe/FFI blocks anywhere in the codebase

VERDICT: NOT_APPLICABLE
REASONING: Python manages memory automatically; there is no direct pointer/buffer arithmetic for
application code to get wrong. Buffer overflow in the classic C sense is not present. (If the
codebase later imports a C-extension module or uses ctypes/cffi, re-run this analysis against that
module specifically - the verdict is per-surface, not per-repo.)
```

## Analysis process - answer these three questions per checklist item

### 1. Does the vulnerability class exist in this language/stack at all?

Some classes are structural to a language and either fully present or fully absent:

- Buffer overflow: applies to C/C++, may apply to Rust inside `unsafe` blocks, does not apply to
  Python/Java/Go application code.
- SQL injection: applies to any language with database access.
- XSS: applies to any language generating HTML output.
- Memory leak: relevant in C/C++, far less relevant in garbage-collected languages (but resource
  leaks - file handles, connections, goroutines - are a live analog worth checking instead).
- Type confusion: relevant in dynamically typed languages, far less in strongly typed ones.

### 2. Does an equivalent construct exist?

Identify what the checklist item or the (unavailable) scanner rule actually detects, then find the
target stack's equivalent:

- **Sinks** - what dangerous functions/methods does the pattern flag?
- **Sources** - where does tainted data enter, in this stack's idiom (HTTP handler, CLI arg, queue
  message, env var)?
- **Pattern type** - is this a single-call pattern-match, or does it need taint tracking across
  multiple hops (assignment, then use)?

Then research the target stack: what are the equivalent dangerous functions, the common source
patterns, and are there stack-specific idioms (a popular ORM, a common templating engine, a
standard HTTP client) that need their own line in the manual check?

### 3. Are the semantics similar enough to be worth checking?

- Does the vulnerability manifest the same way once triggered?
- Are there stack-specific mitigations already baked in that change what "missing" looks like
  (e.g. a templating engine that auto-escapes by default shifts the finding from "no escaping" to
  "escaping explicitly disabled")?
- Would flagging this actually provide security value, or would it be noise dressed as thoroughness?

## Common applicability patterns

### Always relevant, regardless of stack

These vulnerability classes exist across nearly every language and always deserve a manual check
when the scanner can't reach them:

- SQL injection (any language with DB access)
- Command injection (any language with shell execution)
- Path traversal (any language with file operations)
- SSRF (any language with an HTTP client)
- XSS (any language generating HTML)

### Context-dependent - analyze before deciding

These require the full three-question process above, not a reflexive yes:

- Deserialization - the unsafe mechanism differs sharply per language (pickle vs
  ObjectInputStream vs unserialize() vs BinaryFormatter vs Marshal).
- Cryptographic weaknesses - depends entirely on which crypto library the stack uses and what its
  defaults are.
- Race conditions - depends on the concurrency model (threads, event loop, goroutines, actors).
- Integer overflow - depends on the type system (checked vs wrapping arithmetic, fixed vs
  arbitrary-precision integers).

### Usually NOT_APPLICABLE outside their home language

- Memory corruption (C/C++-specific, unless FFI/unsafe blocks are present - then re-check that
  surface specifically)
- Type juggling (PHP-specific)
- Prototype pollution (JavaScript-specific)
- GIL-related concurrency bugs (Python-specific)

## When the checklist item targets a specific library

Domain checklists and playbooks often name a specific library (an ORM, an HTTP client, a
templating engine). When the codebase uses a *different* library in the same role:

1. **Identify the library's purpose** - what functionality does it provide (ORM/DB access, HTTP
   client/server, serialization, templating, auth)?
2. **Research the actual library in use** - does it have the same escape hatches (raw query
   methods, `eval`-equivalents, unsafe deserialization modes) as the one the checklist named?
3. **Decide scope** - is the equivalent check against the standard-library primitive, the specific
   third-party library actually imported, or does the codebase use multiple libraries in the same
   role (check each)?

Default to checking the library actually imported, not the one the checklist happened to name -
the goal is coverage of this codebase, not fidelity to the checklist's original wording.

## Verdict format (write this down before you check anything)

```
ITEM: <checklist item / scanner rule this stands in for>
STACK: <language/framework, and which scanner is unavailable for it>
VERDICT: APPLICABLE | ADAPT | NOT_APPLICABLE
REASONING: <does the class exist here, does an equivalent construct exist, are semantics close>
EQUIVALENT CONSTRUCT: <this stack's actual sink/source/idiom, if APPLICABLE or ADAPT>
MANUAL CHECK: <what to grep for / trace, and what "safe" looks like>
```

## How the verdict feeds a finding

`APPLICABLE`/`ADAPT` with a manual check performed becomes a normal entry in `agent-<domain>.json`
(`finding-schema.md`) exactly like a scanner-sourced lead - `confidence: confirmed` only if you
read the sink and traced the taint yourself; `suspected` if you found the construct but couldn't
fully trace it statically, naming the runtime test that would close the gap. `NOT_APPLICABLE` is
not silence either - note it in your working notes so the reconciler knows the checklist item was
considered and dismissed with reasoning, not skipped by omission. A gap in coverage caused by "the
scanner doesn't run here" is exactly the situation the persona's fail-closed posture exists for
(`persona.md`): absence of scanner evidence is never evidence of absence.

## Checklist before moving past this analysis

- [ ] Identified what the original checklist item / scanner rule actually detects (sink, source,
      pattern type).
- [ ] Researched the equivalent construct in the stack actually in front of you.
- [ ] Wrote the verdict with specific reasoning - not "probably applies."
- [ ] If ADAPT, listed the concrete adaptations needed before checking anything.
- [ ] If NOT_APPLICABLE, documented why, scoped to the specific surface (a repo-wide dismissal is
      wrong if one module does use FFI/unsafe/a native extension).
- [ ] Every APPLICABLE/ADAPT item was actually checked against a real file:line - a verdict is not
      a substitute for reading the sink.
