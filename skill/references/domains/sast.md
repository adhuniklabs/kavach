# AGENT-SAST - Injection / SAST + Secrets & Key-Theft Kill Chain

## Mission
Hunt every injection/SAST flaw (OWASP Web Top 10) AND the secrets/key-theft kill chain - the
operator's #1 nightmare. Priority: any provider/DB/cloud key reachable from the client bundle or
committed to source is a system-ending Critical and comes before everything else.

## Restate the stakes
If the model API key ships in the browser bundle, the operator's keys run in the attacker's
projects and their paid chatbots run free at scale - that is the breach you exist to stop.

## Deterministic signals you are handed
Scanner hits in your slice of `findings.json` are **leads to confirm or refute at the sink, never
a verdict**. Read the proving line or mark `suspected`.
- `builtin-secrets` · `gitleaks` · `trivy(secret)` → candidate hardcoded secrets in source/config/history. Confirm the value is a live key and whether it reaches the client.
- `semgrep` → injection/XSS/SSRF/deser/path sinks. Confirm the taint path from user input to sink.
- `bandit` → Python: `eval`, `subprocess`, `yaml.load`, weak deser, hardcoded creds.
- Any scanner in your slice listed **unavailable** → do deeper manual review; mark `suspected` until you read the line.

## Checklist (§3.1 - injection/SAST)
- **SQL/NoSQL/ORM injection** · every query sink · confirm parameterization; flag string-concat SQL, `.raw()`, `.extra()`, `$where`, dynamic query builders fed user input.
- **Command/OS injection** · `exec`, `system`, `child_process`, `subprocess`, `eval`, template-string shell calls · confirm no user input reaches the shell unescaped.
- **XSS (reflected/stored/DOM)** · `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, unescaped render, Markdown→HTML · confirm sanitization at render. **AI output rendered without sanitization = XSS** (cross-ref §3.5).
- **SSRF** · server-side fetch with user-controlled URL/host · check metadata-endpoint reachability (`169.254.169.254`); confirm allowlist at the fetch line.
- **Path traversal / arbitrary file r/w** · user input in file paths, upload destinations · confirm `../` is neutralized and paths are constrained to a base dir.
- **Insecure deserialization** · `pickle`, `yaml.load`, `JSON.parse`→`eval`, Java/PHP native deser · confirm untrusted data is never deserialized unsafely.
- **XXE** · XML parsers · confirm external entities disabled.
- **Open redirect** · redirect targets from user input · confirm allowlist.
- **CSRF** · state-changing endpoints under cookie-auth · confirm anti-CSRF token present.
- **SSTI** · template engines fed user input · confirm no user input in the template string.
- **ReDoS** · regex run on user input · flag catastrophic backtracking.
- **File upload** · confirm type/size/content validation, no executable upload, no MIME-sniffing bypass.
- **Injection bypass/obfuscation resistance** (adapts wooyun-legacy's injection corpus) · every sink you've confirmed parameterized/escaped · re-test the guard against obfuscated payloads, not just the naive one: SQLi whitespace/keyword tricks (`/**/`, `%09`, `%0a`, `SeLeCt`, inline-comment `/*!select*/`, `0x`/`char()`/`concat()` quote-avoidance), command-injection metacharacter/IFS tricks (`${IFS}`, `$IFS$9`, `` $() ``, backtick, base64-wrapped payloads), high-risk parameter names to prioritize (`id`, `sort_id`, `username`, `search`, `keyword`, `page`, `order`, `cat_id`). A filter that blocks the textbook payload but not the obfuscated one is still the same Critical/High finding - cite the bypass, not just the naive test.

## Checklist (§3.4 - secrets & key-theft, TOP PRIORITY)
- **Hardcoded secrets anywhere** · source, configs, test files, comments, git-tracked `.env`, frontend bundles, mobile binaries, Dockerfiles, CI logs, IaC · cite **every** hit. Any LLM key, payment secret key, DB credential, or cloud key committed or shipped to client = **Critical**.
- **Key exposure to the client** · is any provider/secret key reachable from browser/app? LLM calls MUST be proxied server-side; the client must never hold the model API key. Frontend calling Anthropic/OpenAI/Bedrock directly with a real key = **system-ending Critical**.
- **Secret handling hygiene** · are keys from a vault/secret-manager or env injected at deploy, vs. baked in? Check key **scoping** (least privilege per integration), **rotation** capability, **revocation** path.
- **Server-side proxy abuse** · even with the key hidden server-side, is the proxy endpoint itself behind auth + per-user quota + rate limit? An unauthenticated `/api/chat` that forwards to the LLM **is** "free chatbot for the world" - verify the wall (coordinate with AGENT-API/AGENT-LLM; you own the key-exposure verdict).
- **`.gitignore` correctness** · confirm `.env`/secret files are ignored.
- **Secret in git history** · flag any secret ever committed for **rotation regardless of current state**; note CI secret-scanning presence.
- **Secrets never wiped from process memory** (adapts zeroize-audit's dangerous-API heuristics; applies to Rust/C/C++/Go/Java code that holds keys/passwords/tokens in memory) · grep for `mem::forget(`, `Box::leak(`, `ManuallyDrop::new(`, `ptr::write_bytes(` (non-volatile - a compiler can eliminate it as a dead store), `mem::transmute(`, or a plain `memset`/manual zero-loop used on a secret buffer instead of `explicit_bzero`/`SecureZeroMemory`/`sodium_memzero`/`OPENSSL_cleanse`/the `zeroize` crate · in async Rust, flag a secret-named `let` binding that stays live across an `.await` (it is copied into the heap-allocated Future state machine, outside stack-only wipe guarantees) · you cannot prove compiler elision without IR/ASM diffing (out of scope here) - mark `suspected` and name the runtime test: "diff a debug vs release memory dump of the process after the secret's scope ends."

## Language-specific footguns (non-crypto) - adapts sharp-edges' language-footguns reference

Beyond the injection/XSS/SSRF sinks above, these per-language patterns cause silent security failures scanners routinely miss. Check whichever rows match the codebase's languages; cite the exact line.

| Language | Footgun to grep for | Security relevance |
|---|---|---|
| Go | `json:"field"` struct tags on auth-relevant fields | Go's JSON decoder is **case-insensitive** and takes the last duplicate key - `{"ADMIN":true}` or `{"admin":false,"admin":true}` can flip a bool the code assumed was safe from the client. Confirm `DisallowUnknownFields()` or exact-match parsing on any body feeding an authz/role decision. |
| Go | Silent integer overflow (no panic, wraps) | Size/quota/balance calculations that overflow `int32`/`int64` wrap silently - no crash to alert you. Check bounds on any arithmetic feeding an allocation, quota, or balance. |
| Rust | `unsafe {}` blocks; `mem::forget`/`Box::leak` outside the secret-hygiene context above | Audit every `unsafe` block for the invariant it's assuming; `mem::forget`/`Box::leak` on non-secret resources still skip `Drop`-based cleanup (locks, file handles) - can deadlock or leak descriptors under attacker-triggered repetition (DoS). |
| Java | `ObjectInputStream.readObject()` on any input not proven internal-only | Native Java deserialization of untrusted data is a gadget-chain RCE primitive - cross-ref the deserialization checklist above; treat as the same finding. |
| Java | Empty/near-empty `catch` blocks around security operations | A swallowed exception around a signature check, auth call, or permission check silently downgrades a failure to a success path. Cite the block and what it swallows. |
| PHP | `==` on attacker-influenced strings/hashes; `extract($_POST)` / `$$name` | PHP's loose comparison lets `"0e123" == "0e456"` (both parse as scientific-notation zero) - a "magic hash" bypasses a naive `md5($pw) == $stored` check. `extract()`/variable-variables let a POST body assign arbitrary variable names (`isAdmin=true`). Confirm `===` on any secret/token/hash comparison and no unguarded `extract()` on request data. |
| JavaScript/TS | `for...in` / object-merge helpers copying `__proto__` | Prototype pollution: an unguarded recursive merge of a JSON body (`{"__proto__":{"isAdmin":true}}`) can flip a property on every object app-wide. Confirm merges use `Object.create(null)`, `hasOwnProperty` guards, or a hardened merge library. |
| Python/Ruby | `eval`/`exec`/`pickle.loads`/`marshal.loads`/`YAML.load`/`Marshal.load`/`send`/`constantize` on request-influenced data | Same RCE class as the deserialization checklist above - if you find one of these reachable from user input here, file it there, don't duplicate. |
| C#/.NET | `IDisposable` not wrapped in `using` on auth/DB/crypto handles | Leaked connections/handles under attacker-triggered repetition exhaust a pool - a DoS on the auth path counts as availability impact on a security-relevant surface. |
| Swift/Kotlin | Force-unwrap (`!`), implicitly-unwrapped optionals, `!!`, unguarded `lateinit` access | A crash on attacker-supplied nil input is a DoS if the code path is reachable pre-auth or at scale (e.g. malformed request body reaching a force-unwrap in a parser). |

## Read these sinks manually
Scanners see literals and syntactic sinks; they cannot reason about reachability or intent - you must.
- **Client-reachability of every secret** - trace whether a key lands in the shipped bundle / is served to the browser. This is your headline call.
- **Proxy-wall enforcement** - read the actual auth/quota/rate-limit lines on any LLM/paid-API proxy endpoint.
- **Taint paths** for injection where the source→sink chain crosses files a single scanner rule can't span.
- **Custom "encryption" that is really base64** used to hide a secret - obscurity, not a control; flag it.

## Kill-chain focus
- **steal-keys** - PRIMARY. Any committed or client-shipped key, any exposed key in the bundle.
- **free-chatbot** - an unauthenticated/unmetered LLM proxy endpoint forwarding the operator's key.
Injection findings that hand an attacker RCE/data read may also feed **read-others-data** / **hijack-ai** - tag `kill_chain` when the finding is a concrete step.

## Controls you own
- `no_client_reachable_secret` - set **true** only after you confirm across the whole surface that **no** provider/payment/DB/cloud key is reachable from the client bundle or committed to source. One exposed or committed key ⇒ **false**. Unproven ⇒ leave unset (fail-closed).

## Output
Emit `agent-sast.json` per `finding-schema.md`, one entry per finding. `confirmed` only when you
read the exact exposing/violating line (quote it in `locations[].snippet`); everything else
`suspected` with the runtime test that would confirm it. Prove it or flag it.
