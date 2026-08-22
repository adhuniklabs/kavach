> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Insecure Defaults - Fail-Open vs Fail-Secure Heuristic & Regex Catalog

Load this whenever you're auditing config loading, environment-variable handling, secrets
management, auth toggles, CORS, crypto choices, or debug/error-handling code - `kavach-config`
and `kavach-sast` lean on it most, but any domain agent can hit a fallback default mid-trace.

## The one-line test

**Fail-open (report it):** `SECRET = env.get('KEY') or 'default'` → the app **runs** insecurely
with a known/weak value when configuration is missing.

**Fail-secure (skip it):** `SECRET = env['KEY']` → the app **crashes** at startup when
configuration is missing. A crash is not a vulnerability - the operator finds out the moment they
deploy, not the moment they're breached.

Everything in this reference is one question applied over and over: **when the expected config is
absent, does the code keep running with a weaker posture, or does it stop?** Fail-open is the
finding. Fail-secure is not - even if the fallback value itself looks alarming, a value that is
never reached in a running process is not a live vulnerability.

## When this reference does NOT apply

Do not flag:

- **Test fixtures** explicitly scoped to test environments (`test/`, `spec/`, `__tests__/`).
- **Example/template files** (`.example`, `.template`, `.sample` suffixes).
- **Development-only tooling** (local Docker Compose for dev, debug scripts never shipped).
- **Documentation examples** in `README.md` or `docs/`.
- **Build-time configuration** that is guaranteed to be replaced before deployment - but verify
  this guarantee, don't take it on faith.
- **Crash-on-missing behavior** where the app genuinely will not start without proper config
  (fail-secure).

When in doubt, trace the code path to determine whether the app *runs* with the default or
*crashes*. Do not guess - read the line, per the persona's prime directive (`persona.md`).

## Rationalizations to reject

These are the excuses that let a fail-open default survive a review. Reject every one - they are
restatements of the persona's banned behaviors ("it probably validates this upstream" is how banks
get robbed):

| Rationalization | Why it fails |
|---|---|
| "It's just a development default." | If it reaches production code, it's a finding. Dev-only intent isn't a control. |
| "The production config overrides it." | Verify the prod config actually sets it. If you can't prove that, the code-level vulnerability stands. |
| "This would never run without proper config." | Prove it with a code trace - many apps fail silently and keep serving traffic. |
| "It's behind authentication." | Defense in depth, not a reason to skip. A compromised session still exploits the weak default underneath. |
| "We'll fix it before release." | Document now. "Later" rarely comes, and it is not your job to trust the roadmap. |

## Workflow

Apply this four-step loop to every candidate you find.

### 1. SEARCH - project discovery + pattern hunt

Determine language, framework, and project conventions first, then search `**/config/`,
`**/auth/`, `**/database/`, and env files with the regex catalog below. Tailor the search to what
discovery turned up - a Rails app's `credentials.rb` and a Node app's `process.env` calls need
different greps even though they're the same vulnerability class. Focus on production-reachable
code; test fixtures and example files are not findings (see above).

### 2. VERIFY - actual runtime behavior

For each match, trace the code path:

- When does this code execute - startup, or on every request?
- What happens when the configuration variable is genuinely missing?
- Is there validation elsewhere that enforces a secure configuration before this line is reached?

### 3. CONFIRM - production impact

- If the production config **provides** the variable → the code-level flaw still exists, but
  lower severity (defense-in-depth gap: the default is a landmine for the next deploy, not an
  active hole). Still report it - `confidence: confirmed`, but weigh it as such in the CVSS
  (typically the AC/PR metrics shift, not the underlying finding disappearing).
- If the production config is **missing the variable, or the deployment matches the default** →
  Critical/High per `severity-model.md`'s band table - this is a live fail-open in production.

### 4. REPORT - with evidence, per finding-schema.md

Every insecure-default finding follows the standard KAVACH shape - do not invent a separate report
format. At minimum:

- `locations`: the exact `file:line` of the fallback/default.
- `what_it_is`: the pattern (quote it).
- `how_exploited`: what happens when the env var is absent - "app starts without `JWT_SECRET`;
  falls back to `'dev-secret-key-123'` at line 42, used to sign tokens at line 58."
- `business_impact`: what the weak default lets an attacker do (forge tokens, connect as
  `admin/admin123`, read plaintext debug traces, etc).
- `confidence`: `confirmed` when you traced both that the app starts without the var *and* that
  the fallback value reaches a security-sensitive sink. `suspected` when you can show the fallback
  exists but can't confirm from static code whether the deployment ever hits it - name the runtime
  check ("confirm `JWT_SECRET` is set in every deploy target's env").
- `cvss_vector` / `severity`: score off the real exposure (network-reachable auth bypass via known
  secret often lands Critical - compare to the anchors in `severity-model.md`).

## Regex catalog (SEARCH step)

Search `**/config/`, `**/auth/`, `**/database/`, and env files for:

- **Fallback secrets:** `getenv\(.*\) or ['"]`, `process\.env\.[A-Z_]+ \|\| ['"]`,
  `ENV\.fetch.*default:`
- **Hardcoded credentials:** `password.*=.*['"][^'"]{8,}['"]`, `api[_-]?key.*=.*['"][^'"]+['"]`
- **Weak defaults:** `DEBUG.*=.*true`, `AUTH.*=.*false`, `CORS.*=.*\*`
- **Crypto algorithms:** `MD5|SHA1|DES|RC4|ECB` in security contexts (hashing passwords/tokens,
  encrypting data, verifying signatures - not checksums/cache keys, see below)

## Quick verification checklist

**Fallback secrets** - `SECRET = env.get(X) or Y`
→ Verify: does the app start without the env var? Is the fallback used in a crypto/auth sink?
→ Skip: test fixtures, example files.

**Default credentials** - hardcoded `username`/`password` pairs
→ Verify: is this account active in the deployed config, with no runtime override?
→ Skip: disabled accounts, documentation examples.

**Fail-open security toggle** - `AUTH_REQUIRED = env.get(X, 'false')`
→ Verify: is the default value itself insecure (false/disabled/permissive)?
→ Safe: the app crashes on missing config, or the default is secure (true/enabled/restricted).

**Weak crypto** - MD5/SHA1/DES/RC4/ECB in a security context
→ Verify: used for passwords, encryption keys, or tokens?
→ Skip: checksums, cache keys, non-security hashing.

**Permissive access** - CORS `*`, mode `0777`, public-by-default storage
→ Verify: does the default allow unauthorized access?
→ Skip: explicitly configured permissiveness with a documented justification.

**Debug features** - stack traces, introspection, verbose errors
→ Verify: enabled by default? Exposed in the actual HTTP response, not just logs?
→ Skip: logging-only output that never reaches the client.

## Examples and counter-examples

For each category: the vulnerable shape to report, and the secure shape to skip.

### Fallback secrets

**❌ Report - Python, environment variable with fallback**
```python
# src/auth/jwt.py
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-123')

def create_token(user_id):
    return jwt.encode({'user_id': user_id}, SECRET_KEY, algorithm='HS256')
```
The app runs with a known secret if `SECRET_KEY` is missing; an attacker forges tokens.

**❌ Report - JavaScript, logical-OR fallback**
```javascript
// config/database.js
const DB_PASSWORD = process.env.DB_PASSWORD || 'admin123';
const pool = new Pool({ user: 'admin', password: DB_PASSWORD, database: 'production' });
```
The database accepts a hardcoded password in production if the env var is missing.

**❌ Report - Ruby, `fetch` with default**
```ruby
# config/secrets.rb
Rails.application.credentials.secret_key_base =
  ENV.fetch('SECRET_KEY_BASE', 'fallback-secret-base')
```
Rails session encryption uses a weak known key as fallback.

**✅ Skip - fail-secure, crashes without config**
```python
SECRET_KEY = os.environ['SECRET_KEY']  # raises KeyError if missing - app won't start
```

**✅ Skip - explicit validation**
```javascript
if (!process.env.DB_PASSWORD) {
  throw new Error('DB_PASSWORD environment variable required');
}
const DB_PASSWORD = process.env.DB_PASSWORD;
```

**✅ Skip - test fixture, clearly scoped**
```python
# tests/fixtures/auth.py
TEST_SECRET = 'test-secret-key-123'  # OK - test-only
```

### Default credentials

**❌ Report - hardcoded admin bootstrap**
```python
# src/models/user.py
def bootstrap_admin():
    """Create default admin account if none exists"""
    if not User.query.filter_by(role='admin').first():
        admin = User(username='admin', password=hash_password('admin123'), role='admin')
        db.session.add(admin)
        db.session.commit()
```
A default admin account is created on first run with a known, unrotated password.

**❌ Report - API key fallback**
```javascript
// src/integrations/payment.js
const STRIPE_API_KEY = process.env.STRIPE_KEY || 'sk_tes...';
const stripe = require('stripe')(STRIPE_API_KEY);
```
Falls back to a test key if the env var is missing - and test keys leak into production more
often than teams expect.

**❌ Report - hardcoded connection string fallback**
```java
// DatabaseConfig.java
private static final String DB_URL = System.getenv().getOrDefault(
    "DATABASE_URL", "postgresql://admin:password@localhost:5432/prod");
```

**✅ Skip - admin creds must be explicitly configured**
```python
def bootstrap_admin():
    username = os.environ['ADMIN_USERNAME']
    password = os.environ['ADMIN_PASSWORD']
    if not User.query.filter_by(username=username).first():
        admin = User(username=username, password=hash_password(password), role='admin')
        db.session.add(admin)
```

**✅ Skip - example/doc credential, clearly labeled**
```
export STRIPE_KEY='sk_tes...'  # Example only, README.md
```

**✅ Skip - test fixture credential**
```python
@pytest.fixture
def test_user():
    return User(username='test_user', password='test_pass')  # OK - test scope
```

### Fail-open security toggles

**❌ Report - authentication disabled by default**
```python
# config/security.py
REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'false').lower() == 'true'

@app.before_request
def check_auth():
    if not REQUIRE_AUTH:
        return  # skip auth check
```
Default is *no authentication at all* if the env var is missing or misconfigured.

**❌ Report - CORS wide open by default**
```javascript
// server.js
const allowedOrigins = process.env.ALLOWED_ORIGINS || '*';
app.use(cors({ origin: allowedOrigins }));
```

**❌ Report - debug mode on by default**
```python
# config.py
DEBUG = os.getenv('DEBUG', 'true').lower() != 'false'  # default: true
if DEBUG:
    app.config['DEBUG'] = True
    app.config['PROPAGATE_EXCEPTIONS'] = True
```
Stack traces leak internals in production unless `DEBUG` is explicitly set to `'false'`.

**✅ Skip - auth required by default (or fail-secure)**
```python
REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'true').lower() == 'true'  # default: true
# or better - crash if not explicitly configured:
REQUIRE_AUTH = os.environ['REQUIRE_AUTH'].lower() == 'true'
```

**✅ Skip - CORS requires explicit config**
```javascript
if (!process.env.ALLOWED_ORIGINS) {
  throw new Error('ALLOWED_ORIGINS must be configured');
}
const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',');
```

**✅ Skip - debug off by default**
```python
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'  # default: false
```

### Weak crypto

**❌ Report - MD5 password hashing**
```python
# src/auth/passwords.py
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```
Cryptographically broken; rainbow tables exist. Use bcrypt/Argon2/scrypt.

**❌ Report - DES/ECB encryption**
```java
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
```
56-bit keys are brute-forceable; ECB leaks block patterns.

**❌ Report - SHA1 signature verification**
```javascript
// webhooks.js
function verifySignature(payload, signature) {
  const hmac = crypto.createHmac('sha1', WEBHOOK_SECRET);
  return hmac.update(payload).digest('hex') === signature;
}
```
SHA1 collisions exist; use SHA256 or better, and a constant-time compare.

**✅ Skip - weak hash used only for a non-security checksum**
```python
def cache_key(data):
    return hashlib.md5(data.encode()).hexdigest()  # OK - just a cache lookup key
```

**✅ Skip - modern password hashing**
```python
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

**✅ Skip - strong authenticated encryption**
```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");  // 256-bit key, authenticated
```

### Permissive access

**❌ Report - world-writable file**
```python
def create_secure_file(path):
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o666)  # rw-rw-rw-
    return fd
```

**❌ Report - public-by-default storage bucket**
```python
def create_storage_bucket(name):
    bucket = s3.create_bucket(Bucket=name, ACL='public-read')
```

**❌ Report - CORS allows any origin with credentials**
```python
@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```
Combining wildcard origin with credentials enables cross-site credential theft.

**✅ Skip - explicit, justified permissiveness**
```python
def create_public_asset(path):
    """Create world-readable asset for CDN distribution - intentionally public, static only"""
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o644)
    return fd
```

**✅ Skip - restrictive by default, opt-in to public with logging**
```python
def create_storage_bucket(name, public=False):
    acl = 'public-read' if public else 'private'
    if public:
        logger.warning(f'Creating PUBLIC bucket: {name}')
    bucket = s3.create_bucket(Bucket=name, ACL=acl)
```

### Debug features

**❌ Report - stack traces in API responses**
```python
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({'error': str(error), 'traceback': traceback.format_exc()}), 500
```
Leaks internal paths, library versions, and query structure to any caller.

**❌ Report - GraphQL introspection on in production**
```javascript
const server = new ApolloServer({ typeDefs, resolvers, introspection: true, playground: true });
```
Exposes the entire schema, including admin-only fields, to unauthenticated callers.

**❌ Report - verbose SQL errors surfaced to the client**
```java
catch (SQLException e) {
    return ResponseEntity.status(500).body("Database error: " + e.getMessage());
}
```

**✅ Skip - full detail logged, generic message to the user**
```python
@app.errorhandler(Exception)
def handle_error(error):
    logger.exception('Request failed', exc_info=error)  # full trace to logs
    return jsonify({'error': 'Internal server error'}), 500  # generic to caller
```

**✅ Skip - environment-aware debug settings**
```javascript
const server = new ApolloServer({
  typeDefs, resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production'
});
```

**✅ Skip - generic user-facing error, full detail to logs**
```java
catch (SQLException e) {
    logger.error("Database error", e);
    return ResponseEntity.status(500).body("Unable to process request");
}
```
