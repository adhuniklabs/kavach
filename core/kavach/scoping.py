"""Which files a hunter should look at first, on a repo too big to look at all of.

`recon` writes `file-manifest.txt` - every file it walked - and nothing narrows it, so each
domain hunter is pointed at the whole tree. On a 70k-file monorepo that is not a budget
problem so much as an attention problem: the hunter spends its context deciding where to
start, and the files that decide the audit (the route that takes money, the middleware that
checks the session) are ranked no higher than a fixture.

Ranking is deterministic and path-shaped on purpose. No model, no content read: those cost
exactly what this exists to save, and a path like `src/api/billing/webhook.ts` already tells
you most of what a first pass needs. A high score is "look here first", never "the bug is
here" - the manifest stays available and nothing is hidden from a hunter that wants it.
"""

from __future__ import annotations

import json
import os
import re

# Path fragments that raise a file's security relevance whatever domain is asking, with the
# weight each is worth. Ordered by how often the fragment decides an audit rather than by how
# common it is: an auth boundary outranks a config file, which outranks a plain handler.
GENERIC_SIGNALS: tuple[tuple[str, int], ...] = (
    ("auth", 9), ("session", 8), ("login", 8), ("password", 8), ("token", 7), ("jwt", 7),
    ("permission", 8), ("authoriz", 8), ("admin", 7), ("rbac", 7), ("tenant", 7),
    ("middleware", 7), ("guard", 6), ("policy", 6),
    ("payment", 9), ("billing", 9), ("checkout", 8), ("stripe", 8), ("invoice", 7),
    ("subscription", 7), ("credit", 6), ("price", 6), ("refund", 6),
    ("webhook", 8), ("callback", 5),
    ("route", 6), ("router", 6), ("controller", 6), ("endpoint", 6), ("api", 5),
    ("handler", 4), ("resolver", 4), ("graphql", 5),
    ("upload", 6), ("download", 5), ("file", 3), ("exec", 6), ("shell", 6), ("command", 4),
    ("serial", 6), ("deserial", 7), ("pickle", 7), ("eval", 6), ("template", 4),
    ("query", 5), ("sql", 6), ("db", 4), ("database", 5), ("model", 3), ("repository", 3),
    ("crypto", 7), ("encrypt", 7), ("hash", 6), ("secret", 8), ("credential", 8), ("key", 5),
    ("config", 5), ("settings", 5), ("env", 5),
    ("prompt", 6), ("llm", 6), ("agent", 4), ("openai", 6), ("anthropic", 6), ("embedding", 4),
    ("cors", 6), ("csrf", 7), ("sanitiz", 6), ("validat", 5), ("escape", 5),
)

# What each domain hunter is actually looking for, on top of the generic signal. A domain with
# no entry (chamber, probe, verifier) is not narrowed - it works from findings, not from files.
DOMAIN_SIGNALS: dict[str, tuple[str, ...]] = {
    # "deserial" as well as "serial": matching is prefix-on-token, so "serial" alone never
    # reaches "deserializer" - which is the exact filename this hunter most wants to see.
    "kavach-sast": ("secret", "key", "token", "credential", "env", "query", "sql", "exec",
                    "shell", "command", "serial", "deserial", "eval", "template", "upload",
                    "render"),
    "kavach-api": ("route", "router", "controller", "endpoint", "api", "handler", "resolver",
                   "graphql", "auth", "session", "permission", "authoriz", "tenant", "admin",
                   "middleware", "guard"),
    "kavach-llm": ("prompt", "llm", "agent", "openai", "anthropic", "embedding", "chat",
                   "completion", "rag", "tool"),
    "kavach-billing": ("payment", "billing", "checkout", "stripe", "invoice", "subscription",
                       "credit", "price", "refund", "webhook", "usage", "quota", "plan",
                       "entitlement", "coupon"),
    "kavach-crypto": ("crypto", "encrypt", "hash", "password", "cipher", "tls", "cert",
                      "pii", "personal", "gdpr", "redact", "mask"),
    "kavach-supply": ("package", "requirements", "gemfile", "go.mod", "cargo", "pom", "lock",
                      "vendor", "postinstall", "setup.py", "dependency"),
    "kavach-config": ("config", "settings", "env", "docker", "compose", "terraform", "helm",
                      "k8s", "kubernetes", "nginx", "ci", "workflow", "pipeline", "cors",
                      "header", "csp"),
    "kavach-logic": ("workflow", "state", "status", "transition", "order", "cart", "queue",
                     "job", "worker", "race", "lock", "transaction", "idempot"),
}

# Deprioritised, never dropped. A test file can hold the credential; it just should not be
# where a hunter starts.
DAMPENERS: tuple[tuple[str, int], ...] = (
    ("test", -6), ("tests", -6), ("spec", -4), ("fixture", -6), ("mock", -5),
    ("__snapshots__", -8), ("example", -4), ("sample", -4), ("demo", -4), ("docs/", -5),
    ("migrations/", -3), ("locale", -6), ("i18n", -5), ("generated", -6), (".min.", -9),
    ("dist/", -8), ("node_modules", -12), ("vendor/", -8),
    # Vendored scaffolding: a tree the target ships *to* its users rather than runs. It reads
    # as application code to every path signal - `_bmad_template/.../review-prompts/*.md`
    # outranked the real prompt module for the LLM hunter until this landed.
    ("_template", -8), ("scaffold", -6), ("boilerplate", -6), ("skeleton", -5),
)

SOURCE_EXTENSIONS: tuple[str, ...] = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".java", ".kt", ".cs",
    ".rs", ".swift", ".scala", ".c", ".cc", ".cpp", ".h", ".hpp", ".vue", ".svelte",
)
# Not source, but a hunter that skips them misses whole finding classes.
CONFIG_EXTENSIONS: tuple[str, ...] = (
    ".yml", ".yaml", ".toml", ".ini", ".conf", ".tf", ".env", ".json", ".xml", ".properties",
)


_TOKEN = re.compile(r"[a-z0-9]+")
_SHORT = 3      # at or below this, a signal must be a whole path token


def _tokens(lowered: str) -> list[str]:
    return _TOKEN.findall(lowered)


def matches(lowered: str, tokens: list[str], frag: str) -> bool:
    """Signals match path *tokens*, not raw substrings.

    A plain `frag in path` reads `ci` out of "dependen**ci**es", `api` out of "r**api**d",
    `key` out of "mon**key**", `lock` out of "b**lock**list" - and a config hunter opening
    `auth/dependencies.py` because of a two-letter accident is worse than no ranking at all.
    So a short signal must be a whole token, and a longer one may prefix a token, which is
    what lets `authoriz` reach "authorization" and `deserial` reach "deserialize".

    Fragments carrying punctuation (`go.mod`, `docs/`, `.min.`) never survive tokenization, so
    they stay plain substring matches - they are distinctive enough not to collide.
    """
    if not frag.isalnum():
        return frag in lowered
    if len(frag) <= _SHORT:
        return frag in tokens
    return any(t.startswith(frag) for t in tokens)


def _hits(lowered: str, tokens: list[str], table) -> list[tuple[str, int]]:
    return [(frag, weight) for frag, weight in table if matches(lowered, tokens, frag)]


def domain_hits(path: str, agent: str | None) -> list[str]:
    lowered = path.lower()
    tokens = _tokens(lowered)
    return [frag for frag in DOMAIN_SIGNALS.get(agent or "", ())
            if matches(lowered, tokens, frag)]


def score(path: str, agent: str | None = None) -> tuple[int, list[str]]:
    """(score, the signals that produced it). Returning the reasons is not decoration - a
    ranking nobody can audit is one nobody will trust enough to act on."""
    lowered = path.lower()
    tokens = _tokens(lowered)
    total, why = 0, []

    for frag, weight in _hits(lowered, tokens, GENERIC_SIGNALS):
        total += weight
        why.append(frag)

    for frag in domain_hits(path, agent):
        total += 6
        why.append(f"{agent.split('-')[-1]}:{frag}")

    for frag, weight in _hits(lowered, tokens, DAMPENERS):
        total += weight
        why.append(f"-{frag.strip('/.')}")

    if lowered.endswith(SOURCE_EXTENSIONS):
        total += 3
    elif lowered.endswith(CONFIG_EXTENSIONS):
        total += 2
    else:
        total -= 4      # neither source nor config: an asset, a lockfile, a binary

    # Shallow files are entrypoints more often than deep ones, and an entrypoint is where an
    # unauthenticated attacker starts.
    total += max(0, 3 - lowered.count("/"))
    return total, sorted(set(why))


def rank(files: list[str], agent: str | None = None) -> list[dict]:
    """Domain first, then heat.

    Scoring alone does not do this. A generic score sums - `routers/sessions_auth.py` collects
    auth + session + route + api and reaches the high twenties - while a domain match adds one
    term, so on a real tree the LLM hunter and the config hunter were both handed the auth
    router at the top and their own files nowhere near it. Every hunter got the same list,
    which is the same as having no per-domain scope at all.

    So the sort is two-tier: files carrying this hunter's own signal come first, ordered by
    score, and everything else follows in score order. With no agent there is no first tier and
    it degrades to a plain ranking.
    """
    scored = []
    for path in files:
        value, why = score(path, agent)
        scored.append({"path": path, "score": value, "signals": why,
                       "domain": len(domain_hits(path, agent))})
    scored.sort(key=lambda e: (-min(e["domain"], 1), -e["score"], e["path"]))
    return scored


def read_manifest(audit_dir: str) -> list[str]:
    path = os.path.join(os.path.abspath(audit_dir), "file-manifest.txt")
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def artifact_name(agent: str | None) -> str:
    return f"scope-{agent}.json" if agent else "scope.json"


def write_scope(audit_dir: str, *, agent: str | None = None, limit: int = 200) -> dict:
    """Rank the manifest and land it under attack-surface/. `limit` caps what the hunter is
    pointed at, never what it may open."""
    files = read_manifest(audit_dir)
    ranked = rank(files, agent)
    capped = ranked[:limit] if limit else ranked
    payload = {
        "agent": agent,
        "total_files": len(files),
        "ranked": len(capped),
        "limit": limit,
        "note": ("Ranked by security relevance, highest first. This is where to start, not a "
                 "boundary: file-manifest.txt still holds every file and nothing here stops "
                 "you opening one that is not listed."),
        "files": capped,
    }
    d = os.path.join(os.path.abspath(audit_dir), "attack-surface")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, artifact_name(agent))
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return {"path": path, "total_files": len(files), "ranked": len(capped)}
