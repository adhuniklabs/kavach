"""Phase 0 - deterministic reconnaissance.

Walks the whole tree, parses every manifest, and fingerprints the stack: languages,
frameworks, datastores, ORMs, auth, LLM providers, payment processors, cloud, and IaC.
The result (``recon.json``) is the shared map every subagent reads, and the file
manifest is the report's Appendix B - coverage proven by a script, not a model's claim.
"""

from __future__ import annotations

import json
import os
from typing import Any

IGNORE_DIRS = {
    ".git", "node_modules", "dist", "build", "out", ".next", ".nuxt", "target",
    "__pycache__", ".venv", "venv", "env", ".mypy_cache", ".pytest_cache", ".tox",
    "vendor", ".gradle", ".idea", ".vscode", "coverage", ".dmux", ".terraform",
    "bower_components", ".cache", "site-packages",
}

# Dot-directories are tool state by convention - an index, a cache, a virtualenv - and a walk
# that follows them puts generated binary into a manifest whose job is to prove source
# coverage (one `.codegraph/codegraph.db` measured 23 MB). They are skipped as a class rather
# than enumerated, because the next tool to invent one ships before we hear about it. These
# are the exceptions: configuration that ships with the repository and runs somewhere, which
# is exactly the surface an audit is there to read. Dot-*files* are untouched - `.env` is what
# a secret scanner exists for.
AUDITED_DOT_DIRS = {
    ".github", ".gitlab", ".circleci", ".buildkite", ".azure-pipelines", ".husky",
    ".devcontainer", ".docker", ".ebextensions", ".platform", ".well-known", ".config",
    ".aws", ".ssh", ".gnupg",
}

LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".rb": "Ruby", ".php": "PHP", ".java": "Java", ".kt": "Kotlin", ".cs": "C#",
    ".rs": "Rust", ".dart": "Dart", ".scala": "Scala", ".ex": "Elixir", ".exs": "Elixir",
    ".swift": "Swift", ".c": "C", ".cpp": "C++", ".cc": "C++", ".h": "C/C++",
}

CODE_EXTS = set(LANG_BY_EXT) | {".vue", ".svelte", ".yml", ".yaml", ".env", ".toml"}

MANIFEST_TYPES = {
    "package.json": "npm", "requirements.txt": "pip", "pyproject.toml": "python",
    "pipfile": "pipenv", "setup.py": "python", "go.mod": "go", "cargo.toml": "cargo",
    "composer.json": "composer", "gemfile": "bundler", "pom.xml": "maven",
    "build.gradle": "gradle", "build.gradle.kts": "gradle", "pubspec.yaml": "pub",
    "mix.exs": "hex",
}

# category -> {canonical name: [lowercase substrings that signal it]}
MARKERS: dict[str, dict[str, list[str]]] = {
    "frameworks": {
        "Django": ["django"], "Flask": ["flask"], "FastAPI": ["fastapi"],
        "Express": ["express"], "Next.js": ["next"], "NestJS": ["@nestjs", "nestjs"],
        "React": ["react"], "Vue": ["vue"], "Angular": ["@angular"], "Svelte": ["svelte"],
        "Spring": ["spring-boot", "springframework"], "Rails": ["rails", "railties"],
        "Laravel": ["laravel"], "Symfony": ["symfony"], "Gin": ["gin-gonic"],
        "Phoenix": ["phoenix"], "Actix": ["actix-web"],
    },
    "datastores": {
        "PostgreSQL": ["postgres", "psycopg", "pg8000", '"pg"', "node-postgres"],
        "MySQL": ["mysql", "mariadb"], "MongoDB": ["mongodb", "mongoose", "pymongo"],
        "Redis": ["redis", "ioredis"], "SQLite": ["sqlite"], "DynamoDB": ["dynamodb"],
        "Elasticsearch": ["elasticsearch", "@elastic"], "Cassandra": ["cassandra"],
    },
    "orms": {
        "Prisma": ["prisma"], "Sequelize": ["sequelize"], "TypeORM": ["typeorm"],
        "Drizzle": ["drizzle-orm"], "SQLAlchemy": ["sqlalchemy"], "Mongoose": ["mongoose"],
        "GORM": ["gorm.io"], "ActiveRecord": ["activerecord"], "Eloquent": ["eloquent"],
        "Hibernate": ["hibernate"],
    },
    "auth": {
        "jsonwebtoken": ["jsonwebtoken"], "jose": ['"jose"', "python-jose"],
        "PyJWT": ["pyjwt"], "Passport": ["passport"], "NextAuth": ["next-auth"],
        "Authlib": ["authlib"], "Devise": ["devise"], "Spring Security": ["spring-security"],
        "Clerk": ["@clerk", "clerk-sdk"], "Auth0": ["auth0"], "Firebase Auth": ["firebase-admin", "firebase/auth"],
        "Supabase Auth": ["@supabase"],
    },
    "llm_providers": {
        "Anthropic": ["anthropic", "@anthropic-ai"], "OpenAI": ["openai"],
        "Azure OpenAI": ["azure-openai", "@azure/openai", "azure.ai.openai"],
        "AWS Bedrock": ["bedrock"], "Google Vertex": ["vertexai", "@google-cloud/vertexai"],
        "Google Gemini": ["generativeai", "@google/genai", "google-genai"],
        "Cohere": ["cohere"], "Mistral": ["mistralai"], "LangChain": ["langchain"],
        "LlamaIndex": ["llama-index", "llama_index", "llamaindex"], "Ollama": ["ollama"],
        "HuggingFace": ["huggingface", "transformers"], "Replicate": ["replicate"],
    },
    "payment_processors": {
        "Stripe": ["stripe"], "Razorpay": ["razorpay"], "Paddle": ["paddle"],
        "LemonSqueezy": ["lemonsqueezy", "lemon-squeezy"], "Braintree": ["braintree"],
        "PayPal": ["paypal", "@paypal"], "Square": ["squareup", "square-connect"],
        "Adyen": ["adyen"], "Chargebee": ["chargebee"], "Recurly": ["recurly"],
    },
    "cloud": {
        "AWS": ["aws-sdk", "boto3", "botocore", "@aws-sdk"], "Azure": ["@azure", "azure-sdk-for"],
        "GCP": ["@google-cloud", "google-cloud-"], "Firebase": ["firebase"],
        "Vercel": ["vercel", "@vercel"], "Netlify": ["netlify"],
        "Cloudflare": ["cloudflare", "wrangler"], "Supabase": ["supabase"],
    },
}


def _walkable(name: str) -> bool:
    return name in AUDITED_DOT_DIRS if name.startswith(".") else name not in IGNORE_DIRS


def _is_manifest(name: str) -> str | None:
    low = name.lower()
    if low in MANIFEST_TYPES:
        return MANIFEST_TYPES[low]
    if low.endswith(".csproj"):
        return "dotnet"
    return None


def _extract_deps(mtype: str, text: str) -> list[str]:
    deps: list[str] = []
    try:
        if mtype == "npm":
            obj = json.loads(text)
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                deps.extend((obj.get(key) or {}).keys())
        elif mtype == "composer":
            obj = json.loads(text)
            for key in ("require", "require-dev"):
                deps.extend((obj.get(key) or {}).keys())
        elif mtype == "pip":
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "-")):
                    deps.append(line.split("==")[0].split(">=")[0].split("[")[0].strip())
        elif mtype == "bundler":
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("gem "):
                    deps.append(line.split()[1].strip("\"',"))
        elif mtype == "go":
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(("module", "go ", "require", ")", "//")):
                    deps.append(line.split()[0])
    except (json.JSONDecodeError, IndexError, ValueError):
        pass
    return [d for d in deps if d]


def _match_markers(haystack: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for category, table in MARKERS.items():
        hits = sorted(
            name for name, subs in table.items()
            if any(sub in haystack for sub in subs)
        )
        if hits:
            out[category] = hits
    return out


def run_recon(root: str, *, max_code_scan: int = 400, max_read_bytes: int = 4000) -> tuple[dict[str, Any], list[str]]:
    root = os.path.abspath(root)
    files: list[str] = []
    by_ext: dict[str, int] = {}
    by_lang: dict[str, int] = {}
    manifests: list[dict[str, Any]] = []
    secret_surfaces: list[str] = []
    iac = {"dockerfiles": [], "compose": [], "terraform": [], "k8s": [], "ci": [], "helm": []}
    haystack_parts: list[str] = []
    code_scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if _walkable(d)]
        for name in filenames:
            abspath = os.path.join(dirpath, name)
            rel = os.path.relpath(abspath, root)
            files.append(rel)
            low = name.lower()
            _, ext = os.path.splitext(low)
            by_ext[ext] = by_ext.get(ext, 0) + 1
            if ext in LANG_BY_EXT:
                by_lang[LANG_BY_EXT[ext]] = by_lang.get(LANG_BY_EXT[ext], 0) + 1
            haystack_parts.append(low)

            mtype = _is_manifest(name)
            if mtype:
                text = _read(abspath, 200_000)
                manifests.append({"file": rel, "type": mtype, "dependencies": _extract_deps(mtype, text)})
                haystack_parts.append(text.lower())

            if low.startswith(".env") or low.startswith("appsettings") or low in {"settings.py"} \
                    or low.startswith("application.") or low.startswith("application-"):
                secret_surfaces.append(rel)
                haystack_parts.append(_read(abspath, max_read_bytes).lower())

            if low == "dockerfile" or low.startswith("dockerfile."):
                iac["dockerfiles"].append(rel)
            elif low.startswith("docker-compose") and low.endswith((".yml", ".yaml")):
                iac["compose"].append(rel)
            elif low.endswith((".tf", ".tfvars")):
                iac["terraform"].append(rel)
            elif low == "chart.yaml":
                iac["helm"].append(rel)
            elif f"{os.sep}.github{os.sep}workflows{os.sep}" in abspath or low == ".gitlab-ci.yml":
                iac["ci"].append(rel)

            if ext in CODE_EXTS and code_scanned < max_code_scan:
                snippet = _read(abspath, max_read_bytes)
                haystack_parts.append(snippet.lower())
                code_scanned += 1
                if _looks_like_k8s(snippet):
                    iac["k8s"].append(rel)

    haystack = "\n".join(haystack_parts)
    markers = _match_markers(haystack)
    languages = sorted(by_lang, key=lambda k: by_lang[k], reverse=True)

    recon: dict[str, Any] = {
        "root": root,
        "totals": {"files": len(files), "code_files": sum(by_lang.values()),
                   "by_language": by_lang, "by_extension": dict(sorted(by_ext.items()))},
        "languages": languages,
        "manifests": manifests,
        "frameworks": markers.get("frameworks", []),
        "datastores": markers.get("datastores", []),
        "orms": markers.get("orms", []),
        "auth": markers.get("auth", []),
        "llm_providers": markers.get("llm_providers", []),
        "payment_processors": markers.get("payment_processors", []),
        "cloud": markers.get("cloud", []),
        "iac": {k: sorted(v) for k, v in iac.items()},
        "secret_surfaces": sorted(secret_surfaces),
        "capabilities": {
            "has_python": "Python" in languages,
            "has_node": any(l in languages for l in ("JavaScript", "TypeScript")),
            "has_go": "Go" in languages,
            "has_ruby": "Ruby" in languages,
            "has_php": "PHP" in languages,
            "has_java": any(l in languages for l in ("Java", "Kotlin")),
            "has_dockerfile": bool(iac["dockerfiles"]),
            "has_iac": bool(iac["terraform"] or iac["k8s"] or iac["helm"]),
            "has_lockfiles": _has_lockfiles(files),
            "has_llm": bool(markers.get("llm_providers")),
            "has_payments": bool(markers.get("payment_processors")),
        },
    }
    return recon, sorted(files)


def _read(path: str, limit: int) -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _looks_like_k8s(text: str) -> bool:
    head = text[:600]
    return "apiVersion:" in head and ("kind: Deployment" in head or "kind: Service" in head
                                      or "kind: Pod" in head or "kind: Ingress" in head)


def _has_lockfiles(files: list[str]) -> bool:
    lock = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
            "pipfile.lock", "go.sum", "cargo.lock", "composer.lock", "gemfile.lock"}
    return any(os.path.basename(f).lower() in lock for f in files)
