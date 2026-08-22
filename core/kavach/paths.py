"""Where the skill's non-Python assets live, from the engine's point of view.

The core is installed three different ways and the references/agents it must name in a
dispatch prompt sit in a different place each time:

    repo checkout          <repo>/core/kavach/     <repo>/skill/references/  <repo>/agents/
    install.sh             <skill>/core/kavach/    <skill>/references/       <skill>/../agents/
    pip install            site-packages/kavach/   - nothing bundled -

So resolution walks outward from the package and takes the first hit, with an env
override for the case the walk cannot cover (a pip install plus a checkout elsewhere).
Nothing here raises: an engine that cannot find the references still composes a prompt,
it just cannot name their absolute paths, and the caller is told which set is missing.
"""

from __future__ import annotations

import glob
import os

ENV_REFERENCES = "KAVACH_REFERENCES_DIR"
ENV_AGENTS = "KAVACH_AGENTS_DIR"


def _package_root() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _ancestors(levels: int = 4) -> list[str]:
    d = _package_root()
    out = []
    for _ in range(levels):
        d = os.path.dirname(d)
        out.append(d)
    return out


def _first_dir(candidates: list[str], sentinel: str) -> str | None:
    """The walk climbs four levels, which on a checkout reaches outside the project. A bare
    `isdir` would happily bind `~/Documents/agents` to the roster, so a directory only
    counts when it holds something only the real tree holds."""
    for c in candidates:
        if c and os.path.isdir(c) and glob.glob(os.path.join(c, sentinel)):
            return os.path.abspath(c)
    return None


def references_dir(env: dict[str, str] | None = None) -> str | None:
    """The `references/` tree SKILL.md's progressive disclosure reads from."""
    env = os.environ if env is None else env
    override = env.get(ENV_REFERENCES)
    if override:
        return os.path.abspath(override) if os.path.isdir(override) else None
    candidates = []
    for base in _ancestors():
        candidates += [os.path.join(base, "references"),
                       os.path.join(base, "skill", "references")]
    return _first_dir(candidates, "persona.md")


def agents_dir(env: dict[str, str] | None = None) -> str | None:
    """The `agents/` roster. install.sh lands it beside the skill, not inside it."""
    env = os.environ if env is None else env
    override = env.get(ENV_AGENTS)
    if override:
        return os.path.abspath(override) if os.path.isdir(override) else None
    candidates = []
    for base in _ancestors():
        candidates.append(os.path.join(base, "agents"))
    return _first_dir(candidates, "kavach-*.md")


def reference(name: str, env: dict[str, str] | None = None) -> str | None:
    """Absolute path of one reference file, or None when it is not on this machine.

    `name` is the path SKILL.md uses - `persona.md`, `domains/sast.md`.
    """
    base = references_dir(env)
    if base is None:
        return None
    path = os.path.join(base, name)
    return path if os.path.exists(path) else None
