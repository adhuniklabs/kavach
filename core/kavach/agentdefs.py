"""Reading the `agents/` roster as data, so a harness does not have to parse markdown.

Every agent file is Claude Code subagent frontmatter plus a body. Two fields matter to a
non-Claude harness and one of them was Claude-shaped:

- `tools` names the capability set the dispatch must provide.
- `model` is `inherit | sonnet | haiku`, which encodes a real dispatch tier
  (judgement / bounded-mechanical / one-label) in one vendor's model names.

`tier` is that same decision spelled provider-neutrally. A file may declare it; when it
does not, it is derived from `model`, so the roster answers in tiers whether or not the
files have been annotated yet.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field

import yaml

from . import paths

REASONING = "reasoning"
MECHANICAL = "mechanical"
TRIAGE = "triage"

# `model:` stays for Claude Code, which reads these same files. Both spellings survive.
MODEL_TIER: dict[str, str] = {"inherit": REASONING, "sonnet": MECHANICAL, "haiku": TRIAGE}
TIERS: tuple[str, ...] = (REASONING, MECHANICAL, TRIAGE)


@dataclass(frozen=True)
class AgentDef:
    name: str
    description: str
    tools: tuple[str, ...]
    model: str
    tier: str
    path: str
    body: str = field(repr=False, default="")

    def as_dict(self, *, with_body: bool = False) -> dict:
        d = {"name": self.name, "description": self.description, "tools": list(self.tools),
             "model": self.model, "tier": self.tier, "path": self.path}
        if with_body:
            d["body"] = self.body
        return d


def split_frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---\n"):
        return {}, text
    _, fm, body = text.split("---\n", 2)
    return yaml.safe_load(fm) or {}, body


def _tools(raw) -> tuple[str, ...]:
    if isinstance(raw, list):
        return tuple(str(t).strip() for t in raw if str(t).strip())
    if isinstance(raw, str):
        return tuple(t.strip() for t in raw.split(",") if t.strip())
    return ()


def parse(path: str) -> AgentDef | None:
    with open(path, encoding="utf-8") as fh:
        fm, body = split_frontmatter(fh.read())
    name = fm.get("name")
    if not name:
        return None
    model = str(fm.get("model", "inherit"))
    tier = str(fm.get("tier") or MODEL_TIER.get(model, REASONING))
    return AgentDef(name=name, description=str(fm.get("description", "")),
                    tools=_tools(fm.get("tools")), model=model, tier=tier,
                    path=os.path.abspath(path), body=body)


def load_all(agents_dir: str | None = None) -> dict[str, AgentDef]:
    """Every agent in the roster, keyed by name. Empty when the roster is not installed."""
    base = agents_dir or paths.agents_dir()
    if base is None:
        return {}
    out: dict[str, AgentDef] = {}
    for path in sorted(glob.glob(os.path.join(base, "*.md"))):
        agent = parse(path)
        if agent is not None:
            out[agent.name] = agent
    return out


def get(name: str, agents_dir: str | None = None) -> AgentDef | None:
    return load_all(agents_dir).get(name)
