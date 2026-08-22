#!/usr/bin/env bash
# Install KAVACH as a Claude Code skill + subagents, in one of two modes:
#
#   ./install.sh global            # user-level  → ~/.claude/{skills,agents}   (available in every repo)
#   ./install.sh project [DIR]     # project     → DIR/.claude/{skills,agents}  (default DIR = cwd)
#   ./install.sh --dest DIR        # explicit    → DIR/{skills,agents}
#
# Flags --global / --project are accepted as aliases. With no mode, you are asked to pick.
# Bundles the Python core, the 7 standalone companion skills/, the full agents/ roster, and docs/
# into the installed skill so it is self-contained; runs `pip install` for the core's two deps
# (PyYAML, filelock) and, best-effort, the [report] extra (reportlab) for PDF reports.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=""; DEST=""; PROJECT_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    global|--global) MODE="global"; shift ;;
    project|--project) MODE="project"; shift
      if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then PROJECT_DIR="$1"; shift; fi ;;
    --dest) MODE="dest"; DEST="$2"; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$MODE" ]; then
  echo "Install KAVACH where?"
  echo "  1) global   → ~/.claude            (available in every repo on this machine)"
  echo "  2) project  → $(pwd)/.claude       (this project only; commit it to share with the team)"
  printf "Choose [1/2]: "; read -r choice
  case "$choice" in
    1) MODE="global" ;;
    2) MODE="project" ;;
    *) echo "aborted"; exit 1 ;;
  esac
fi

case "$MODE" in
  global)  DEST="$HOME/.claude" ;;
  project) DEST="${PROJECT_DIR:-$(pwd)}/.claude" ;;
  dest)    : ;;  # DEST already set
esac

SKILL_DIR="$DEST/skills/kavach"
AGENTS_DIR="$DEST/agents"
SKILLS_DIR="$DEST/skills"

echo "Installing KAVACH ($MODE) → $DEST"
mkdir -p "$SKILL_DIR" "$AGENTS_DIR" "$SKILLS_DIR"

# Skill (SKILL.md + references + docs), with the core bundled inside it so it is self-contained.
rm -rf "$SKILL_DIR/references" "$SKILL_DIR/core" "$SKILL_DIR/docs"
cp "$SRC/skill/SKILL.md" "$SKILL_DIR/SKILL.md"
cp -R "$SRC/skill/references" "$SKILL_DIR/references"
cp -R "$SRC/docs" "$SKILL_DIR/docs"
cp -R "$SRC/core" "$SKILL_DIR/core"
find "$SKILL_DIR/core" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true

# Install the core as a real package (editable-if-writable, so the corpus fixtures under
# core/corpus/ - a sibling of core/kavach/ - stay reachable at runtime; falls back to a plain
# install if pip refuses -e on this filesystem/venv).
if ! pip install --quiet -e "$SKILL_DIR/core" 2>/dev/null && \
   ! pip3 install --quiet -e "$SKILL_DIR/core" 2>/dev/null; then
  pip install --quiet "$SKILL_DIR/core" 2>/dev/null || pip3 install --quiet "$SKILL_DIR/core" 2>/dev/null || true
fi

# The [report] extra (reportlab) is what makes `kavach render --format pdf` work out of the box.
# Non-fatal on purpose: without it, md/json/sarif are unaffected, the HTML report substitutes a data
# table for each figure and still renders, and --format pdf exits with the install command rather
# than a traceback. A machine that cannot get reportlab still gets a working KAVACH.
REPORTLAB_OK=""
for attempt in "-e $SKILL_DIR/core[report]" "$SKILL_DIR/core[report]" "reportlab"; do
  # shellcheck disable=SC2086  # deliberate word splitting: the -e flag is part of the attempt
  if pip install --quiet $attempt 2>/dev/null || pip3 install --quiet $attempt 2>/dev/null; then
    REPORTLAB_OK="yes"; break
  fi
done

# Subagents (8 domain hunters + specialist/reasoning/chamber/validation/pipeline/confirm agents).
cp "$SRC"/agents/kavach-*.md "$AGENTS_DIR/"

# Standalone companion skills (codeql, threat-model, spec-compliance, variant-analysis,
# zeroize-audit, ci-agent-actions, semgrep-rule-creator).
for d in "$SRC"/skills/*/; do
  name="$(basename "$d")"
  rm -rf "$SKILLS_DIR/$name"
  cp -R "$d" "$SKILLS_DIR/$name"
done

echo "  skill:    $SKILL_DIR"
echo "  agents:   $(ls "$SRC"/agents/kavach-*.md | wc -l | tr -d ' ') subagents → $AGENTS_DIR"
echo "  skills:   $(ls -d "$SRC"/skills/*/ | wc -l | tr -d ' ') companion skills → $SKILLS_DIR"
echo "  docs:     $SKILL_DIR/docs"
if [ -n "$REPORTLAB_OK" ]; then
  echo "  pdf:      reportlab installed - 'kavach render --format pdf' is available"
else
  echo "  pdf:      reportlab NOT installed - PDF reports are unavailable on this machine."
  echo "            Everything else works (markdown/HTML/JSON/SARIF; HTML substitutes a data"
  echo "            table for each figure). To enable it later:"
  echo "              pip install 'kavach-audit[report]'    # or: pip install reportlab"
fi
echo
echo "Sanity check:"
PYTHONPATH="$SKILL_DIR/core" python3 -m kavach --version
if PYTHONPATH="$SKILL_DIR/core" python3 -m kavach corpus >/dev/null 2>&1; then
  echo "  corpus self-test: PASS"
else
  echo "  corpus self-test: FAIL (run: PYTHONPATH=\"$SKILL_DIR/core\" python3 -m kavach corpus)"
fi
if PYTHONPATH="$SKILL_DIR/core" python3 -c "import reportlab" >/dev/null 2>&1; then
  echo "  pdf renderer:     PASS (reportlab importable)"
else
  echo "  pdf renderer:     SKIP (reportlab not importable - PDF only; nothing else is affected)"
fi
echo
if [ "$MODE" = "project" ]; then
  echo "Done. Committed under $DEST, KAVACH is available to anyone who opens this repo in Claude Code."
else
  echo "Done. KAVACH is available in every repo on this machine."
fi
echo "Run  /kavach [mode]  at a repo root (default mode: balanced; or ask it to 'security-audit this codebase')."
echo "Requires: python3 + pip (installs PyYAML + filelock, and reportlab for PDF reports), and Docker for the full scanner suite (degrades gracefully without either)."
