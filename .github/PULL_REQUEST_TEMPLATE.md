<!-- For security fixes, do not open a public PR - see SECURITY.md. -->

## What & why

<!-- What does this change, and what problem does it solve? -->

## Type

- [ ] New scanner adapter
- [ ] Bug fix
- [ ] New capability / coverage
- [ ] Skill / subagent change
- [ ] Docs / meta

## Checklist

- [ ] `cd core && python3 -m unittest discover -s tests` passes
- [ ] `PYTHONPATH=. python3 -m kavach corpus` passes (exit 0)
- [ ] New/changed detection has a fixture + a normalizer test (corpus grows with the detector)
- [ ] No invented CVE IDs; findings cite a scanner result or a concrete `file:line`
- [ ] Any new fixture secrets are fake and don't trip real provider detectors (push protection stays green)
- [ ] Docs updated if behavior/flags changed (`tool-catalog.md`, `README.md`)
