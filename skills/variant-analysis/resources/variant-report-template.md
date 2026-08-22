# Variant Analysis Tracking Doc

Scratch working doc - lives at `.kavach/tmp/variant-workspace/<original-finding-slug>/tracking.md`.
This is not the finding record; once a variant is confirmed/suspected it goes into the calling
agent's own `agent-<domain>.json` per `finding-schema.md`.

## Summary

| Field | Value |
|-------|-------|
| **Original Finding** | [kavach_id / draft slug] |
| **Analysis Date** | [DATE] |
| **Codebase** | [REPO/PROJECT] |
| **Variants Found** | [COUNT] |

## Original Vulnerability

**Root Cause:** [e.g., "User input reaches SQL query without parameterization"]

**Location:** `[path/to/file.py:LINE]` in `function_name()`

```python
# Vulnerable code
```

## Search Methodology

| Version | Pattern | Tool | Matches | TP | FP |
|---------|---------|------|---------|----|----|
| v1 | [exact] | ripgrep | 1 | 1 | 0 |
| v2 | [abstract] | semgrep | N | N | N |

**Final Pattern:**
```yaml
# Pattern used
```

## Findings

### Variant #1: [BRIEF_TITLE]

| Severity | CVSS Vector | Confidence |
|----------|-------------|------------|
| High | CVSS:3.1/... | confirmed |

**Location:** `[path/to/file.py:LINE]`

```python
# Vulnerable code
```

**Analysis:** [Why this is a true/false positive, and why its severity matches or differs from the original]

**Exploitability:**
- [ ] Reachable from external input
- [ ] User-controlled data
- [ ] No sanitization

---

<!-- Copy variant template above for additional findings -->

## False Positive Patterns

| Pattern | Count | Reason |
|---------|-------|--------|
| [pattern] | N | [why safe] |

## Recommendations

### Immediate
1. Fix variant in [location] - fold into the same `agent-<domain>.json` entry (or a linked one if severity differs)

### Preventive
1. Note the custom-rule gap (if any) so a targeted Semgrep/CodeQL rule can catch the next instance - see the domain reference's "custom-rule gaps" guidance

```yaml
# CI-ready rule, if one was produced
```
