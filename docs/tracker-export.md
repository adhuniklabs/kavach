# Tracker Export - filing KAVACH findings as GitHub issues

`core/kavach/issues.py` turns the promoted findings tree into tracker issues. It is the only
part of KAVACH that reaches outside the machine, so it is built to be boring: two explicit
phases, a plan you can read and edit before anything is created, idempotency on the stable
finding id, and a hard rule that a secret's value never leaves the local audit tree.

**GitHub is the only supported provider.** There is no Jira adapter in this cut - see
[Jira](#jira) below. There is no API-token path either: KAVACH shells out to the `gh` CLI you
have already authenticated and never handles a credential itself.

## The two phases

Creating issues in someone's tracker is outward-facing and hard to reverse, so it is never a
side effect of an audit. Nothing about `/kavach <mode>` files an issue.

```
kavach issues plan  --out .kavach [--severity critical --severity high] [--no-aggregates]
kavach issues push  --out .kavach --provider github --repo <owner/name> [--yes] [--label triage]
```

1. **plan** reads `findings/*/metadata.json`, `findings.json` and `recon.json`, and writes
   exactly one file: `.kavach/reports/issues.json`. It makes no network call and touches no
   tracker. Read it. Edit it. Delete the entries you don't want filed.
2. **push** reads that file back and, only when you pass `--yes`, creates or updates issues.
   Without `--yes` it is a dry run: it still runs the idempotency searches and renders every
   body, but executes no mutating `gh` command and writes nothing back.

`dry_run=True` is the default in the module signature, so the un-configured call is the safe
one. In the code there is a single chokepoint - `_gh()` - through which every `gh` invocation
passes; a mutating command under `dry_run` is recorded with `"executed": false` and never run.
The dry-run guarantee is asserted in `core/tests/test_issues.py` against the recorded command
list, not against a live `gh`.

## What gets exported

By default: every promoted finding directory whose severity is `critical` or `high`, plus the
`G*` aggregate directories (rolled-up dependency and IaC findings). Widen or narrow with
`--severity`; drop the aggregates with `--no-aggregates`. The severity filter applies to
aggregates too - a `medium` dependency roll-up is not exported unless you ask for `medium`.

Everything excluded is listed in the plan's `skipped[]` with a reason, so the plan accounts for
the whole tree rather than quietly shrinking it:

| Reason | Meaning |
|---|---|
| `marked false positive` | the directory is `FP-*`; a killed finding is never filed |
| `severity <x> not in [...]` | below the requested threshold |
| `aggregate excluded by include_aggregates=False` | `--no-aggregates` was passed |
| `no report.md - nothing disclosure-ready to post` | the reporter never ran for this finding |
| `report.md fails the report_finding contract` | the report is a stub: missing one of the five H2 sections, under 500 bytes, or pointing at a sibling draft |

The last two matter. An issue body is a disclosure document read by people who never see your
`.kavach/` tree, so KAVACH refuses to file a placeholder. Run the reporter phase, then re-plan.

## The plan file

`.kavach/reports/issues.json`:

```json
{
  "meta": {
    "target": "/repo/target", "commit": "deadbeef",
    "generated_at": "2026-08-21T09:14:02Z", "provider": "github",
    "severities": ["critical", "high"], "include_aggregates": true
  },
  "issues": [
    {
      "kavach_id": "KAVACH-7e3c775628",
      "display_id": "C1",
      "title": "[KAVACH C1] Four authorization controls are implemented but disabled by default",
      "labels": ["security", "kavach", "severity:critical"],
      "body_path": "findings/C1-four-authorization-controls/report.md",
      "severity": "critical",
      "finding_class": "reasoned",
      "existing_issue": null,
      "redacted": false,
      "is_aggregate": false,
      "member_count": 0,
      "cvss_score": 9.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "kill_chain": "read-others-data",
      "locations": ["src/authz/guards.py:118"],
      "remediation": "Flip the four defaults to deny and add a test per route.",
      "commit": "deadbeef"
    }
  ],
  "skipped": [{"display_id": "M1", "dir": "findings/M1-verbose-error-page",
               "reason": "severity medium not in ['critical', 'high']"}]
}
```

`body_path` is relative to the audit directory, so the file stays readable and portable.
`render_issue(entry)` needs an absolute path, so `read_plan()` re-derives one into `_body_abs`
when it loads the file; keys starting with `_` are hydration-only and never serialized.
`locations` carries `file:line` only - a `Location.snippet` is never copied into the plan.

For a `secret`-class entry `_body_abs` is `None` while `body_path` stays - see "Secret findings
are redacted, always" below for exactly what that does and does not guarantee.

The plan is meant to be edited between the two phases. Deleting an entry drops that issue.
Retitling one changes the issue title. Trimming `labels` avoids the most common `gh` failure
(see below). Do not edit `kavach_id`: it is the handle the next audit matches on.

## Idempotency - re-running an audit never duplicates issues

The key is `kavach_id`, never the title. `kavach_id` is `Finding.fingerprint()` - a sha1 over
category, normalized primary path, rule id and title - which **deliberately excludes the line
number** so it survives code movement. Titles get edited by humans; fingerprints don't.

Before creating anything, `push` searches:

```
gh issue list --repo <owner/name> --search "<kavach_id> in:body" --state all --json number,title,state
```

- **no hit** → `gh issue create` with the rendered body.
- **a hit** → `gh issue comment` with a short re-audit delta ("still open at `<commit>`",
  severity and display id this run, the local artifact path). No new issue, no re-post of the
  body.
- **an open hit and a closed hit** → the open one wins. A closed-only hit still counts as
  existing, so a regression comments on the closed issue instead of filing a second one beside
  it.

This is why the footer KAVACH appends to every body carries the `kavach_id` in plain text: it
is what makes the issue findable next time. If you strip it, the next audit files a duplicate.

After a real (non-dry) push, `issues.json` is rewritten with `existing_issue` populated, so the
file doubles as a record of what was filed.

## Secret findings are redacted, always

A finding whose `finding_class == "secret"` **never has its evidence pasted into an issue.** An
issue is readable by more people than the repository, and a pasted credential outlives its
rotation. The class covers gitleaks, TruffleHog, the built-in secret scanner, `rust_secret_apis`,
and - because `triage` keys the rule on `category == "A07:Secrets"` before it tests the dependency
rule - **trivy's secret rows**, which arrive with `source="trivy"`. There is no separate
`trivy-secret` scanner; a rule that looked for one would miss every trivy credential.

For those findings the body is synthesized from `file:line`, the class, and the remediation,
plus an explicit note that the value is withheld and names the local path where it lives. The
guarantee is structural, not a filter applied at the end. Stated precisely:

- **No evidence, no snippet and no matched value reaches an issue body.** The body is built from
  the entry's own fields, never from a file. `render_issue` branches on `redacted` before it
  computes anything.
- **`_body_abs` is `None`** for a secret entry, so the finding's `report.md` - the one artifact
  that may inline the credential - is never opened on the export path.
- The entry **does** keep the relative `body_path` (e.g. `findings/C2-…/report.md`), and the
  redacted body prints it as the local pointer to the withheld value. That is deliberate and it is
  not a leak: it is a path, not evidence; nothing reads it; the directory slug comes from the
  scanner's rule description or detector name, never from the matched value; and `issues.json`
  stays on the machine that ran the audit. If you would rather not publish even the path, delete
  the line from the entry before pushing - the plan file is editable for exactly this kind of call.
- The entry never carries `Location.snippet` - the one field a secret scanner fills with the
  credential itself.
- The finding's own `title` and `remediation` are scrubbed against every snippet on the finding
  before they enter the entry, because a `kavach-*` authored finding can quote the credential in
  its own prose. A match is replaced with `[withheld]`.

`core/tests/test_issues.py` asserts a sentinel credential written into the fixture's `report.md`,
`title` and `remediation` reaches neither the issue title nor the issue body.

The finding still gets filed - severity, location, class and remediation are exactly what a
responder needs, and the withheld value is one `cat` away for whoever holds the audit tree.
Treat any secret-class issue as an active incident: rotate first, then purge from git history,
then close.

## `gh` requirements and failure modes

`gh` must be on `PATH` and authenticated. If it is missing or unauthenticated, `push` returns a
clear error, writes nothing, and the CLI exits non-zero. There is no fallback route - KAVACH
will not post by API token, webhook, or anything else you did not configure yourself.

```
gh --version && gh auth status      # what push checks first
```

Every `gh` call runs through `subprocess` with a 60-second timeout and no shell, so a title or
body containing shell metacharacters is inert. Bodies are passed via `--body-file`, not `--body`,
so a long report cannot overflow the argument list.

**The most common real failure is a missing label.** `gh issue create --label kavach` fails if
the label does not exist in the target repo. Create them once:

```
gh label create kavach   --repo <owner/name> --color 5319e7 --description "Filed by KAVACH"
gh label create security --repo <owner/name> --color d73a4a
gh label create severity:critical --repo <owner/name> --color b60205
gh label create severity:high     --repo <owner/name> --color d93f0b
```

…or strip the `labels` arrays out of `issues.json` before pushing. `push` reports `gh`'s stderr
verbatim per entry and keeps going, so one bad label does not abort the rest of the run.

The result dict distinguishes what happened: `created[]`, `updated[]`, `skipped[]`, `errors[]`,
and `commands[]` (every `gh` argv, each flagged `mutating` and `executed`). `ok` is `True` only
when `errors` is empty.

## Python API

```python
from kavach import issues

plan = issues.plan(audit_dir, severities=("critical", "high"), include_aggregates=True)
path = issues.write_plan(audit_dir, plan)              # -> .kavach/reports/issues.json
plan = issues.read_plan(audit_dir)                     # re-hydrates body paths

title, body = issues.render_issue(plan["issues"][0])   # redacted entries synthesize the body
comment     = issues.render_comment(plan["issues"][0]) # the re-audit delta

result = issues.push_github(audit_dir, plan, repo="owner/name", dry_run=True, labels=[])
result = issues.push(audit_dir, plan, provider="github", repo="owner/name")
```

`render_issue` raises `IssuesError` when a non-redacted entry's body is missing - a hand-edited
plan pointing at a report that no longer exists fails loudly rather than filing an empty issue.
`push` raises `IssuesError` for an unknown provider.

## Jira

**Not supported.** There is no Jira adapter, no partial implementation, and no configuration
that makes one appear. `issues.PROVIDERS` is a one-row dispatch table (`{"github": push_github}`)
so adding one later is a single `push_jira(audit_dir, plan, *, project, dry_run, labels)`
function plus a row in that table - but until that function exists, `kavach issues push
--provider jira` raises an explicit error rather than silently doing nothing.

The pieces a Jira adapter would reuse unchanged: `plan()`, `write_plan()`, `read_plan()`,
`render_issue()` and the redaction rules. What it needs of its own is the idempotency search
(JQL over a `kavach_id` label or a custom field rather than `in:body`) and issue-type mapping.
