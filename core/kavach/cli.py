"""KAVACH core CLI - the deterministic harness spine.

    python -m kavach recon    [path] [--out DIR]
    python -m kavach sweep    [path] [--out DIR]
    python -m kavach scan     [path] [--out DIR] [--format md] [--output PATH]
    python -m kavach triage   --out DIR                          # classify finding_class
    python -m kavach merge    --out DIR --extra findings.json ...  # fold in subagent findings
    python -m kavach render   --out DIR --format md|json|sarif|html|pdf [--output PATH]
    python -m kavach gate     --out DIR [--controls controls.json] [--severity-only]
    python -m kavach coverage --phase poc|report --out DIR       # per-finding phase gates
    python -m kavach budget   show|check|charge --out DIR        # the dispatch ledger
    python -m kavach issues   plan|push --out DIR                # tracker export (gated)
    python -m kavach corpus                                      # self-validation gate

Human/progress text goes to stderr; stdout carries the machine artifact for json/sarif.
Exit codes: 0 clean · 2 open Critical · 3 open High · 4 gate fail · 5 tooling error ·
6 corpus fail · 7 policy not met (coverage incomplete / budget exhausted).
"""

from __future__ import annotations

import argparse
import glob
import gzip
import json
import os
import shutil
import subprocess
import sys
import time

from . import __version__, flags
from .finding import Finding, dump_findings, load_findings
from .recon import run_recon
from .render import ReportlabMissing, render as render_report
from .score import exit_code, gate as run_gate
from .sweep import run_sweep


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _out_dir(args) -> str:
    d = os.path.abspath(args.out)
    os.makedirs(d, exist_ok=True)
    return d


def _write_text(path: str, text: str) -> str:
    """Write a rendered artifact, creating its parent - every deliverable now lands under
    .kavach/reports/, which the caller should not have to mkdir first."""
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _audit_id(out: str) -> str | None:
    from . import state
    run = state.latest_audit(out)
    return None if run is None else run.audit_id


def _empty_recon() -> dict:
    """Safe stand-in for render() when recon.json was never written - merge/longshot/
    revisit can reach a report phase without a core:recon pass in their own audit dir.
    Every renderer reads recon fields via .get() with its own fallback, so an empty stack
    fingerprint here just means an honest "unknown stack" report, not a crash."""
    return {
        "root": "", "totals": {"files": 0, "code_files": 0, "by_language": {}, "by_extension": {}},
        "languages": [], "manifests": [], "frameworks": [], "datastores": [], "orms": [],
        "auth": [], "llm_providers": [], "payment_processors": [], "cloud": [],
        "iac": {"dockerfiles": [], "compose": [], "terraform": [], "k8s": [], "ci": [], "helm": []},
        "secret_surfaces": [],
        "capabilities": {
            "has_python": False, "has_node": False, "has_go": False, "has_ruby": False,
            "has_php": False, "has_java": False, "has_dockerfile": False, "has_iac": False,
            "has_lockfiles": False, "has_llm": False, "has_payments": False,
        },
    }


def _load_recon(out: str) -> dict:
    path = os.path.join(out, "recon.json")
    if not os.path.exists(path):
        return _empty_recon()
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def cmd_recon(args) -> int:
    out = _out_dir(args)
    _log(f"KAVACH recon → {args.path}")
    recon, files = run_recon(args.path)
    with open(os.path.join(out, "recon.json"), "w", encoding="utf-8") as fh:
        json.dump(recon, fh, indent=2)
    with open(os.path.join(out, "file-manifest.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(files) + "\n")
    t = recon["totals"]
    _log(f"  {t['files']} files · languages: {', '.join(recon['languages']) or 'none'}")
    _log(f"  LLM: {', '.join(recon['llm_providers']) or '-'} · "
         f"payments: {', '.join(recon['payment_processors']) or '-'}")
    return 0


def cmd_sweep(args) -> int:
    out = _out_dir(args)
    recon = _load_recon(out) if os.path.exists(os.path.join(out, "recon.json")) \
        else _run_recon_inline(args, out)
    from .scanners import applicable_scanners
    names = [s.id for s in applicable_scanners(recon)]
    _log(f"KAVACH sweep → {len(names)} applicable scanner(s): {', '.join(names)}")
    result = run_sweep(recon["root"], recon)
    dump_findings(result.findings, os.path.join(out, "findings.json"),
                  meta={"phase": "sweep", "version": __version__})
    with open(os.path.join(out, "sweep-summary.json"), "w", encoding="utf-8") as fh:
        json.dump(result.summary(), fh, indent=2)
    for o in result.outcomes:
        _log(f"  {o.scanner_id:14} {o.status:12} {len(o.findings):>3} findings"
             + (f"  ({o.message})" if o.message else ""))
    if result.unavailable:
        _log(f"  degraded (no tool): {', '.join(result.unavailable)} - subagents review these manually")
    return 0


def cmd_merge(args) -> int:
    out = _out_dir(args)
    base = os.path.join(out, "findings.json")
    findings: list[Finding] = load_findings(base) if os.path.exists(base) else []
    for extra in args.extra or []:
        findings.extend(load_findings(extra))
    from .sweep import dedupe
    merged = dedupe(findings)
    dump_findings(merged, base, meta={"phase": "merge", "version": __version__})
    _log(f"KAVACH merge → {len(merged)} findings after dedupe")
    return 0


def cmd_merge_run(args) -> int:
    from . import merge_findings as mf
    from .findings_tree import consolidate
    out = _out_dir(args)
    dirs = [os.path.abspath(d) for d in (args.dir or [])]
    if len(dirs) < 2:
        _log("KAVACH merge-run → need at least 2 --dir sources")
        return 5

    index = mf.index_sources(out, dirs)                                      # MG1
    workspace = os.path.join(out, "tmp", "merge-workspace")
    merged = load_findings(os.path.join(workspace, "findings-merged.json"))
    merged, dedup_notes = mf.apply_dedup_decisions(out, merged)               # MG2, if run
    ordered = mf.severity_renumber(merged)                                    # MG5 basis

    promoted = consolidate(out, ordered)                                      # MG6
    renames = mf.rename_map(dirs, promoted)                                   # MG5 artifact
    mf.write_rename_map(out, renames)
    mf.merge_summary(out, {"sources": index["sources"], "renames": renames, "dedup": dedup_notes})

    _log(f"KAVACH merge-run → {len(dirs)} source(s), {index['merged_count']} merged, "
        f"{len(dedup_notes)} chamber-deduped, {len(promoted)} promoted, {len(renames)} renamed")
    return 0


def _cover_date(explicit: str) -> str:
    """Today in UTC unless the operator pinned a date. The cover always carries one."""
    return explicit or time.strftime("%Y-%m-%d", time.gmtime())


def _cover_commit(explicit: str, out: str) -> str:
    """The commit the audit recorded, then the audited tree's HEAD, then nothing.

    The recorded commit outranks live HEAD because the cover describes the tree the finding set
    was produced against: a tree that has moved on since `state complete` would otherwise put a
    commit on page 1 that the audit never saw, and a wrong provenance is worse than a missing
    one. `state init` leaves the commit null, so an in-progress run still falls through to HEAD
    and gets the tree it is scanning - and it is the newest record *carrying* a commit that
    answers, so a later null-commit record cannot shadow an earlier completed one.

    HEAD is resolved against the parent of the audit dir rather than the process cwd, so
    rendering a report for a checkout elsewhere cannot stamp *this* tree's HEAD onto its cover.
    An empty string is the honest answer for a target with neither git nor a record - the
    renderers print "not recorded" and no commit is invented.
    """
    if explicit:
        return explicit
    from . import state
    recorded = next((a.commit for a in reversed(state.load_state(out).audits) if a.commit), None)
    head = _git_head(os.path.dirname(out) or None)
    if recorded and head and head != recorded:
        _log(f"  cover commit {recorded} is the one the audit recorded; the working tree has "
             f"since moved to {head}")
    return recorded or head or ""


def cmd_render(args) -> int:
    out = _out_dir(args)
    if args.format == "pdf" and not args.output:
        _log("KAVACH render → --format pdf needs --output PATH (a PDF is bytes, not stdout)")
        return 5
    recon = _load_recon(out)
    findings = load_findings(os.path.join(out, "findings.json"))
    controls = _load_controls(args)
    gate = run_gate(findings, controls, require_controls=not args.severity_only)
    # audit_dir is what unlocks the Limits section (budget.shed + coverage gaps), the promoted
    # display ids, and attack-surface/narrative.json - without it the report silently drops
    # the record of what this run did not do.
    meta = {"version": __version__, "date": _cover_date(args.date),
            "commit": _cover_commit(args.commit, out),
            "mode": args.mode, "audit_dir": out, "output": args.output}
    if controls:
        meta["controls"] = controls
    narrative = _load_narrative(args)
    if narrative is not None:
        meta["narrative"] = narrative
    try:
        text = render_report(args.format, findings, recon, gate, meta=meta)
    except ReportlabMissing as exc:
        _log(str(exc))          # the message already carries the pip command
        return 5
    if args.format == "pdf":
        _log(text)              # pdf.render() wrote the file; text is its summary line
    elif args.output:
        _write_text(args.output, text)
        _log(f"KAVACH render → {args.output} ({args.format})")
    else:
        print(text)
    return 0


def cmd_triage(args) -> int:
    from . import triage
    out = _out_dir(args)
    path = os.path.join(out, "findings.json")
    findings = triage.classify_all(load_findings(path))
    dump_findings(findings, path, meta={"phase": "triage", "version": __version__})
    counts = {cls: 0 for cls in triage.CLASSES}
    for f in findings:
        counts[f.finding_class] += 1
    _log(f"KAVACH triage → {len(findings)} finding(s) classified")
    for cls in triage.CLASSES:
        aggregated = " (aggregated)" if cls in triage.AGGREGATE_CLASSES else ""
        _log(f"  {cls:11} {counts[cls]:>4}{aggregated}")
    print(json.dumps({"total": len(findings), "by_class": counts}, indent=2))
    return 0


def cmd_coverage(args) -> int:
    from . import coverage
    out = _out_dir(args)
    path = coverage.write_coverage(out, args.phase)
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    print(json.dumps(report, indent=2))
    _log(f"KAVACH coverage {args.phase} → {report['satisfied']}/{report['total']} satisfied "
         f"({report['aggregates_exempt']} aggregate(s) exempt, scoped by "
         f"{report['scoped_by']}) → {os.path.relpath(path, out)}")
    if report["stale"]:
        # Loud on stderr, not only in the JSON: N directories from an earlier run silently
        # not gating is exactly the kind of thing that should not be silent.
        reasons = sorted({s["reason"] for s in report["stale_dirs"]})
        _log(f"  {report['stale']} stale dir(s) excluded from this gate ({', '.join(reasons)})"
             " - `kavach consolidate --prune-stale` moves them to findings-stale/")
    if report["complete"]:
        return 0
    for m in report["missing"]:
        _log(f"  ✗ {m['display_id']} - {m['reason']}")
    return 7


def cmd_budget(args) -> int:
    from . import budget
    out = _out_dir(args)
    if args.budget_cmd == "show":
        print(json.dumps(budget.show(out), indent=2))
        return 0
    if not args.phase:
        _log(f"KAVACH budget {args.budget_cmd} → --phase is required")
        return 5
    audit_id = _audit_id(out)
    if audit_id is None:
        _log("KAVACH budget → no audit in this dir; run `kavach state init` first")
        return 5
    if args.budget_cmd == "check":
        if args.planned is None:
            _log("KAVACH budget check → --planned N is required")
            return 5
        decision = budget.check(out, audit_id, args.phase, args.planned)
        print(json.dumps({"allowed": decision.allowed, "dropped": decision.dropped,
                          "reason": decision.reason}, indent=2))
        _log(f"KAVACH budget check {args.phase} → {decision.allowed}/{args.planned} allowed "
             f"({decision.reason})")
        return 0 if decision.allowed == args.planned else 7
    if args.count is None:
        _log("KAVACH budget charge → -n N is required")
        return 5
    ledger = budget.charge(out, audit_id, args.phase, args.count)
    print(json.dumps(ledger, indent=2))
    _log(f"KAVACH budget charge {args.phase} +{args.count} → {ledger['dispatches']} "
         f"dispatch(es) spent of {ledger['max_dispatches'] or 'unlimited'}")
    return 0


def cmd_issues(args) -> int:
    from . import issues
    out = _out_dir(args)
    try:
        if args.issues_cmd == "plan":
            plan = issues.plan(out, severities=tuple(args.severity or ("critical", "high")),
                               include_aggregates=not args.no_aggregates)
            path = issues.write_plan(out, plan)
            redacted = sum(1 for e in plan["issues"] if e.get("redacted"))
            _log(f"KAVACH issues plan → {path}")
            _log(f"  {len(plan['issues'])} issue(s) planned · {len(plan['skipped'])} skipped "
                 f"· {redacted} secret-class entry(ies) redacted to file:line")
            return 0
        if not args.repo:
            _log("KAVACH issues push → --repo <owner/name> is required")
            return 5
        if not os.path.exists(issues.plan_path(out)):
            _log("KAVACH issues push → no plan on disk; run `kavach issues plan` first")
            return 5
        plan = issues.read_plan(out)
        redacted = sum(1 for e in plan["issues"] if e.get("redacted"))
        _log(f"KAVACH issues push → {args.provider}:{args.repo} · "
             f"{len(plan['issues'])} planned entry(ies), {redacted} secret-class redacted · "
             + ("LIVE (--yes given)" if args.yes else "DRY RUN"))
        result = issues.push(out, plan, provider=args.provider, repo=args.repo,
                             dry_run=not args.yes, labels=args.label or [])
    except issues.IssuesError as exc:
        _log(str(exc))
        return 5
    for c in result["commands"]:
        if c["mutating"] and not c["executed"]:
            _log("  would run: " + " ".join(c["argv"]))
    _log(f"  created {len(result['created'])} · updated {len(result['updated'])} · "
         f"skipped {len(result['skipped'])} · errors {len(result['errors'])}"
         + ("  [dry run - nothing was created; pass --yes to apply]"
            if result["dry_run"] else ""))
    for e in result["errors"]:
        _log(f"  ✗ {e}")
    return 0 if result["ok"] else 5


def cmd_gate(args) -> int:
    out = _out_dir(args)
    findings = load_findings(os.path.join(out, "findings.json"))
    controls = _load_controls(args)
    gate = run_gate(findings, controls, require_controls=not args.severity_only)
    print(json.dumps(gate.to_dict(), indent=2))
    verdict = "PRODUCTION-READY" if gate.passed else "NOT PRODUCTION-READY"
    _log(f"KAVACH gate → {verdict}")
    for b in gate.blockers:
        _log(f"  ✗ {b}")
    return exit_code(gate)


def cmd_scan(args) -> int:
    rc = cmd_recon(args)
    if rc:
        return rc
    rc = cmd_sweep(args)
    if rc:
        return rc
    if args.format:
        out = _out_dir(args)
        recon = _load_recon(out)
        findings = load_findings(os.path.join(out, "findings.json"))
        gate = run_gate(findings, require_controls=False)
        args.severity_only = True
        text = render_report(args.format, findings, recon, gate,
                             meta={"version": __version__, "audit_dir": out,
                                   "date": _cover_date(""),
                                   "commit": _cover_commit("", out)})
        # KAVACH_SECURITY_REPORT.<ext> is retired and no longer written. scan also picks no
        # default path of its own: reports/final-audit-report.md is a phase gate, and a
        # standalone scan pre-satisfying it would stop the report phase from ever running.
        if args.output:
            _write_text(args.output, text)
            _log(f"KAVACH scan → {args.output} ({args.format})")
        else:
            print(text)
    return 0


def cmd_corpus(args) -> int:
    from .corpus import run_corpus_gate
    return run_corpus_gate()


def cmd_state(args) -> int:
    from . import modes, state
    out = _out_dir(args)
    if args.state_cmd == "init":
        from . import budget as budget_mod
        run = state.init_audit(out, args.mode, modes.phases_for(args.mode),
                               repository=getattr(args, "repository", "") or "")
        ledger = budget_mod.init_budget(out, run.audit_id, args.mode,
                                        max_dispatches=args.budget,
                                        max_wall_seconds=args.max_wall_seconds)
        _log(f"KAVACH state → new {args.mode} audit {run.audit_id}")
        _log(f"  budget: {ledger['max_dispatches'] or 'unlimited'} dispatch(es) · "
             f"{ledger['max_wall_seconds'] or 'unlimited'} wall second(s)")
        return 0
    if args.state_cmd == "complete":
        commit = args.commit or _git_head()
        run = state.complete_audit(out, commit)
        if run is None:
            _log("KAVACH state complete → no in-progress audit to mark complete")
            return 5
        baseline = _snapshot_findings_baseline(out, run.commit)
        note = f"baseline {os.path.basename(baseline)}" if baseline else "no baseline snapshotted"
        _log(f"KAVACH state complete → {run.audit_id} @ {run.commit or 'no-git'} · {note}")
        return 0
    run = state.latest_audit(out)
    print(json.dumps({} if run is None else {
        "audit_id": run.audit_id, "mode": run.mode, "status": run.status,
        "phases": {p: ph.status for p, ph in run.phases.items()},
    }, indent=2))
    return 0


def _git_head(cwd: str | None = None) -> str | None:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                                text=True, timeout=10, cwd=cwd)
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _snapshot_findings_baseline(out: str, commit: str | None) -> str | None:
    """Gzipped. The plain copy was byte-identical to findings.json - 520 KB of
    duplicate on the audited run - and there is one per completed audit, forever.
    diffing.baseline_path() still resolves a .json written by an earlier release."""
    if not commit:
        return None
    src = os.path.join(out, "findings.json")
    if not os.path.exists(src):
        return None
    d = os.path.join(out, "attack-surface")
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, f"findings-baseline-{commit}.json.gz")
    with open(src, "rb") as fh_in, gzip.open(dest, "wb") as fh_out:
        shutil.copyfileobj(fh_in, fh_out)
    return dest


def cmd_plan(args) -> int:
    from . import runner
    out = _out_dir(args)
    for phase in runner.next_actionable(out, args.mode):
        print(phase)
    return 0


def cmd_phase_prompt(args) -> int:
    from . import dispatch, modes
    out = _out_dir(args)
    body = f"Execute phase {args.phase} ({modes.PHASE_LABELS.get(args.phase, args.phase)})."
    print(dispatch.compose_prompt(args.mode, args.phase, body, out, args.target,
                                  modes.gate_for(args.phase),
                                  agent=args.agent, index=args.index))
    return 0


def cmd_ingest(args) -> int:
    from . import dispatch
    out = _out_dir(args)
    results = ([args.result] if args.result
               else sorted(glob.glob(dispatch.result_glob(out, args.phase))))
    if not results:
        _log(f"KAVACH ingest → no result file under "
             f"{dispatch.result_glob(out, args.phase)} (pass --result to name one)")
        return 5
    total = 0
    for path in results:
        n = dispatch.ingest(out, args.phase, path)
        total += n
        _log(f"  {os.path.relpath(path, out)} → {n} draft(s)")
    _log(f"KAVACH ingest → {total} draft(s) from {len(results)} result file(s)")
    return 0


def cmd_consolidate(args) -> int:
    from . import findings_tree
    out = _out_dir(args)
    findings = load_findings(os.path.join(out, "findings.json"))
    dirs = findings_tree.consolidate(out, findings)
    _log(f"KAVACH consolidate → {len(dirs)} finding dir(s)")
    if args.prune_stale:
        # A move, never a delete: findings/ is audit evidence, and findings-stale/ is durable.
        moved = findings_tree.prune_stale(out, findings)
        _log(f"  pruned {len(moved)} stale dir(s) → findings-stale/")
        for path in moved:
            _log(f"    {os.path.basename(path)}")
        return 0
    _, stale, _ = findings_tree.scope_promoted(out, findings)
    if stale:
        _log(f"  {len(stale)} stale dir(s) left in place - they no longer gate this audit. "
             "Re-run with --prune-stale to move them to findings-stale/")
    return 0


def cmd_cleanup(args) -> int:
    from .cleanup import cleanup
    out = _out_dir(args)
    s = cleanup(out, args.mode)
    _log(f"KAVACH cleanup → removed {len(s['removed'])}, retained {len(s['retained'])}")
    if s["unexpected"]:
        _log(f"  {len(s['unexpected'])} unexpected root file(s), left in place: "
             f"{', '.join(s['unexpected'])}")
    return 0


def cmd_diff(args) -> int:
    from . import diffing
    out = _out_dir(args)
    repo = os.path.abspath(args.path)
    prior = diffing.resolve_prior_commit(out, since=args.since)
    if not prior:
        _log("KAVACH diff → no prior commit resolvable "
             "(pass --since <commit> or complete a baseline audit first)")
        return 5

    files = diffing.changed_files(repo, prior)
    in_scope = diffing.scope_guard(files)
    _write_diff_scope(out, prior, files, in_scope)
    verdict = "in scope" if in_scope else "SKIPPED (empty or too broad)"
    _log(f"KAVACH diff → {len(files)} changed file(s) vs {prior[:12]} - {verdict}")

    current_path = os.path.join(out, "findings.json")
    baseline = diffing.baseline_path(out, prior)
    if os.path.exists(current_path):
        if baseline:
            new, fixed, unchanged = diffing.diff_findings(
                diffing.load_baseline(baseline), load_findings(current_path))
            _log(f"  drift → new {len(new)} · fixed {len(fixed)} · unchanged {len(unchanged)}")
        else:
            _log("  drift → no prior baseline, full-scan")
    return 0


def _write_diff_scope(out: str, prior: str, files: list[str], in_scope: bool) -> str:
    """Pre-phase change-scoping artifact, written before DF1 exists. Deliberately not
    diff-summary.md - that path is DF1's own gate (PHASE_GATES["DF1"]), produced by the
    kavach-sast dispatch; writing it here would pre-satisfy the gate and DF1 would never
    be dispatched."""
    d = os.path.join(out, "attack-surface")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "diff-scope.md")
    lines = ["# Diff Scope", "", f"Prior commit: `{prior}`", f"Changed files: {len(files)}", ""]
    if in_scope:
        lines.append("Scope: IN SCOPE")
    else:
        reason = "no changed files" if not files else f"{len(files)} changed files exceeds the scope guard"
        lines.append(f"Scope: SKIPPED - {reason}")
    lines.append("")
    if files:
        lines += ["## Changed files", ""]
        lines += [f"- `{f}`" for f in files]
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def cmd_resume(args) -> int:
    from . import runner, state
    out = _out_dir(args)
    run = state.latest_resumable_audit(out)
    if run is None:
        print("nothing to resume")
        return 0
    print(run.mode)
    for phase in runner.next_actionable(out, run.mode):
        print(phase)
    return 0


def cmd_report_finding(args) -> int:
    from . import report_finding as rf
    out = _out_dir(args)
    matches = glob.glob(os.path.join(out, "findings", f"{args.display_id}-*"))
    if not matches:
        _log(f"KAVACH report-finding → no finding dir matching {args.display_id}")
        return 5
    finding_dir = matches[0]
    with open(os.path.join(finding_dir, "metadata.json"), encoding="utf-8") as fh:
        meta = json.load(fh)
    if meta.get("is_aggregate"):
        # G* dirs have no single member in findings.json; findings_tree wrote their report.md
        # when it built the aggregate. Nothing to render, and nothing wrong.
        _log(f"KAVACH report-finding → {args.display_id} is an aggregate; "
             "its report.md is written by the core")
        return 0
    findings = load_findings(os.path.join(out, "findings.json"))
    match = next((f for f in findings if f.fingerprint() == meta["kavach_id"]), None)
    if match is None:
        _log(f"KAVACH report-finding → {args.display_id}: no matching finding in findings.json")
        return 5
    path = rf.write_report(finding_dir, match)
    _log(f"KAVACH report-finding → {'wrote ' + path if path else 'already complete'}")
    return 0


def cmd_kb(args) -> int:
    from . import kb
    out = _out_dir(args)
    if args.kb_cmd == "kill-chains":
        with open(args.file, encoding="utf-8") as fh:
            chains = json.load(fh)
        path = kb.write_kill_chains(out, chains)
        _log(f"KAVACH kb kill-chains → wrote {path}")
        return 0
    return 5


def _run_recon_inline(args, out: str) -> dict:
    recon, files = run_recon(args.path)
    with open(os.path.join(out, "recon.json"), "w", encoding="utf-8") as fh:
        json.dump(recon, fh, indent=2)
    with open(os.path.join(out, "file-manifest.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(files) + "\n")
    return recon


def _load_controls(args) -> dict:
    path = getattr(args, "controls", None)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def _load_narrative(args) -> dict | None:
    """VAJRA's prose for the six render anchors. None = let the renderer read
    attack-surface/narrative.json itself, which is the normal path."""
    path = getattr(args, "narrative", None)
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kavach", description="KAVACH deterministic security core")
    p.add_argument("--version", action="version", version=f"kavach {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--out", default=".kavach", help="artifact directory (default: .kavach)")
        # dests match flags.FLAG_ENV exactly; main() mirrors them into KAVACH_* so a subagent
        # dispatched later in the same shell reads the same ceiling.
        sp.add_argument("--budget", type=int, default=None, metavar="N",
                        help="max sub-agent dispatches for this audit, 0 = unlimited "
                             "(KAVACH_MAX_DISPATCHES)")
        sp.add_argument("--max-wall-seconds", type=int, default=None, metavar="S",
                        help="wall-clock ceiling for this audit, 0 = unlimited "
                             "(KAVACH_MAX_WALL_SECONDS)")

    sp = sub.add_parser("recon", help="deterministic stack fingerprint")
    sp.add_argument("path", nargs="?", default="."); add_common(sp)
    sp.set_defaults(func=cmd_recon)

    sp = sub.add_parser("sweep", help="run applicable docker scanners")
    sp.add_argument("path", nargs="?", default="."); add_common(sp)
    sp.set_defaults(func=cmd_sweep)

    sp = sub.add_parser("scan", help="recon + sweep (+ optional render)")
    sp.add_argument("path", nargs="?", default="."); add_common(sp)
    sp.add_argument("--format", choices=["md", "json", "sarif", "html"], default=None,
                    help="also render a report; pdf is render-only (it needs --output)")
    sp.add_argument("--output", help="write the render here instead of stdout")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("triage", help="classify every finding's finding_class in place")
    add_common(sp); sp.set_defaults(func=cmd_triage)

    sp = sub.add_parser("merge", help="fold subagent findings into the finding set")
    add_common(sp); sp.add_argument("--extra", nargs="*", help="extra findings JSON files")
    sp.set_defaults(func=cmd_merge)

    sp = sub.add_parser("merge-run", help="drive merge-mode phases MG1/MG5/MG6 over source audit dirs")
    add_common(sp)
    sp.add_argument("--dir", action="append", help="source audit dir; repeat for each source")
    sp.set_defaults(func=cmd_merge_run)

    sp = sub.add_parser("render", help="render the report in a format")
    add_common(sp)
    sp.add_argument("--format", choices=["md", "json", "sarif", "html", "pdf"], default="md")
    sp.add_argument("--output", help="write to file instead of stdout (required for pdf)")
    sp.add_argument("--controls", help="controls.json from reconciliation")
    sp.add_argument("--severity-only", action="store_true", help="gate on severity counts only")
    sp.add_argument("--date", default=""); sp.add_argument("--commit", default="")
    sp.add_argument("--mode", default="", help="audit mode name, printed on the cover")
    sp.add_argument("--narrative", default=None,
                    help="JSON of the six render anchors; default reads "
                         "attack-surface/narrative.json")
    sp.set_defaults(func=cmd_render)

    sp = sub.add_parser("coverage", help="write the per-finding phase coverage gate artifact")
    add_common(sp)
    sp.add_argument("--phase", required=True, choices=["poc", "report"],
                    help="which per-finding phase to measure")
    sp.set_defaults(func=cmd_coverage)

    sp = sub.add_parser("budget", help="the dispatch/wall-clock ledger: show | check | charge")
    sp.add_argument("budget_cmd", choices=["show", "check", "charge"]); add_common(sp)
    sp.add_argument("--phase", default=None, help="phase id (check, charge)")
    sp.add_argument("--planned", type=int, default=None,
                    help="how many dispatches this phase wants (check)")
    sp.add_argument("-n", "--count", type=int, default=None, dest="count",
                    help="how many dispatches were actually made (charge)")
    sp.set_defaults(func=cmd_budget)

    sp = sub.add_parser("issues", help="tracker export: plan, then an explicitly-approved push")
    sp.add_argument("issues_cmd", choices=["plan", "push"]); add_common(sp)
    sp.add_argument("--severity", action="append",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="severity to export; repeatable (default: critical + high)")
    sp.add_argument("--no-aggregates", action="store_true",
                    help="leave the G* aggregate findings out of the plan")
    sp.add_argument("--provider", choices=["github"], default="github")
    sp.add_argument("--repo", default=None, help="owner/name (push)")
    sp.add_argument("--yes", action="store_true",
                    help="actually create/update issues. WITHOUT IT, push is a dry run")
    sp.add_argument("--label", action="append", help="extra label to apply; repeatable")
    sp.set_defaults(func=cmd_issues)

    sp = sub.add_parser("gate", help="production-readiness gate + exit code")
    add_common(sp)
    sp.add_argument("--controls", help="controls.json from reconciliation")
    sp.add_argument("--severity-only", action="store_true")
    sp.set_defaults(func=cmd_gate)

    sp = sub.add_parser("corpus", help="self-validation gate against vulnerable fixtures")
    sp.set_defaults(func=cmd_corpus)

    sp = sub.add_parser("state", help="audit-state.json management")
    sp.add_argument("state_cmd", choices=["init", "show", "complete"]); add_common(sp)
    sp.add_argument("--mode", default="balanced"); sp.add_argument("--repository", default="")
    sp.add_argument("--commit", default=None,
                    help="commit to record on complete (else git rev-parse HEAD)")
    sp.set_defaults(func=cmd_state)

    sp = sub.add_parser("plan", help="print next-actionable phases for a mode")
    add_common(sp); sp.add_argument("--mode", required=True)
    sp.set_defaults(func=cmd_plan)

    sp = sub.add_parser("phase-prompt", help="emit the composed sub-agent prompt for a phase")
    sp.add_argument("phase"); add_common(sp)
    sp.add_argument("--mode", required=True); sp.add_argument("--target", default=".")
    sp.add_argument("--agent", default=None,
                    help="the sub-agent being dispatched, when it is not PHASE_AGENT[phase] "
                         "(a fan-out dispatches several)")
    sp.add_argument("--index", type=int, default=None,
                    help="1-based index within a fan-out. REQUIRED when a phase dispatches "
                         "more than one agent, or every dispatch is told to write one path")
    sp.set_defaults(func=cmd_phase_prompt)

    sp = sub.add_parser("ingest", help="fold a sub-agent result into drafts")
    sp.add_argument("phase"); add_common(sp)
    sp.add_argument("--result", default=None,
                    help="one result file; omitted, every runs/<phase>/*.json is folded in")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("consolidate", help="promote drafts/findings into the findings tree")
    add_common(sp)
    sp.add_argument("--prune-stale", action="store_true",
                    help="move directories that no longer belong to this audit into "
                         "findings-stale/ (a move, never a delete; default off)")
    sp.set_defaults(func=cmd_consolidate)

    sp = sub.add_parser("cleanup", help="remove transient artifacts for a mode")
    add_common(sp); sp.add_argument("--mode", required=True)
    sp.set_defaults(func=cmd_cleanup)

    sp = sub.add_parser("diff", help="resolve prior commit, scope changed files, drift diff")
    sp.add_argument("path", nargs="?", default="."); add_common(sp)
    sp.add_argument("--since", default=None, help="explicit prior commit (else latest complete audit)")
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("resume", help="print the latest resumable audit's mode + next-actionable phases")
    add_common(sp)
    sp.set_defaults(func=cmd_resume)

    sp = sub.add_parser("report-finding", help="render a per-finding report.md")
    sp.add_argument("display_id"); add_common(sp)
    sp.set_defaults(func=cmd_report_finding)

    sp = sub.add_parser("kb", help="attack-surface/ knowledge-base writers")
    sp.add_argument("kb_cmd", choices=["kill-chains"]); add_common(sp)
    sp.add_argument("--file", required=True, help="JSON input file")
    sp.set_defaults(func=cmd_kb)
    return p


def _mark_interrupted(args) -> None:
    out = getattr(args, "out", None)
    if not out:
        return
    from . import state
    from .state import PhaseStatus
    run = state.latest_audit(os.path.abspath(out), getattr(args, "mode", None))
    if not run:
        return
    for phase, ph in run.phases.items():
        if ph.status == PhaseStatus.IN_PROGRESS.value:
            state.set_phase_status(os.path.abspath(out), run.audit_id, phase, PhaseStatus.FAILED,
                                   last_error="interrupted (KeyboardInterrupt)")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    flags.apply_flag_env(args)
    try:
        return args.func(args)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        _log(f"error: {exc}")
        return 5
    except KeyboardInterrupt:
        _mark_interrupted(args)
        return 130
