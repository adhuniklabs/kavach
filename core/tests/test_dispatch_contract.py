"""The dispatch contract: everything a harness needs comes from the engine, not from prose.

`phase-prompt` used to emit one line - "Execute phase hunt (Static Analysis & Triage)." -
and the actual instruction lived in SKILL.md, so any harness that was not SKILL.md had to
re-read that prose and re-encode it. These tests pin the contract that replaced it.
"""

import json
import os
import tempfile
import unittest

from kavach import agentdefs, dispatch, modes, paths, slicing, triage
from kavach.finding import Finding, Location, Severity

AGENT_PHASES = [(m, p) for m in modes.MODES for p in modes.phases_for(m, live=True)
                if not modes.PHASE_AGENT.get(p, "core:none").startswith("core:")]


class TestPhaseSpecs(unittest.TestCase):
    def test_every_phase_has_a_contract(self):
        for mode, phase in AGENT_PHASES:
            spec = modes.spec_for(phase)
            self.assertTrue(spec.task.strip(), f"{mode}/{phase}: empty task")

    def test_every_roster_name_is_a_real_agent(self):
        roster = agentdefs.load_all()
        if not roster:
            self.skipTest("agents/ not installed beside the core")
        for mode, phase in AGENT_PHASES:
            for agent in modes.roster_for(phase, mode):
                self.assertIn(agent, roster, f"{phase} dispatches unknown agent {agent}")

    def test_every_reference_named_exists(self):
        base = paths.references_dir()
        if base is None:
            self.skipTest("references/ not installed beside the core")
        for mode, phase in AGENT_PHASES:
            for agent in modes.roster_for(phase, mode) or [None]:
                for name in modes.references_for(phase, agent):
                    self.assertTrue(os.path.exists(os.path.join(base, name)),
                                    f"{phase}/{agent}: missing reference {name}")

    def test_agent_reference_keys_are_real_agents(self):
        roster = agentdefs.load_all()
        if not roster:
            self.skipTest("agents/ not installed beside the core")
        for name in modes.AGENT_REFERENCES:
            self.assertIn(name, roster)

    def test_fanout_phases_declare_their_whole_roster(self):
        """`hunt` dispatches eight hunters at balanced and deep. A roster of one there
        means seven domains are silently never audited - the failure mode is a
        clean-looking report."""
        for mode in ("balanced", "deep"):
            self.assertEqual(modes.roster_for("hunt", mode), list(modes.DOMAIN_ROSTER))

    def test_single_agent_phase_falls_back_to_phase_agent(self):
        self.assertEqual(modes.roster_for("probe", "balanced"), ["kavach-probe"])

    def test_core_phase_dispatches_nothing(self):
        self.assertEqual(modes.roster_for("render", "balanced"), [])
        self.assertEqual(modes.roster_for("cleanup", "balanced"), [])

    def test_inputs_inherit_prereq_gates(self):
        got = modes.inputs_for("deep", "probe")
        self.assertIn("attack-surface/knowledge-base-report.md", got)   # kb's gate
        self.assertIn("attack-surface/source-sink-flows-all-severities.md", got)  # hunt's
        self.assertNotIn("findings", got)   # a directory gate is not a readable input

    def test_live_inputs_come_from_the_tail_not_through_it(self):
        """With the tail dropped, exploit's prereq resolution walks provision ->
        envscan -> inventory -> render and hands kavach-poc-executor the final report.
        Under --live the tail is a member, so it gets the sandbox connection that
        provision wrote for it."""
        self.assertIn("reports/final-audit-report.md", modes.inputs_for("deep", "exploit"))
        got = modes.inputs_for("deep", "exploit", live=True)
        self.assertEqual(got[-1], "attack-surface/confirm-env-connection.json")
        self.assertNotIn("reports/final-audit-report.md", got)


class TestPhasePrompt(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_prompt_carries_header_task_and_result_path(self):
        p = dispatch.phase_prompt("balanced", "hunt", self.dir, "/repo",
                                  agent="kavach-sast", index=1)
        self.assertIn("Static Analysis & Triage", p)
        self.assertIn("scanner hit", p)
        self.assertIn(os.path.join("runs", "hunt", "kavach-sast-1.json"), p)

    def test_fanout_prompt_names_the_peers_so_domains_are_not_duplicated(self):
        p = dispatch.phase_prompt("deep", "hunt", self.dir, "/repo", agent="kavach-billing",
                                  index=4)
        self.assertIn("one of 8 agents", p)
        self.assertIn("kavach-sast", p)
        self.assertNotIn("The others are: kavach-billing", p)

    def test_missing_reference_is_declared_not_silently_dropped(self):
        """A machine without the skill tree still gets a dispatchable prompt, and the agent
        is told what it could not be given rather than being left to assume it had it."""
        os.environ["KAVACH_REFERENCES_DIR"] = os.path.join(self.dir, "nope")
        try:
            p = dispatch.phase_prompt("balanced", "hunt", self.dir, "/repo",
                                      agent="kavach-sast", index=1)
        finally:
            del os.environ["KAVACH_REFERENCES_DIR"]
        self.assertIn("Not installed on this machine", p)
        self.assertIn("persona.md", p)

    def test_live_reaches_the_inputs_the_prompt_names(self):
        """The flag has to survive phase_prompt -> _existing_inputs -> inputs_for, or
        the tail agent is told to read the report instead of its own prereq."""
        os.makedirs(os.path.join(self.dir, "attack-surface"))
        with open(os.path.join(self.dir, "attack-surface", "confirm-env-connection.json"),
                  "w", encoding="utf-8") as fh:
            fh.write("{}")
        p = dispatch.phase_prompt("deep", "exploit", self.dir, "/repo", live=True)
        inputs = p.split("Audit inputs:")[1].split("---")[0]
        self.assertIn("confirm-env-connection.json", inputs)

    def test_only_inputs_that_exist_are_named(self):
        p = dispatch.phase_prompt("balanced", "kb", self.dir, "/repo")
        self.assertIn("Audit inputs:", p)
        self.assertNotIn("recon.json", p.split("Audit inputs:")[1].split("---")[0])
        with open(os.path.join(self.dir, "recon.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")
        p = dispatch.phase_prompt("balanced", "kb", self.dir, "/repo")
        self.assertIn("recon.json", p.split("Audit inputs:")[1].split("---")[0])


class TestDispatchPlan(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_fanout_plan_gives_every_dispatch_a_distinct_result_path(self):
        plan = dispatch.dispatch_plan("balanced", "hunt", self.dir, "/repo")
        self.assertEqual(plan["kind"], "fanout")
        self.assertEqual(plan["planned"], 8)
        paths_out = [d["result_path"] for d in plan["dispatches"]]
        self.assertEqual(len(set(paths_out)), 8)
        self.assertEqual([d["index"] for d in plan["dispatches"]], list(range(1, 9)))

    def test_single_agent_plan_omits_the_index_suffix(self):
        plan = dispatch.dispatch_plan("balanced", "probe", self.dir, "/repo")
        self.assertEqual(plan["kind"], "agent")
        self.assertTrue(plan["dispatches"][0]["result_path"].endswith("kavach-probe.json"))

    def test_core_plan_has_nothing_to_dispatch(self):
        plan = dispatch.dispatch_plan("balanced", "render", self.dir, "/repo")
        self.assertEqual(plan["kind"], "core")
        self.assertEqual(plan["dispatches"], [])
        self.assertEqual(plan["executor"], "core:render")

    def test_sequential_rosters_are_flagged(self):
        self.assertTrue(dispatch.dispatch_plan("deep", "history", self.dir, "/repo")["sequential"])
        self.assertFalse(dispatch.dispatch_plan("deep", "hunt", self.dir, "/repo")["sequential"])

    def test_live_reaches_the_dispatch_plan(self):
        self.assertEqual(dispatch.dispatch_plan("deep", "exploit", self.dir, "/repo")["prereqs"],
                         ["render"])
        self.assertEqual(
            dispatch.dispatch_plan("deep", "exploit", self.dir, "/repo", live=True)["prereqs"],
            ["provision"])

    def test_gate_paths_are_absolute(self):
        plan = dispatch.dispatch_plan("balanced", "kb", self.dir, "/repo")
        self.assertTrue(all(os.path.isabs(g) for g in plan["gate"]))


class TestAgentDefs(unittest.TestCase):
    def test_roster_loads_with_tools_and_tier(self):
        roster = agentdefs.load_all()
        if not roster:
            self.skipTest("agents/ not installed beside the core")
        self.assertEqual(len(roster), 37)
        sast = roster["kavach-sast"]
        self.assertIn("Bash", sast.tools)
        self.assertEqual(sast.tier, agentdefs.REASONING)
        self.assertEqual(roster["kavach-triager"].tier, agentdefs.TRIAGE)
        self.assertEqual(roster["kavach-reporter"].tier, agentdefs.MECHANICAL)

    def test_tier_is_derived_when_a_file_does_not_declare_one(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "kavach-x.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("---\nname: kavach-x\ndescription: d\ntools: Read\nmodel: haiku\n---\nbody\n")
            self.assertEqual(agentdefs.parse(path).tier, agentdefs.TRIAGE)

    def test_every_tier_is_one_the_harness_knows(self):
        roster = agentdefs.load_all()
        if not roster:
            self.skipTest("agents/ not installed beside the core")
        for agent in roster.values():
            self.assertIn(agent.tier, agentdefs.TIERS, agent.name)


def _finding(title, source, category, severity=Severity.HIGH):
    return Finding(title=title, severity=severity, category=category, source=source,
                   locations=[Location(file="a.js", line=1)])


class TestSlicing(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.findings = [
            _finding("key", "builtin-secrets", "A07:Secrets"),
            _finding("cve", "trivy", "A06:Vulnerable-Components"),
            _finding("iac", "hadolint", "A05:Misconfig"),
            _finding("prompt injection", "kavach-llm", "LLM01"),
        ]
        with open(os.path.join(self.dir, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump({"meta": {}, "findings": [f.to_dict() for f in self.findings]}, fh)

    def test_each_domain_gets_only_its_leads(self):
        for agent, expected in (("kavach-sast", "key"), ("kavach-supply", "cve"),
                                ("kavach-config", "iac"), ("kavach-llm", "prompt injection")):
            mine, excluded = slicing.slice_for(self.findings, agent)
            self.assertEqual([f.title for f in mine], [expected], agent)
            self.assertEqual(excluded, 3, agent)

    def test_an_agent_with_no_domain_map_gets_everything(self):
        mine, excluded = slicing.slice_for(self.findings, "kavach-chamber")
        self.assertEqual(len(mine), 4)
        self.assertEqual(excluded, 0)

    def test_written_slice_declares_what_it_left_out(self):
        """A hunter that thinks its slice is the whole set reports coverage it does not have."""
        result = slicing.write_slice(self.dir, "hunt", "kavach-supply", index=6)
        self.assertEqual((result["included"], result["excluded"], result["total"]), (1, 3, 4))
        with open(result["path"], encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertIn("3 belong to other domains", payload["note"])
        self.assertTrue(result["path"].endswith(os.path.join("hunt", "slices", "kavach-supply-6.json")))

    def test_merged_source_aliases_still_slice(self):
        """merge_findings prefixes sources with a per-audit alias, so a whole-string match
        against 'trivy' misses 'a:trivy' and the CVE silently reaches no hunter."""
        merged = _finding("cve", "a:trivy+b:trivy", "A06:Vulnerable-Components")
        self.assertTrue(slicing.matches(merged, "kavach-supply"))


if __name__ == "__main__":
    unittest.main()


class TestPaths(unittest.TestCase):
    """Resolution climbs four levels, which on a checkout reaches outside the project."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_a_lookalike_directory_is_not_bound_as_the_roster(self):
        empty = os.path.join(self.dir, "agents")
        os.makedirs(empty)
        os.environ["KAVACH_AGENTS_DIR"] = empty
        try:
            self.assertEqual(agentdefs.load_all(paths.agents_dir()), {})
        finally:
            del os.environ["KAVACH_AGENTS_DIR"]

    def test_override_pointing_nowhere_resolves_to_none(self):
        os.environ["KAVACH_REFERENCES_DIR"] = os.path.join(self.dir, "absent")
        try:
            self.assertIsNone(paths.references_dir())
            self.assertIsNone(paths.reference("persona.md"))
        finally:
            del os.environ["KAVACH_REFERENCES_DIR"]

    def test_checkout_layout_resolves_both_trees(self):
        self.assertIsNotNone(paths.references_dir())
        self.assertIsNotNone(paths.agents_dir())
        self.assertTrue(paths.reference("persona.md"))
        self.assertTrue(paths.reference("domains/sast.md"))
        self.assertIsNone(paths.reference("nope.md"))


class TestAgentAuthoredResults(unittest.TestCase):
    """A subagent hand-writes its result file, so the contract has to survive a model.

    Two failures cost a whole `hunt` dispatch before these existed: `finding-schema.md`'s own
    example omitted `source`, which `Finding` requires, so no agent following the documented
    contract could produce an ingestible file; and one invented key raised, which quarantined
    the file and lost the six findings beside it.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "runs", "hunt"))

    def _result(self, name, findings):
        path = os.path.join(self.dir, "runs", "hunt", name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"domain": "sast", "controls": {}, "findings": findings}, fh)
        return path

    def test_the_documented_example_ingests(self):
        example = _schema_example()
        Finding.from_dict(example)

    def test_an_invented_key_is_dropped_not_fatal(self):
        f = Finding.from_dict({"title": "t", "severity": "high", "category": "A01",
                               "source": "kavach-sast", "exploitability": "trivial"})
        self.assertEqual(f.title, "t")
        self.assertFalse(hasattr(f, "exploitability"))

    def test_a_result_without_source_is_attributed_to_its_dispatch(self):
        path = self._result("kavach-sast.json", [
            {"title": "Hardcoded key", "severity": "critical", "category": "A07:Secrets",
             "locations": [{"file": "server.js", "line": 7}]}])
        written, _ = dispatch.ingest(self.dir, "hunt", path)
        self.assertEqual(written, 1)
        drafts = os.listdir(os.path.join(self.dir, "findings-draft"))
        self.assertEqual(len(drafts), 1)

    def test_a_status_result_with_no_findings_is_not_corrupt(self):
        """`probe` writes a protocol status object, not a findings envelope. Quarantining
        it left the phase re-planning a dispatch that had already done its work."""
        path = os.path.join(self.dir, "runs", "hunt", "kavach-probe.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"agent": "kavach-probe", "status": "complete", "loops": 2}, fh)
        written, skipped = dispatch.ingest(self.dir, "hunt", path)
        self.assertEqual((written, skipped), (0, 0))

    def test_attribution_survives_a_fan_out_index(self):
        self.assertEqual(dispatch.agent_from_result("/a/runs/hunt/kavach-sast-3.json"),
                         "kavach-sast")
        self.assertEqual(dispatch.agent_from_result("/a/runs/hunt/kavach-sast.json"),
                         "kavach-sast")

    def test_an_unattributed_finding_stays_promotable(self):
        f = Finding.from_dict({"title": "t", "severity": "high", "category": "A01"},
                              source="kavach-sast")
        self.assertEqual(triage.classify(f), "reasoned")


def _schema_example() -> dict:
    """The `findings[0]` object out of `finding-schema.md`, parsed from the doc itself.

    Read rather than copied: a schema doc that drifts from the dataclass is exactly the
    defect this pins, and a copy here would drift with it.
    """
    doc = paths.reference("finding-schema.md")
    if doc is None:
        raise unittest.SkipTest("references/ not installed beside the core")
    with open(doc, encoding="utf-8") as fh:
        body = fh.read()
    block = body.split("```json", 1)[1].split("```", 1)[0]
    return json.loads(block)["findings"][0]
