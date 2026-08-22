"""Deterministic six-axis scorecard - the number in the report is arithmetic, not an impression.

Every *assessed* axis starts at 10.0, loses a fixed amount per finding mapped to it, gains a
fixed bonus per control the reconciler proved, and is floored at 1.0. There is no evaluator
override and no fudge factor: two runs over the same ``findings.json`` and ``controls.json``
produce the same scorecard, and :func:`axis_rows` prints the arithmetic that produced it so
Annex A of the report can be argued with rather than reverse-engineered.

Where a human auditor would apply judgement, KAVACH does not. The arithmetic *is* the
score - if the mapping is wrong, argue with :data:`AXIS_MAP`, which is one table by design.

Three properties are load-bearing enough to state here, because each was wrong in an earlier
cut and each put a self-contradicting line on the scorecard page:

* **The taxonomy category decides the axis.** An axis is a family of controls, and the
  category is the only field that says which control family failed. A kill chain says what
  an attacker *gets* out of the defect - a consequence, not a control - so it ranks last and
  decides only findings whose category is unmapped. Scored the other way round, every IDOR,
  BFLA and authentication bypass on a repo left ``security`` with no critical or high finding
  at all while the executive summary on the same page reported fourteen criticals.
* **A rolled-up scanner class deducts once per severity band, not once per row.** The
  promotion policy (spec §A2) puts a ``dependency`` or ``iac`` class in ``findings/`` as one
  ``G`` directory, and the scorecard follows the deliverable. Scored once per row, 136 CVE
  rows floor their axis on their own, which both hides the reasoned findings sharing that axis
  and makes the axis insensitive to them - the deduction is already clamped, so the 136th row
  changes nothing.
* **An axis nothing was scored against is not assessed, not perfect.** Every other half of this
  framework is fail-closed: ``controls.json`` defaults every control to false and the gate
  withholds certification on an unproven one, because an unsupplied control is an unproven
  control (the paranoia mandate, :func:`kavach.score.gate`). A scorecard that started an
  unmeasured axis at :data:`BASE` and printed 10.0/10 said the opposite on the same page - a
  clean bill of health for a control family no scanner and no subagent ever looked at. So an
  axis or sub-characteristic with no mapped finding *and* no proving control now scores
  :data:`None`, renders :data:`NOT_ASSESSED`, is excluded from the overall figure and is not
  plotted. Absence of a finding is not evidence of a control.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .finding import Finding, Severity
from .score import GATE_CONTROLS
from .triage import AGGREGATE_CLASSES

BASE = 10.0
FLOOR = 1.0
ACCEPTABLE = 5.0
CONTROL_BONUS = 0.5

# What an axis or sub-characteristic reads as when nothing was scored against it. A number of
# any kind here would be a claim - 10.0 says the controls hold, 0.0 says they fail, 5.0 says
# they half hold, and the audit established none of the three.
NOT_ASSESSED = "not assessed"

# The "Clears 5.0" cell for an axis that has no score. Neither "yes" nor "no" is answerable.
NOT_APPLICABLE = "-"

DEDUCTION = {
    Severity.CRITICAL: -3.0,
    Severity.HIGH: -1.5,
    Severity.MEDIUM: -0.75,
    Severity.LOW: -0.25,
    Severity.INFO: 0.0,
}

AXES = ("security", "data_protection", "secrets_supply_chain",
        "architecture", "reliability", "maintainability")

AXIS_LABELS = {
    "security": "Security",
    "data_protection": "Data protection",
    "secrets_supply_chain": "Secrets & supply chain",
    "architecture": "Architecture",
    "reliability": "Reliability",
    "maintainability": "Maintainability",
}

# What each axis is a score *of*, printed as the first sentence of the axis reading. A scorecard
# line can only be argued with if the reader knows what was measured, and the two axes a reader
# most often mistakes for each other are named against each other on purpose.
AXIS_SCOPE = {
    "security": "authorization, authentication and injection resistance across the reachable "
                "surface - a cross-tenant read is scored here, where the missing check is",
    "data_protection": "whether the personal-data mechanisms exist in the code: encryption in "
                       "transit and at rest, PII minimisation and exposure, consent, retention "
                       "and erasure",
    "secrets_supply_chain": "credential handling and the provenance of third-party code: "
                            "committed secrets, secret lifecycle, dependency advisories and "
                            "artifact integrity",
    "architecture": "trust-boundary design, configuration and infrastructure-as-code defaults",
    "reliability": "the money path, rate and abuse limiting, and the logging and monitoring "
                   "pipeline",
    "maintainability": "code quality, verification coverage and unverified finding debt",
}

# A standing caveat about what can ever reach an axis, printed after the not-assessed sentence.
# Only maintainability has one, and it is prose rather than a derived count because the fact it
# states is about the tool's purpose, not about the mapping tables: KAVACH is a security
# auditor, so nothing in the sweep or the subagent brief reads code for maintainability, and
# this axis is not-assessed by design rather than by accident of one run. The reference audit
# format carries a maintainability score because a human auditor read the code for it; printing
# a number here would be claiming that reading happened. Naming the axis is the alternative to
# deleting it - a reader comparing against that format is owed the row and the reason it is
# empty, not a silently missing sixth axis.
AXIS_COVERAGE_CAVEAT = {
    "maintainability": "KAVACH is a security auditor: neither the scanner sweep nor the "
                       "subagent brief reads code for maintainability, so expect this axis to "
                       "be not assessed on every run. Where a reference audit format scores "
                       "maintainability, a human auditor read the code for it - a number here "
                       "would claim a reading this report did not do.",
}

# How many category keys the not-assessed reading names before it falls back to a count.
MAX_NAMED_CATEGORIES = 6

# Sub-characteristic keys are unique across all six axes, so one flat SUB_MAP suffices.
# The first entry of each tuple is that axis's default sub - where an unmapped finding lands.
SUBS = {
    "security": (("access_control", "Access control (object & function level)"),
                 ("authentication", "Authentication & session integrity"),
                 ("injection_resistance", "Injection & request-forgery resistance"),
                 ("ai_safety", "AI / LLM safety")),
    "data_protection": (("encryption", "Encryption in transit & at rest"),
                        ("pii_exposure", "PII minimisation & exposure"),
                        ("privacy_and_retention", "Consent, retention & erasure")),
    "secrets_supply_chain": (("secret_management", "Secret management"),
                             ("dependency_hygiene", "Dependency hygiene"),
                             ("artifact_integrity", "Artifact & data integrity")),
    "architecture": (("boundary_integrity", "Trust-boundary integrity"),
                     ("configuration", "Configuration"),
                     ("infrastructure_as_code", "Infrastructure as code")),
    "reliability": (("money_path_integrity", "Money-path integrity"),
                    ("rate_limiting", "Rate & abuse limiting"),
                    ("observability", "Logging & observability")),
    "maintainability": (("code_quality", "Code quality"),
                        ("verification_coverage", "Verification coverage"),
                        ("finding_debt", "Unverified finding debt")),
}

# Precedence, highest first. An entry names a whole dimension, or one specific key of one
# dimension when that key outranks the dimensions above it.
#
# The category decides, because an axis is a family of controls and the category is the only
# field that names the control family that failed. The kill chain is the *consequence* of the
# defect, so it decides only what no category maps.
#
# `class:secret` is the single hoisted key. Triage's secret rule is itself category-exact or
# dedicated-scanner (spec §A1 correction), so it is a stronger statement than the taxonomy
# label a secret arrives with: `rust-secret-apis` emits `A02:Crypto` for a secret that outlives
# its scope in memory, which is secret handling, not an encryption failure. The other two
# classes stay below the category, because `dependency` and `iac` are provenance and their
# categories are more specific - the nine `A05:Misconfiguration` rows trivy emits are
# configuration findings, and scoring them as supply chain because trivy also reads manifests
# is the tail wagging the dog.
AXIS_PRECEDENCE = ("class:secret", "category", "class", "kill_chain")
DEFAULT_AXIS = "security"

# The sub lookup runs its own precedence, and takes the first mapped key that is actually a sub
# of the axis already resolved. `class` outranks `category` here - the reverse of the axis order -
# because within one axis the class is the more specific statement: checkov's
# `A05:Misconfiguration` rows and kavach-config's carry the same category on the same axis, and
# only the class separates infrastructure-as-code defaults from application configuration. Where
# the class names a sub belonging to another axis (trivy's `A05` rows are class `dependency` but
# score on architecture) the candidate is skipped and the category decides, which is why validity
# is checked per candidate rather than once at the end.
SUB_PRECEDENCE = ("class", "category", "kill_chain")

# The one table. Keys are "<dimension>:<key>"; category keys are upper-cased and matched
# on the whole category first, then on the segment before the first ':'.
#
# `class:code` and `class:reasoned` are deliberately absent - those two classes say nothing
# about which axis a finding belongs to, so the category decides.
#
# A07 needs both forms, for the same reason triage matches "A07:Secrets" exactly rather than
# on the `A07` head (spec §A1 correction): KAVACH's own taxonomy uses `A07:Secrets` for a
# committed credential, while the real corpus also carries `A07:Auth-Failures`,
# `A07:2021-Identification and Authentication Failures` and
# `A07:Identification-and-Authentication-Failures`, none of which is a secret. The whole-category
# key catches KAVACH's spelling; the head carries OWASP 2021's meaning.
AXIS_MAP = {
    "kill_chain:steal-keys": "secrets_supply_chain",
    "kill_chain:free-chatbot": "reliability",
    "kill_chain:bypass-billing": "reliability",
    "kill_chain:mint-tokens": "reliability",
    # Reading another tenant's rows is an authorization failure; data protection is scored on
    # whether the personal-data mechanisms exist, not on what an attacker reached through a
    # missing check. An IDOR is an access-control finding first and a consequence second.
    "kill_chain:read-others-data": "security",
    "kill_chain:hijack-ai": "security",

    "class:secret": "secrets_supply_chain",
    "class:dependency": "secrets_supply_chain",
    "class:iac": "architecture",

    "category:A01": "security",                 # broken access control
    "category:A02": "data_protection",          # cryptographic failures
    "category:A03": "security",                 # injection
    "category:A04": "architecture",             # insecure design
    "category:A05": "architecture",             # security misconfiguration
    "category:A06": "secrets_supply_chain",     # vulnerable & outdated components
    "category:A07:SECRETS": "secrets_supply_chain",   # KAVACH taxonomy: a committed credential
    "category:A07": "security",                 # OWASP 2021: identification & auth failures
    "category:A08": "secrets_supply_chain",     # software & data integrity failures
    "category:A09": "reliability",              # logging & monitoring failures
    "category:A10": "security",                 # SSRF

    "category:API1": "security",                # BOLA
    "category:API2": "security",                # broken authentication
    "category:API3": "security",                # object property level authorization
    "category:API4": "reliability",             # unrestricted resource consumption
    "category:API5": "security",                # BFLA
    "category:API6": "reliability",             # sensitive business flows
    "category:API7": "security",                # SSRF
    "category:API8": "architecture",            # misconfiguration
    "category:API9": "maintainability",         # improper inventory management
    "category:API10": "secrets_supply_chain",   # unsafe consumption of APIs

    "category:LLM01": "security",               # prompt injection
    "category:LLM02": "security",               # insecure output handling
    "category:LLM03": "secrets_supply_chain",   # training-data poisoning
    "category:LLM04": "reliability",            # model denial of service
    "category:LLM05": "secrets_supply_chain",   # supply chain
    "category:LLM06": "data_protection",        # sensitive information disclosure
    "category:LLM07": "architecture",           # insecure plugin design
    "category:LLM08": "architecture",           # excessive agency
    "category:LLM09": "maintainability",        # overreliance
    "category:LLM10": "secrets_supply_chain",   # model theft - a proprietary artifact, not PII

    "category:BILLING-BYPASS": "reliability",
    "category:BILLING": "reliability",
    "category:SECRETS": "secrets_supply_chain",
    "category:MISCONFIGURATION": "architecture",
    "category:VULNERABLE-COMPONENTS": "secrets_supply_chain",
    "category:DEPENDENCY": "secrets_supply_chain",
    "category:IAC": "architecture",
}

SUB_MAP = {
    "kill_chain:steal-keys": "secret_management",
    "kill_chain:free-chatbot": "rate_limiting",
    "kill_chain:bypass-billing": "money_path_integrity",
    "kill_chain:mint-tokens": "money_path_integrity",
    "kill_chain:read-others-data": "access_control",
    "kill_chain:hijack-ai": "ai_safety",

    "class:secret": "secret_management",
    "class:dependency": "dependency_hygiene",
    "class:iac": "infrastructure_as_code",

    "category:A01": "access_control",
    "category:A02": "encryption",
    "category:A03": "injection_resistance",
    "category:A04": "boundary_integrity",
    "category:A05": "configuration",
    "category:A06": "dependency_hygiene",
    "category:A07:SECRETS": "secret_management",
    "category:A07": "authentication",
    "category:A08": "artifact_integrity",
    "category:A09": "observability",
    "category:A10": "injection_resistance",

    "category:API1": "access_control",
    "category:API2": "authentication",
    "category:API3": "access_control",
    "category:API4": "rate_limiting",
    "category:API5": "access_control",
    "category:API6": "money_path_integrity",
    "category:API7": "injection_resistance",
    "category:API8": "configuration",
    "category:API9": "verification_coverage",
    "category:API10": "artifact_integrity",

    "category:LLM01": "ai_safety",
    "category:LLM02": "ai_safety",
    "category:LLM03": "artifact_integrity",
    "category:LLM04": "rate_limiting",
    "category:LLM05": "dependency_hygiene",
    "category:LLM06": "pii_exposure",
    "category:LLM07": "boundary_integrity",
    "category:LLM08": "boundary_integrity",
    "category:LLM09": "verification_coverage",
    "category:LLM10": "artifact_integrity",

    "category:BILLING-BYPASS": "money_path_integrity",
    "category:BILLING": "money_path_integrity",
    "category:SECRETS": "secret_management",
    "category:MISCONFIGURATION": "configuration",
    "category:VULNERABLE-COMPONENTS": "dependency_hygiene",
    "category:DEPENDENCY": "dependency_hygiene",
    "category:IAC": "infrastructure_as_code",
}

# Each of the eight gate controls credits exactly one sub-characteristic. Architecture and
# maintainability carry no control - they are entirely finding-driven, and the doc says so.
CONTROL_MAP = {
    "no_client_reachable_secret": ("secrets_supply_chain", "secret_management"),
    "billing_server_side_enforced": ("reliability", "money_path_integrity"),
    "authz_on_every_object_and_function": ("security", "access_control"),
    "ai_guardrails_present": ("security", "ai_safety"),
    "encryption_tls_and_at_rest": ("data_protection", "encryption"),
    "rate_limits_on_expensive_endpoints": ("reliability", "rate_limiting"),
    "no_debug_or_secret_leak_in_prod": ("data_protection", "pii_exposure"),
    "webhooks_verified_and_idempotent": ("reliability", "observability"),
}


@dataclass
class Row:
    """One term of an axis's arithmetic, printed verbatim in Annex A."""

    item: str
    effect: float
    justification: str

    def to_dict(self) -> dict:
        return {"item": self.item, "effect": self.effect, "justification": self.justification}


@dataclass
class SubScore:
    """One sub-characteristic. ``score`` is None when nothing was scored against it."""

    key: str
    label: str
    score: float | None
    determined_by: list[str] = field(default_factory=list)

    @property
    def assessed(self) -> bool:
        return self.score is not None

    @property
    def score_text(self) -> str:
        return f"{self.score:.1f}" if self.assessed else NOT_ASSESSED

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "score": self.score,
                "assessed": self.assessed, "determined_by": list(self.determined_by)}


@dataclass
class Axis:
    """One axis. ``score`` is None when nothing was scored against it - see the module docstring."""

    key: str
    label: str
    score: float | None
    subs: list[SubScore] = field(default_factory=list)
    reading: str = ""
    rows: list[Row] = field(default_factory=list)

    @property
    def assessed(self) -> bool:
        return self.score is not None

    @property
    def acceptable(self) -> bool | None:
        """None on a not-assessed axis: the question is unanswerable, not answered "no"."""
        return None if self.score is None else self.score >= ACCEPTABLE

    @property
    def score_text(self) -> str:
        return f"{self.score:.1f}" if self.assessed else NOT_ASSESSED

    @property
    def clears_text(self) -> str:
        if not self.assessed:
            return NOT_APPLICABLE
        return "yes" if self.acceptable else "no"

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "score": self.score,
                "assessed": self.assessed, "acceptable": self.acceptable,
                "reading": self.reading, "subs": [s.to_dict() for s in self.subs],
                "rows": [r.to_dict() for r in self.rows]}


@dataclass
class Scorecard:
    """The six axes and the figure over the assessed ones. ``overall`` is None when none are."""

    axes: list[Axis]
    overall: float | None
    method: str

    @property
    def assessed_axes(self) -> list[Axis]:
        return [a for a in self.axes if a.assessed]

    @property
    def unassessed_axes(self) -> list[Axis]:
        return [a for a in self.axes if not a.assessed]

    @property
    def acceptable(self) -> bool:
        """Acceptable only when every *assessed* axis clears 5.0.

        A 9.0 elsewhere does not buy off a 2.0, and an axis nobody measured buys off nothing at
        all. A scorecard with no assessed axis is not acceptable - there is nothing for the word
        to be true of.
        """
        assessed = self.assessed_axes
        return bool(assessed) and all(a.acceptable for a in assessed)

    @property
    def summary(self) -> str:
        """The cover's scorecard line, shared so five renderers cannot word it five ways.

        Names how many axes the figure covers, because an average over a varying denominator is
        unreadable without one.
        """
        assessed = self.assessed_axes
        if not assessed:
            return (f"{NOT_ASSESSED} - no finding maps to any of the {len(self.axes)} axes and "
                    f"no control credits one")
        head = (f"{self.overall:.1f} / {BASE:.0f} across {len(assessed)} assessed "
                f"{'axis' if len(assessed) == 1 else 'axes'}")
        missing = self.unassessed_axes
        if len(missing) == 1:
            # One is worth naming on a cover; a list of five is a wall, and the axis table in
            # the scoring section names every one of them either way.
            head += f" (1 not assessed: {missing[0].label})"
        elif missing:
            head += f" ({len(missing)} not assessed)"
        return head + " - " + ("every assessed axis acceptable" if self.acceptable else
                               f"at least one assessed axis below the {ACCEPTABLE:.1f} "
                               f"threshold")

    def axis(self, key: str) -> Axis:
        for a in self.axes:
            if a.key == key:
                return a
        raise KeyError(f"unknown axis '{key}'; choose from {list(AXES)}")

    def axis_rows(self, key: str) -> list[Row]:
        return self.axis(key).rows

    def to_dict(self) -> dict:
        return {"overall": self.overall, "acceptable": self.acceptable,
                "assessed_axes": [a.key for a in self.assessed_axes],
                "not_assessed_axes": [a.key for a in self.unassessed_axes],
                "summary": self.summary, "threshold": ACCEPTABLE, "method": self.method,
                "axes": [a.to_dict() for a in self.axes]}


METHOD = (f"Each assessed axis starts at {BASE:.1f}. Every mapped finding deducts "
          f"{-DEDUCTION[Severity.CRITICAL]:.1f} (critical), "
          f"{-DEDUCTION[Severity.HIGH]:.2f} (high), "
          f"{-DEDUCTION[Severity.MEDIUM]:.2f} (medium) or "
          f"{-DEDUCTION[Severity.LOW]:.2f} (low); info deducts nothing. Every control proven "
          f"in controls.json adds {CONTROL_BONUS:.1f}. The result is clamped to "
          f"[{FLOOR:.1f}, {BASE:.1f}] and rounded to one decimal. An axis is acceptable at "
          f"{ACCEPTABLE:.1f} or above. The two rolled-up scanner classes "
          f"({', '.join(AGGREGATE_CLASSES)}) deduct once per severity band they contain rather "
          f"than once per row, because findings/ carries each of them as one aggregate "
          f"directory; the band's row names its member count. There is no evaluator override. "
          f"Absence of a finding is not evidence of a control: an axis or sub-characteristic "
          f"with no mapped finding and no proving control in controls.json is reported as "
          f"'{NOT_ASSESSED}' rather than scored - it never starts at {BASE:.1f}, it is left out "
          f"of the overall figure, and it is not plotted on the radar. This is the same "
          f"fail-closed rule the gate applies to an unsupplied control, and it means the "
          f"overall figure is an average over the axes this audit actually covered.")


def _category_keys(category: str) -> list[str]:
    cat = (category or "").strip().upper()
    if not cat:
        return []
    keys = [f"category:{cat}"]
    head = cat.split(":", 1)[0].strip()
    if head and head != cat:
        keys.append(f"category:{head}")
    return keys


def _dimension_keys(finding: Finding, dim: str) -> list[str]:
    """The table keys ``finding`` offers on one dimension, most specific first."""
    if dim == "kill_chain":
        chain = (finding.kill_chain or "").strip().lower()
        return [f"kill_chain:{chain}"] if chain else []
    if dim == "class":
        cls = (finding.finding_class or "").strip().lower()
        return [f"class:{cls}"] if cls else []
    return _category_keys(finding.category)


def _lookup(finding: Finding, table: dict, precedence: tuple[str, ...],
            valid: set[str] | None = None) -> str:
    """Resolve a finding against AXIS_MAP / SUB_MAP under ``precedence``.

    ``valid`` restricts what counts as a hit, so a candidate that maps outside the caller's
    scope is skipped rather than ending the walk.
    """
    for entry in precedence:
        dim, _, want = entry.partition(":")
        for key in _dimension_keys(finding, dim):
            if want and key != entry:
                continue
            value = table.get(key, "")
            if value and (valid is None or value in valid):
                return value
    return ""


def axis_for(finding: Finding) -> str:
    """Which of the six axes this finding is scored against."""
    return _lookup(finding, AXIS_MAP, AXIS_PRECEDENCE) or DEFAULT_AXIS


def sub_for(finding: Finding, axis: str) -> str:
    """Which sub-characteristic of ``axis`` this finding is scored against.

    A finding can resolve its axis on one dimension and its sub on another (a category picks
    the axis, the triage class picks the sub). Nothing outside ``axis``'s own subs can win, so
    a finding whose every mapped sub belongs elsewhere lands on that axis's default sub - the
    axis total stays correct either way.
    """
    valid = {key for key, _ in SUBS[axis]}
    return _lookup(finding, SUB_MAP, SUB_PRECEDENCE, valid) or SUBS[axis][0][0]


def _crediting_controls(axis: str, controls: dict[str, bool]) -> list[str]:
    """The controls proven in ``controls.json`` that credit ``axis``, in gate order."""
    return [c for c in GATE_CONTROLS
            if CONTROL_MAP.get(c, (None, None))[0] == axis and controls.get(c) is True]


def assessed_subs(axis: str, findings: list[Finding],
                  controls: dict[str, bool] | None = None) -> set[str]:
    """The sub-characteristics of ``axis`` this run has evidence about, either way.

    A sub is assessed when a finding maps to it or a proven control credits it - the only two
    ways KAVACH can say anything at all about a control family. Membership is decided on the
    mapped *findings* rather than on the deduction terms, so a sub carrying nothing but ``info``
    findings is "assessed, nothing to deduct" rather than unassessed: something was looked at
    and reported, and the score is a result rather than a default.
    """
    controls = controls or {}
    out = {sub_for(f, axis) for f in findings if axis_for(f) == axis}
    for control in _crediting_controls(axis, controls):
        out.add(CONTROL_MAP[control][1])
    return out


def assessed(axis: str, findings: list[Finding],
             controls: dict[str, bool] | None = None) -> bool:
    """Whether this run holds any evidence bearing on ``axis``.

    False is a statement about coverage, not about the code: nothing mapped here and nothing
    proved a control here, so the audit has no basis for a number.
    """
    return bool(assessed_subs(axis, findings, controls))


def _clamp(value: float) -> float:
    return round(min(BASE, max(FLOOR, value)), 1)


def _ref(finding: Finding) -> str:
    loc = finding.locations[0].file if finding.locations else ""
    return f"{finding.id} {finding.title}"[:90] + (f" ({loc})" if loc else "")


@dataclass
class _Term:
    """One deduction on an axis: an individual finding, or one severity band of an aggregate."""

    item: str
    short: str
    effect: float
    justification: str
    sub: str


def _terms(axis: str, findings: list[Finding]) -> list[_Term]:
    """Every deduction on ``axis``, in the order Annex A prints it.

    Individually-promotable findings first, severity-descending, one term each. Then one term
    per (aggregate class, sub, severity band) - a ``dependency`` or ``iac`` class is one ``G``
    directory in ``findings/`` (spec §A2), so it is one deduction per band here rather than one
    per row. Grouping on the sub as well as the class keeps the sub scores consistent with the
    axis total, since the same class can resolve two subs (trivy's ``A05:Misconfiguration`` rows
    land on ``configuration``, its ``A06`` rows on ``dependency_hygiene``).
    """
    mine = [f for f in findings if axis_for(f) == axis]
    single = sorted((f for f in mine if f.finding_class not in AGGREGATE_CLASSES),
                    key=lambda f: (-f.severity.rank, -f.cvss_score, f.id))
    terms = []
    for f in single:
        effect = DEDUCTION[f.severity]
        if not effect:
            continue
        sub = sub_for(f, axis)
        terms.append(_Term(_ref(f), f"{f.id} ({f.severity.value} {effect:+.2f})", effect,
                           f"{f.severity.value} · {f.category or 'uncategorized'} · "
                           f"{sub} · {f.source or 'unknown source'}", sub))

    bands: dict[tuple[str, str, Severity], int] = {}
    for f in mine:
        if f.finding_class not in AGGREGATE_CLASSES:
            continue
        key = (f.finding_class, sub_for(f, axis), f.severity)
        bands[key] = bands.get(key, 0) + 1
    for cls, sub, severity in sorted(bands, key=lambda k: (AGGREGATE_CLASSES.index(k[0]),
                                                           k[1], -k[2].rank)):
        effect = DEDUCTION[severity]
        if not effect:
            continue
        count = bands[(cls, sub, severity)]
        terms.append(_Term(f"Aggregate · {cls} · {severity.value} ({count} row(s))",
                           f"aggregate {cls} ×{count} ({severity.value} {effect:+.2f})", effect,
                           f"{severity.value} · rolled-up {cls}-class rows scored once per "
                           f"severity band, not once per row · {sub}", sub))
    return terms


def axis_rows(axis: str, findings: list[Finding],
              controls: dict[str, bool] | None = None) -> list[Row]:
    """The arithmetic behind one axis, in the order Annex A prints it.

    Passed the finding set explicitly so the module holds no state and the annex can be
    regenerated from ``findings.json`` alone. :meth:`Scorecard.axis_rows` is the one-argument
    form for callers that already hold a scorecard.

    Empty when the axis was not assessed. There is no arithmetic to print, and a lone
    ``Baseline +10.00`` row totalling a perfect ten is the claim this whole rule exists to stop.
    """
    if axis not in SUBS:
        raise KeyError(f"unknown axis '{axis}'; choose from {list(AXES)}")
    controls = controls or {}
    if not assessed(axis, findings, controls):
        return []
    rows = [Row("Baseline", BASE,
                "every assessed axis starts at the maximum and is deducted from")]
    rows.extend(Row(t.item, t.effect, t.justification) for t in _terms(axis, findings))

    for control in GATE_CONTROLS:
        if CONTROL_MAP.get(control, (None, None))[0] != axis:
            continue
        if controls.get(control) is True:
            rows.append(Row(control, CONTROL_BONUS, "control proven in controls.json"))

    # A clamp row is emitted only for a genuine clamp. The final rounding to one decimal is
    # not a term of the arithmetic, so it does not get a row of its own.
    raw = sum(r.effect for r in rows)
    bounded = min(BASE, max(FLOOR, raw))
    if abs(raw - bounded) > 1e-9:
        edge = "floor" if raw < FLOOR else "ceiling"
        rows.append(Row(f"Clamped to the {edge}", bounded - raw,
                        f"raw total {raw:+.2f} is outside [{FLOOR:.1f}, {BASE:.1f}]"))
    return rows


def _sub_scores(axis: str, findings: list[Finding], controls: dict[str, bool]) -> list[SubScore]:
    have = assessed_subs(axis, findings, controls)
    terms = _terms(axis, findings)
    out = []
    for key, label in SUBS[axis]:
        raw = BASE
        determined_by: list[str] = []
        for term in terms:
            if term.sub != key:
                continue
            raw += term.effect
            determined_by.append(term.short)
        for control, (c_axis, c_sub) in CONTROL_MAP.items():
            if (c_axis, c_sub) == (axis, key) and controls.get(control) is True:
                raw += CONTROL_BONUS
                determined_by.append(f"{control} (+{CONTROL_BONUS:.1f})")
        out.append(SubScore(key=key, label=label,
                            score=_clamp(raw) if key in have else None,
                            determined_by=determined_by))
    return out


def _coverage_note(axis: str) -> str:
    """Why an axis can end up with nothing scored against it, derived from the two tables.

    Derived rather than written out so it cannot drift from :data:`AXIS_MAP` and
    :data:`CONTROL_MAP`, which are the only things that decide what can reach an axis.
    """
    cats = sorted(k.split(":", 1)[1] for k, v in AXIS_MAP.items()
                  if v == axis and k.startswith("category:"))
    creditors = [c for c, (a, _) in CONTROL_MAP.items() if a == axis]
    named = (", ".join(cats) if len(cats) <= MAX_NAMED_CATEGORIES
             else f"{len(cats)} taxonomy categories")
    if creditors:
        return (f"{named} map here and {len(creditors)} gate control(s) can credit it; on this "
                f"run neither did.")
    return (f"No gate control credits this axis, so a mapped finding is the only evidence that "
            f"can ever reach it - and only {named} map here.")


def _unassessed_reading(axis: str) -> str:
    parts = [f"{NOT_ASSESSED.capitalize()}. Scores {AXIS_SCOPE[axis]}.",
             "No finding maps to this axis and no control in controls.json credits it, so "
             "nothing was measured: absence of a finding is not evidence of a control. The "
             "axis is excluded from the overall figure and is not plotted, because any number "
             "here - 10.0 included - would be a claim this audit did not earn.",
             _coverage_note(axis)]
    caveat = AXIS_COVERAGE_CAVEAT.get(axis)
    if caveat:
        parts.append(caveat)
    return " ".join(parts)


def _reading(axis: str, score: float | None, findings: list[Finding],
             subs: list[SubScore]) -> str:
    if score is None:
        return _unassessed_reading(axis)
    mine = [f for f in findings if axis_for(f) == axis]
    counts = {s: 0 for s in Severity}
    for f in mine:
        counts[f.severity] += 1
    stance = "acceptable" if score >= ACCEPTABLE else "below the acceptability threshold"
    parts = [f"{score:.1f} / {BASE:.0f} - {stance}. Scores {AXIS_SCOPE[axis]}."]
    if not mine:
        parts.append("No finding maps to this axis, so the score rests on the proven controls "
                     "alone.")
    else:
        drivers = ", ".join(f"{counts[s]} {s.value}" for s in
                           (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                            Severity.LOW, Severity.INFO) if counts[s])
        parts.append(f"{len(mine)} finding(s) map here ({drivers}).")
        rolled = [f for f in mine if f.finding_class in AGGREGATE_CLASSES]
        if rolled:
            bands = len({(f.finding_class, f.severity) for f in rolled
                         if DEDUCTION[f.severity]})
            parts.append(f"{len(rolled)} of them are rolled-up scanner rows, deducting once per "
                         f"severity band ({bands} band(s)) rather than once per row.")

    # Naming the not-assessed subs is the honesty term of the reading: no scanner and no agent
    # emits a finding for a mechanism that is simply absent from the codebase, so a sub with
    # nothing scored against it is a statement about coverage, not a clean bill of health. An
    # assessed axis always has at least one assessed sub, so this list is never the whole set.
    blank = [s.label for s in subs if not s.assessed]
    if blank:
        parts.append(f"{NOT_ASSESSED.capitalize()}: {', '.join(blank)} - no finding maps to "
                     f"these and no control credits them, which is not the same as them "
                     f"holding.")
    return " ".join(parts)


def score_axis(axis: str, findings: list[Finding],
               controls: dict[str, bool] | None = None) -> Axis:
    controls = controls or {}
    rows = axis_rows(axis, findings, controls)
    score = _clamp(sum(r.effect for r in rows)) if rows else None
    subs = _sub_scores(axis, findings, controls)
    return Axis(key=axis, label=AXIS_LABELS[axis], score=score, subs=subs,
                reading=_reading(axis, score, findings, subs), rows=rows)


def score(findings: list[Finding], controls: dict[str, bool] | None = None) -> Scorecard:
    """The full six-axis scorecard. Deterministic in ``(findings, controls)``.

    The overall figure averages the *assessed* axes only, and is None when none were. An axis
    nobody measured must not be able to pull the headline number either way.
    """
    axes = [score_axis(a, findings, controls) for a in AXES]
    scored = [a.score for a in axes if a.assessed]
    overall = round(sum(scored) / len(scored), 1) if scored else None
    return Scorecard(axes=axes, overall=overall, method=METHOD)


def class_counts(findings: list[Finding]) -> dict[str, int]:
    """Findings per ``finding_class``, unclassified rolled into ``unclassified``.

    This is the count that makes the scanner-noise correction visible, so it lives next to
    the score rather than inside a renderer.
    """
    out: dict[str, int] = {}
    for f in findings:
        key = (f.finding_class or "").strip().lower() or "unclassified"
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))
