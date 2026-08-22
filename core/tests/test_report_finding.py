import os
import tempfile
import unittest

from kavach import report_finding as rf
from kavach.finding import Finding, Location, Severity, Confidence


def _f():
    return Finding(
        title="IDOR on /orders", severity=Severity.HIGH, category="API1:BOLA",
        source="kavach-api", locations=[Location(file="src/orders.py", line=42)],
        what_it_is=(
            "The /orders/{id} endpoint reads the order id straight from the URL path and "
            "loads the record without checking that the requesting user actually owns it. "
            "Any authenticated session can therefore page through every order in the tenant."
        ),
        how_exploited=(
            "Authenticate as a low-privilege customer, capture a request to GET /orders/1042, "
            "then replay it with sequential or randomized ids (1000-2000). Every response "
            "returns HTTP 200 with a different customer's full order payload, no ownership "
            "check ever rejects the request."
        ),
        business_impact=(
            "Any customer can enumerate and read every other customer's order history, "
            "including shipping address, items purchased, and payment method summary - a "
            "cross-tenant data exposure that breaches contractual confidentiality obligations."
        ),
        remediation=(
            "Load the order by id, then compare order.owner_id against the authenticated "
            "user before returning it; return 404 (not 403) on mismatch to avoid leaking "
            "existence. Add an authorization test that asserts this for every order route."
        ),
        cvss_vector="CVSS:3.1/AV:N/PR:L", cvss_score=8.1, confidence=Confidence.CONFIRMED,
    )


class TestReportFinding(unittest.TestCase):
    def test_render_has_five_sections_and_location(self):
        text = rf.render_report(_f(), commit="abc123")
        for h in ("## Summary", "## Details", "## Root Cause", "## Proof of Concept", "## Impact"):
            self.assertIn(h, text)
        self.assertIn("src/orders.py:42", text)

    def test_is_complete_true_for_rendered(self):
        self.assertTrue(rf.is_complete(rf.render_report(_f())))

    def test_is_complete_false_when_sections_are_out_of_order(self):
        # coverage.py gates the report phases on this predicate, so "all five headings are
        # in here somewhere" is not good enough - a reader needs them in the fixed order
        body = "\n\n".join(f"{h}\n\n{'x' * 150}" for h in
                            ("## Summary", "## Details", "## Impact", "## Proof of Concept",
                             "## Root Cause"))
        self.assertFalse(rf.is_complete(f"# IDOR on /orders\n\n{body}\n"))

    def test_is_complete_false_for_pointer_phrase(self):
        bad = rf.render_report(_f()) + "\n\nsee draft for details\n"
        self.assertFalse(rf.is_complete(bad))

    def test_write_is_idempotent(self):
        d = tempfile.mkdtemp()
        first = rf.write_report(d, _f())
        self.assertIsNotNone(first)
        second = rf.write_report(d, _f())
        self.assertIsNone(second)   # already complete → skip


if __name__ == "__main__":
    unittest.main()
