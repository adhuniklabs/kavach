import os
import tempfile
import unittest

from kavach.finding import Severity
from kavach.scanners.fail_open_defaults import FailOpenDefaultsScanner
from kavach.scanners.rust_secret_apis import RustSecretApisScanner


def _write(dirpath, rel, content):
    path = os.path.join(dirpath, rel)
    os.makedirs(os.path.dirname(path) or dirpath, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


class TestFailOpenDefaultsScanner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_fallback_secret_is_critical(self):
        _write(self.dir, "config.py",
              "SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-123')\n")
        findings = FailOpenDefaultsScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        self.assertIn("fallback-secret", rules)
        self.assertEqual(rules["fallback-secret"].severity, Severity.CRITICAL)

    def test_fail_open_auth_flag_is_high(self):
        _write(self.dir, "security.py",
              "REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'false').lower() == 'true'\n")
        findings = FailOpenDefaultsScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        self.assertIn("fail-open-flag", rules)
        self.assertEqual(rules["fail-open-flag"].severity, Severity.HIGH)

    def test_cors_wildcard_is_high(self):
        _write(self.dir, "server.js", "app.use(cors({ origin: '*' }));\n")
        findings = FailOpenDefaultsScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        self.assertIn("cors-wildcard", rules)
        self.assertEqual(rules["cors-wildcard"].severity, Severity.HIGH)

    def test_get_or_literal_idiom_is_flagged(self):
        _write(self.dir, "config.py", "SECRET = env.get('KEY') or 'default'\n")
        findings = FailOpenDefaultsScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        self.assertIn("fallback-secret", rules)

    def test_os_environ_get_or_literal_idiom_is_flagged(self):
        _write(self.dir, "config.py",
              "SECRET_KEY = os.environ.get('APP_SECRET') or 'insecure-default-value'\n")
        findings = FailOpenDefaultsScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        self.assertIn("fallback-secret", rules)

    def test_flags_its_own_docstring_example(self):
        import kavach.scanners.fail_open_defaults as mod
        scanner_dir = os.path.dirname(os.path.abspath(mod.__file__))
        findings = FailOpenDefaultsScanner().run(scanner_dir, {}).findings
        hits = [f for f in findings
               if f.rule_id == "fallback-secret" and f.locations[0].file == "fail_open_defaults.py"]
        self.assertTrue(hits)

    def test_secure_fallback_is_not_flagged(self):
        _write(self.dir, "config.py", "SECRET_KEY = os.environ['SECRET_KEY']\n")
        findings = FailOpenDefaultsScanner().run(self.dir, {}).findings
        self.assertEqual(findings, [])

    def test_applies_always(self):
        self.assertTrue(FailOpenDefaultsScanner().applies({}))

    def test_minified_js_is_skipped(self):
        # splitext("bundle.min.js") -> ext ".js", which is not itself skippable - the
        # ".min.js" entry in _SKIP_EXT could never match through splitext(). Minified
        # bundles are noise (and can legitimately contain this exact source text), so
        # they must be skipped via a suffix check instead.
        _write(self.dir, "bundle.min.js",
              "SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-123')\n")
        findings = FailOpenDefaultsScanner().run(self.dir, {}).findings
        self.assertEqual(findings, [])


class TestRustSecretApisScanner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_mem_forget_severity_matches_its_own_cvss_score(self):
        _write(self.dir, "src/lib.rs",
              "fn drop_key(key: SecretKey) {\n    mem::forget(key);\n}\n")
        findings = RustSecretApisScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        self.assertIn("mem-forget", rules)
        f = rules["mem-forget"]
        # honest derivation, not a hardcoded band: severity must agree with the CVSS
        # score actually carried on the finding (which itself must agree with its vector -
        # AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N computes to 6.2, i.e. Medium, not 9.1/Critical).
        self.assertEqual(f.severity, Severity.from_cvss(f.cvss_score))
        self.assertEqual(f.severity, Severity.MEDIUM)
        self.assertEqual(f.kill_chain, "steal-keys")

    def test_manually_drop_severity_matches_its_own_cvss_score(self):
        _write(self.dir, "src/lib.rs",
              "let wrapped = ManuallyDrop::new(secret_key);\n")
        findings = RustSecretApisScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        self.assertIn("manually-drop", rules)
        f = rules["manually-drop"]
        self.assertEqual(f.severity, Severity.from_cvss(f.cvss_score))
        self.assertEqual(f.severity, Severity.MEDIUM)

    def test_box_leak_and_box_into_raw_severity_matches_cvss_score(self):
        _write(self.dir, "src/lib.rs",
              "let leaked = Box::leak(Box::new(token));\n"
              "let raw = Box::into_raw(Box::new(token));\n")
        findings = RustSecretApisScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        for rule_id in ("box-leak", "box-into-raw"):
            f = rules[rule_id]
            self.assertEqual(f.severity, Severity.from_cvss(f.cvss_score), rule_id)
            self.assertEqual(f.severity, Severity.MEDIUM, rule_id)
        # "direct" (box-leak) and "conditional" (box-into-raw) are still distinguishable
        # by score even though both land in the Medium severity band.
        self.assertGreater(rules["box-leak"].cvss_score, rules["box-into-raw"].cvss_score)

    def test_ptr_write_bytes_severity_matches_its_own_cvss_score(self):
        _write(self.dir, "src/lib.rs",
              "unsafe { ptr::write_bytes(secret.as_mut_ptr(), 0, secret.len()); }\n")
        findings = RustSecretApisScanner().run(self.dir, {}).findings
        rules = {f.rule_id: f for f in findings}
        self.assertIn("non-volatile-wipe", rules)
        f = rules["non-volatile-wipe"]
        self.assertEqual(f.severity, Severity.from_cvss(f.cvss_score))
        self.assertEqual(f.severity, Severity.MEDIUM)

    def test_commented_out_line_is_ignored(self):
        _write(self.dir, "src/lib.rs", "// mem::forget(key);\n")
        findings = RustSecretApisScanner().run(self.dir, {}).findings
        self.assertEqual(findings, [])

    def test_applies_only_when_rust_present(self):
        scanner = RustSecretApisScanner()
        self.assertTrue(scanner.applies({"languages": ["Rust"]}))
        self.assertFalse(scanner.applies({"languages": ["Python"]}))


if __name__ == "__main__":
    unittest.main()
