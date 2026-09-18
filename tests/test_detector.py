"""
Unit tests for detector.Detector - the point isn't just "does it fire",
but also "does it stay quiet on traffic that looks similar but isn't an
attack" (false positives are what make rule-based detection untrustworthy).

Run with: python -m unittest discover tests
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import detector.detector as detector_module
from detector.detector import Detector


class DetectorTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self._orig_alerts_path = detector_module.ALERTS_PATH
        self._orig_blocklist_path = detector_module.BLOCKLIST_PATH
        detector_module.ALERTS_PATH = self.tmp_dir / "alerts.jsonl"
        detector_module.BLOCKLIST_PATH = self.tmp_dir / "blocklist.json"
        self.detector = Detector()

    def tearDown(self):
        detector_module.ALERTS_PATH = self._orig_alerts_path
        detector_module.BLOCKLIST_PATH = self._orig_blocklist_path
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def feed(self, **event):
        self.detector.process_line(json.dumps(event))

    def rules_fired(self):
        return [a["rule"] for a in self.detector.alerts]

    # --- JWT alg=none ---------------------------------------------------

    def test_jwt_none_alg_flags(self):
        self.feed(ip="1.1.1.1", jwt_alg="none", auth_valid=True, path="/tenants/0/documents", ts=1)
        self.assertIn("JWT_NONE_ALG_BYPASS", self.rules_fired())

    def test_normal_hs256_auth_does_not_flag(self):
        self.feed(ip="1.1.1.1", jwt_alg="HS256", auth_valid=True, path="/tenants/1/documents", ts=1)
        self.assertEqual(self.rules_fired(), [])

    # --- Login brute force ------------------------------------------------

    def test_failed_logins_below_threshold_do_not_flag(self):
        for i in range(3):
            self.feed(ip="2.2.2.2", event="login", auth_valid=False, username="bob", ts=i)
        self.assertEqual(self.rules_fired(), [])

    def test_failed_logins_at_threshold_flags(self):
        for i in range(4):
            self.feed(ip="2.2.2.2", event="login", auth_valid=False, username="bob", ts=i)
        self.assertIn("LOGIN_BRUTE_FORCE", self.rules_fired())

    def test_failed_logins_outside_window_do_not_accumulate(self):
        for i in range(3):
            self.feed(ip="2.2.2.2", event="login", auth_valid=False, username="bob", ts=i)
        # 4th failure arrives well outside the 10s window - should not join the first 3.
        self.feed(ip="2.2.2.2", event="login", auth_valid=False, username="bob", ts=100)
        self.assertEqual(self.rules_fired(), [])

    def test_successful_login_after_threshold_escalates_to_high(self):
        for i in range(4):
            self.feed(ip="2.2.2.2", event="login", auth_valid=False, username="bob", ts=i)
        self.feed(ip="2.2.2.2", event="login", auth_valid=True, username="bob", ts=5)
        self.assertIn("LOGIN_BRUTE_FORCE_SUCCESS", self.rules_fired())

    def test_isolated_single_failed_login_does_not_flag(self):
        self.feed(ip="3.3.3.3", event="login", auth_valid=False, username="alice", ts=1)
        self.assertEqual(self.rules_fired(), [])

    # --- IDOR enumeration ---------------------------------------------------

    def test_single_foreign_tenant_access_does_not_flag(self):
        self.feed(
            ip="4.4.4.4", event="get_document", auth_valid=True,
            token_tenant=1, path_tenant=2, user="alice", ts=1,
        )
        self.assertEqual(self.rules_fired(), [])

    def test_multiple_foreign_tenants_flags(self):
        self.feed(
            ip="4.4.4.4", event="get_document", auth_valid=True,
            token_tenant=1, path_tenant=2, user="alice", ts=1,
        )
        self.feed(
            ip="4.4.4.4", event="get_document", auth_valid=True,
            token_tenant=1, path_tenant=3, user="alice", ts=2,
        )
        self.assertIn("IDOR_ENUMERATION", self.rules_fired())

    def test_accessing_own_tenant_repeatedly_does_not_flag(self):
        for i in range(5):
            self.feed(
                ip="4.4.4.4", event="get_document", auth_valid=True,
                token_tenant=1, path_tenant=1, user="alice", ts=i,
            )
        self.assertEqual(self.rules_fired(), [])

    # --- SQL injection ---------------------------------------------------

    def test_sqli_payload_flags(self):
        self.feed(ip="5.5.5.5", event="search", query_param="' OR '1'='1", ts=1)
        self.assertIn("SQLI_ATTEMPT", self.rules_fired())

    def test_benign_search_does_not_flag(self):
        self.feed(ip="5.5.5.5", event="search", query_param="invoice", ts=1)
        self.assertEqual(self.rules_fired(), [])

    def test_search_term_containing_or_word_does_not_falsely_flag(self):
        # "or" as an ordinary English word shouldn't trip the SQLi signature.
        self.feed(ip="5.5.5.5", event="search", query_param="roadmap or notes", ts=1)
        self.assertEqual(self.rules_fired(), [])

    # --- Auto-block response ---------------------------------------------------

    def test_ip_auto_blocked_after_two_high_alerts(self):
        self.feed(ip="6.6.6.6", jwt_alg="none", auth_valid=True, path="/tenants/0/documents", ts=1)
        self.feed(ip="6.6.6.6", event="search", query_param="' OR '1'='1", ts=2)
        self.assertIn("6.6.6.6", self.detector.blocked_ips)
        self.assertTrue(detector_module.BLOCKLIST_PATH.exists())

    def test_ip_not_blocked_after_single_high_alert(self):
        self.feed(ip="7.7.7.7", jwt_alg="none", auth_valid=True, path="/tenants/0/documents", ts=1)
        self.assertNotIn("7.7.7.7", self.detector.blocked_ips)

    def test_unrelated_ip_not_affected_by_another_ips_alerts(self):
        self.feed(ip="6.6.6.6", jwt_alg="none", auth_valid=True, path="/tenants/0/documents", ts=1)
        self.feed(ip="6.6.6.6", event="search", query_param="' OR '1'='1", ts=2)
        self.feed(ip="8.8.8.8", event="search", query_param="notes", ts=3)
        self.assertNotIn("8.8.8.8", self.detector.blocked_ips)


if __name__ == "__main__":
    unittest.main()
