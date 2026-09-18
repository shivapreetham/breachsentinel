"""
Tests for api/app_secure.py itself (not just the detector) - exercises the
Flask app in-process via its test client, so these run without starting a
real server or making network calls.

Run with: python -m unittest discover tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jwt

import api.app_secure as app_secure


class AppSecureTestCase(unittest.TestCase):
    def setUp(self):
        app_secure.init_db()
        app_secure._login_attempts.clear()
        self.client = app_secure.app.test_client()

    def login(self, username, password):
        return self.client.post("/login", json={"username": username, "password": password})

    def auth_get(self, path, token):
        return self.client.get(path, headers={"Authorization": f"Bearer {token}"})

    # --- basic auth flow ---------------------------------------------------

    def test_health(self):
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_login_with_correct_password_returns_token(self):
        resp = self.login("alice", "password123")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("token", resp.get_json())

    def test_login_with_wrong_password_rejected(self):
        resp = self.login("alice", "not-the-password")
        self.assertEqual(resp.status_code, 401)

    def test_login_with_unknown_username_rejected(self):
        resp = self.login("nobody", "whatever")
        self.assertEqual(resp.status_code, 401)

    # --- rate limiting ---------------------------------------------------

    def test_login_rate_limited_after_repeated_failures(self):
        for _ in range(app_secure.LOGIN_ATTEMPT_LIMIT):
            resp = self.login("bob", "wrong")
            self.assertEqual(resp.status_code, 401)
        # one more than the limit within the window should now be throttled
        resp = self.login("bob", "wrong")
        self.assertEqual(resp.status_code, 429)

    def test_correct_password_still_works_below_the_limit(self):
        for _ in range(app_secure.LOGIN_ATTEMPT_LIMIT - 1):
            self.login("bob", "wrong")
        resp = self.login("bob", "letmein123")
        self.assertEqual(resp.status_code, 200)

    # --- JWT algorithm handling ---------------------------------------------------

    def test_alg_none_token_rejected(self):
        forged = jwt.encode(
            {"sub": 0, "username": "admin", "tenant_id": 0, "role": "admin"},
            key="",
            algorithm="none",
        )
        resp = self.auth_get("/tenants/0/documents", forged)
        self.assertEqual(resp.status_code, 401)

    def test_token_signed_with_wrong_secret_rejected(self):
        forged = jwt.encode(
            {"sub": 0, "username": "admin", "tenant_id": 0, "role": "admin"},
            key="some-other-secret",
            algorithm="HS256",
        )
        resp = self.auth_get("/tenants/0/documents", forged)
        self.assertEqual(resp.status_code, 401)

    def test_missing_token_rejected(self):
        resp = self.client.get("/tenants/1/documents")
        self.assertEqual(resp.status_code, 401)

    # --- BOLA / tenant authorization ---------------------------------------------------

    def test_user_can_access_own_tenant(self):
        token = self.login("alice", "password123").get_json()["token"]
        resp = self.auth_get("/tenants/1/documents", token)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.get_json()) > 0)

    def test_user_cannot_access_foreign_tenant_list(self):
        token = self.login("alice", "password123").get_json()["token"]
        resp = self.auth_get("/tenants/2/documents", token)
        self.assertEqual(resp.status_code, 403)

    def test_user_cannot_access_foreign_tenant_document(self):
        token = self.login("alice", "password123").get_json()["token"]
        resp = self.auth_get("/tenants/2/documents/3", token)
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_access_any_tenant(self):
        token = self.login("admin", "admin123").get_json()["token"]
        resp = self.auth_get("/tenants/2/documents", token)
        self.assertEqual(resp.status_code, 200)

    # --- SQL injection ---------------------------------------------------

    def test_search_returns_matching_rows(self):
        resp = self.client.get("/search", query_string={"q": "Alice"})
        self.assertEqual(resp.status_code, 200)
        titles = [r["title"] for r in resp.get_json()]
        self.assertTrue(any("Alice" in t for t in titles))

    def test_search_sqli_payload_returns_no_rows(self):
        resp = self.client.get("/search", query_string={"q": "' OR '1'='1"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), [])

    def test_search_sqli_drop_table_payload_does_not_error_or_drop_table(self):
        resp = self.client.get("/search", query_string={"q": "'; DROP TABLE documents; --"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), [])
        # table must still exist and be intact for a normal search afterward
        resp2 = self.client.get("/search", query_string={"q": "Alice"})
        self.assertEqual(resp2.status_code, 200)
        self.assertTrue(len(resp2.get_json()) > 0)


if __name__ == "__main__":
    unittest.main()
