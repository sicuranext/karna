"""Login throttling and timing, session revocation, AI key re-entry, proposal review."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

import ai_profiles
import app
import auth
import store

PASSWORD = "correct horse battery"


class _Data(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.old = (auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE, store.DATA_DIR, store.DB_PATH)
        auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE = str(d), str(d / "auth.json"), str(d / "changes.jsonl")
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR, store.DB_PATH = str(d), str(d / "events.db")
        store.init()
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        os.environ.pop(auth.SETUP_TOKEN_ENV, None)

    def tearDown(self):
        self.env.stop()
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE, store.DATA_DIR, store.DB_PATH = self.old
        self.tmp.cleanup()

    def admin(self) -> str:
        token, _ = auth.ensure_setup_token()
        return auth.register("admin@example.com", PASSWORD, token)


class LoginTests(_Data):
    def test_wrong_email_still_runs_scrypt(self):
        self.admin()
        with mock.patch.object(auth, "_hash_password", wraps=auth._hash_password) as hashed:
            with self.assertRaises(auth.AuthError):
                auth.check_login("nobody@example.com", PASSWORD)
            self.assertEqual(hashed.call_count, 1)

    def test_non_text_login_is_422(self):
        self.admin()
        with self.assertRaises(auth.AuthError) as ctx:
            auth.check_login({"$ne": 1}, PASSWORD)
        self.assertEqual(ctx.exception.status, 422)


class ThrottleTests(unittest.TestCase):
    def test_lockout_is_global_grows_and_success_clears_it(self):
        t = auth.Throttle(free=10, window=900, cap=900)
        for i in range(10):
            t.failure(now=1000 + i)
        self.assertEqual(t.wait(now=1010), 0)          # ten free failures, from anyone
        t.failure(now=1010)
        self.assertEqual(t.wait(now=1010), 30)
        t.failure(now=1041)
        self.assertEqual(t.wait(now=1041), 60)
        t.success()
        self.assertEqual(t.wait(now=1041), 0)

    def test_old_failures_fall_out_of_the_window(self):
        t = auth.Throttle(free=10, window=900)
        for i in range(10):
            t.failure(now=float(i))
        t.failure(now=2000.0)
        self.assertEqual(t.wait(now=2000.0), 0)

    def test_lockout_is_capped(self):
        t = auth.Throttle(free=0, window=10 ** 6, cap=900)
        for i in range(40):
            t.failure(now=float(i))
        self.assertLessEqual(t.wait(now=40.0), 900)


class SessionTests(_Data):
    def test_sign_out_everywhere_revokes_old_tokens(self):
        token = self.admin()
        self.assertEqual(auth.verify_token(token), "admin@example.com")
        auth.revoke_sessions()
        self.assertIsNone(auth.verify_token(token))
        fresh = auth.check_login("admin@example.com", PASSWORD)
        self.assertEqual(auth.verify_token(fresh), "admin@example.com")

    def test_password_change_revokes_and_reissues(self):
        old = self.admin()
        with self.assertRaises(auth.AuthError) as ctx:
            auth.change_password("admin@example.com", "not the password", "a brand new secret")
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(auth.AuthError) as ctx:
            auth.change_password("admin@example.com", PASSWORD, "short")
        self.assertEqual(ctx.exception.status, 422)
        new = auth.change_password("admin@example.com", PASSWORD, "a brand new secret")
        self.assertIsNone(auth.verify_token(old))
        self.assertEqual(auth.verify_token(new), "admin@example.com")
        with self.assertRaises(auth.AuthError):
            auth.check_login("admin@example.com", PASSWORD)
        self.assertTrue(auth.check_login("admin@example.com", "a brand new secret"))


class AIKeyReuseTests(_Data):
    def saved_openai(self):
        profile, cipher, keep = ai_profiles.normalize({
            "name": "OpenAI", "provider": "openai", "model": "gpt-x", "api_key": "sk-secret-value"})
        return store.save_ai_profile(profile, cipher, keep_api_key=keep)

    def test_saved_key_is_not_reused_for_another_host_or_provider(self):
        saved = self.saved_openai()
        existing = store.get_ai_profile(saved["id"])
        for payload in (
            {"id": saved["id"], "name": "x", "provider": "custom", "model": "m", "base_url": "https://attacker.example/v1"},
            {"id": saved["id"], "name": "x", "provider": "openrouter", "model": "m"},
        ):
            with self.assertRaises(HTTPException) as ctx:
                ai_profiles.normalize(payload, existing)
            self.assertEqual(ctx.exception.status_code, 422)

    def test_saved_key_is_kept_when_only_the_model_changes(self):
        saved = self.saved_openai()
        existing = store.get_ai_profile(saved["id"])
        _, cipher, keep = ai_profiles.normalize(
            {"id": saved["id"], "name": "OpenAI", "provider": "openai", "model": "gpt-y"}, existing)
        self.assertIsNone(cipher)
        self.assertTrue(keep)


class ProposalReviewTests(unittest.TestCase):
    def test_weakening_config_is_flagged(self):
        review = app._proposal_review({"type": "update_config", "plugin_id": "p",
                                       "changes": {"engine_blocking_mode": False, "paranoia_level": 1}})
        self.assertIn("Set engine_blocking_mode to false", review["changes"])
        self.assertIn("Turns blocking off: matches are only logged.", review["risks"])
        self.assertIn("Changes the paranoia level.", review["risks"])

    def test_hardening_config_is_not_flagged(self):
        review = app._proposal_review({"type": "update_config", "plugin_id": "p",
                                       "changes": {"engine_blocking_mode": True, "auditlog_enabled": True}})
        self.assertEqual(review["risks"], [])

    def test_global_passthrough_override_is_flagged(self):
        review = app._proposal_review({"type": "add_override", "plugin_id": "p", "kind": "action",
                                       "entry": {"selector": {"any": True}, "action": {"type": "passthrough"}}})
        self.assertEqual(len(review["risks"]), 2)

    def test_rule_switching_the_engine_off_is_flagged(self):
        review = app._proposal_review({"type": "add_rule", "plugin_id": "p", "kind": "native",
                                       "rule": {"id": "r1", "rule_control": {"engine_off": True}}})
        self.assertTrue(review["risks"])
        plain = app._proposal_review({"type": "add_rule", "plugin_id": "p", "kind": "native",
                                      "rule": {"id": "r2", "action": {"fixed_response": {"status_code": 403}}}})
        self.assertEqual(plain["risks"], [])


if __name__ == "__main__":
    unittest.main()
