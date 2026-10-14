"""First-run registration needs the setup token; the Kong Admin token only goes to its origin."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app
import auth
import kong_connection


class _AuthDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmp.name)
        self.old_auth = (auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE)
        auth.DATA_DIR = str(self.data_dir)
        auth.AUTH_FILE = str(self.data_dir / "auth.json")
        auth.CHANGES_FILE = str(self.data_dir / "changes.jsonl")
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        os.environ.pop(auth.SETUP_TOKEN_ENV, None)

    def tearDown(self):
        self.env.stop()
        auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE = self.old_auth
        self.tmp.cleanup()


class SetupTokenTests(_AuthDir):
    def test_register_requires_the_setup_token(self):
        token, from_env = auth.ensure_setup_token()
        self.assertTrue(token and not from_env)
        for bad in ("", "wrong", None, 123, token + "x"):
            with self.assertRaises(auth.AuthError) as ctx:
                auth.register("admin@example.com", "correct horse battery", bad)
            self.assertEqual(ctx.exception.status, 403)
        self.assertFalse(auth.account_exists())
        self.assertTrue(auth.register("admin@example.com", "correct horse battery", token))
        self.assertTrue(auth.account_exists())

    def test_token_is_stable_across_restarts_and_deleted_after_use(self):
        first, _ = auth.ensure_setup_token()
        again, _ = auth.ensure_setup_token()
        self.assertEqual(first, again)
        auth.register("admin@example.com", "correct horse battery", first)
        self.assertNotIn("setup_token", auth._load())
        self.assertEqual(auth.ensure_setup_token(), (None, False))
        with self.assertRaises(auth.AuthError) as ctx:
            auth.register("other@example.com", "correct horse battery", first)
        self.assertEqual(ctx.exception.status, 409)

    def test_env_token_wins_and_is_not_persisted(self):
        os.environ[auth.SETUP_TOKEN_ENV] = "operator-chosen-token-123"
        self.assertEqual(auth.ensure_setup_token(), ("operator-chosen-token-123", True))
        self.assertIsNone(auth._load())
        auth.register("admin@example.com", "correct horse battery", " operator-chosen-token-123 ")
        self.assertTrue(auth.account_exists())

    def test_auth_file_is_private(self):
        auth.ensure_setup_token()
        self.assertEqual(os.stat(auth.AUTH_FILE).st_mode & 0o777, 0o600)

    def test_unreadable_state_keeps_registration_closed(self):
        Path(auth.AUTH_FILE).write_text("{ not json", encoding="utf-8")
        self.assertTrue(auth.account_exists())
        self.assertEqual(auth.ensure_setup_token(), (None, False))
        with self.assertRaises(auth.AuthError) as ctx:
            auth.register("admin@example.com", "correct horse battery", "anything")
        self.assertEqual(ctx.exception.status, 409)
        with self.assertRaises(auth.AuthError) as ctx:
            auth.check_login("admin@example.com", "correct horse battery")
        self.assertEqual(ctx.exception.status, 500)
        # the corrupt file was not replaced by a fresh secret
        self.assertEqual(Path(auth.AUTH_FILE).read_text(encoding="utf-8"), "{ not json")

    def test_non_text_credentials_are_rejected_not_crashing(self):
        token, _ = auth.ensure_setup_token()
        with self.assertRaises(auth.AuthError) as ctx:
            auth.register(["a"], {"b": 1}, token)
        self.assertEqual(ctx.exception.status, 422)


class KongTokenOriginTests(unittest.TestCase):
    def setUp(self):
        self.saved = (app.KONG_ADMIN_TOKEN, app.KONG_ADMIN_TOKEN_ORIGIN, app.KONG_ADMIN_DEFAULT_URL)
        app.KONG_ADMIN_TOKEN = "kong-admin-secret"
        app.KONG_ADMIN_TOKEN_ORIGIN = ""
        app.KONG_ADMIN_DEFAULT_URL = "https://kong.internal:8444"

    def tearDown(self):
        app.KONG_ADMIN_TOKEN, app.KONG_ADMIN_TOKEN_ORIGIN, app.KONG_ADMIN_DEFAULT_URL = self.saved

    def conn(self, protocol, host, port):
        return kong_connection.validate({"protocol": protocol, "host": host, "port": port})

    def test_token_only_goes_to_its_origin(self):
        self.assertEqual(app._kong_headers(self.conn("https", "kong.internal", 8444)),
                         {"Kong-Admin-Token": "kong-admin-secret"})
        for other in (self.conn("https", "attacker.example", 443),
                      self.conn("http", "kong.internal", 8444),        # same host, other scheme
                      self.conn("https", "kong.internal", 8001),       # same host, other port
                      self.conn("https", "10.9.9.9", 8444)):            # another private host
            self.assertEqual(app._kong_headers(other), {})

    def test_explicit_origin_overrides_the_default_url(self):
        app.KONG_ADMIN_TOKEN_ORIGIN = "https://admin.kong.internal:8444"
        self.assertEqual(app._kong_headers(self.conn("https", "kong.internal", 8444)), {})
        self.assertTrue(app._kong_headers(self.conn("https", "admin.kong.internal", 8444)))

    def test_misconfigured_origin_sends_the_token_nowhere(self):
        app.KONG_ADMIN_TOKEN_ORIGIN = "https://kong.internal:8444/admin?x=1"
        self.assertEqual(app._kong_headers(self.conn("https", "kong.internal", 8444)), {})

    def test_no_token_no_header(self):
        app.KONG_ADMIN_TOKEN = ""
        self.assertEqual(app._kong_headers(self.conn("https", "kong.internal", 8444)), {})


if __name__ == "__main__":
    unittest.main()
