from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

import ai_profiles
import auth
import store


class AIProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmp.name)
        self.old_store = (store.DATA_DIR, store.DB_PATH)
        self.old_auth = (auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE)
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR = str(self.data_dir)
        store.DB_PATH = str(self.data_dir / "events.db")
        auth.DATA_DIR = str(self.data_dir)
        auth.AUTH_FILE = str(self.data_dir / "auth.json")
        auth.CHANGES_FILE = str(self.data_dir / "changes.jsonl")
        store.init()

    def tearDown(self):
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR, store.DB_PATH = self.old_store
        auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE = self.old_auth
        self.tmp.cleanup()

    def test_cloud_profile_encrypts_key_and_never_returns_it(self):
        profile, cipher, keep = ai_profiles.normalize({
            "name": "OpenAI production",
            "provider": "openai",
            "model": "gpt-5.6-terra",
            "api_key": "sk-secret-value",
        })
        saved = store.save_ai_profile(profile, cipher, keep)

        self.assertTrue(saved["api_key_configured"])
        self.assertNotIn("api_key_cipher", saved)
        internal = store.get_ai_profile(saved["id"], include_cipher=True)
        self.assertNotIn("sk-secret-value", internal["api_key_cipher"])
        _, key = ai_profiles.saved_with_key(saved["id"])
        self.assertEqual(key, "sk-secret-value")

    def test_first_profile_becomes_default_and_replacement_is_promoted(self):
        first, first_cipher, _ = ai_profiles.normalize({
            "name": "Local", "provider": "ollama", "model": "qwen3:8b",
        })
        second, second_cipher, _ = ai_profiles.normalize({
            "name": "Local two", "provider": "lmstudio", "model": "qwen3-8b",
        })
        first_saved = store.save_ai_profile(first, first_cipher)
        second_saved = store.save_ai_profile(second, second_cipher)
        self.assertTrue(first_saved["is_default"])
        self.assertFalse(second_saved["is_default"])

        store.delete_ai_profile(first_saved["id"])
        self.assertTrue(store.get_ai_profile(second_saved["id"])["is_default"])

    def test_huggingface_bill_to_becomes_only_the_expected_header(self):
        profile, _, _ = ai_profiles.normalize({
            "name": "HF security", "provider": "huggingface",
            "model": "openai/gpt-oss-120b:preferred", "api_key": "hf_secret",
            "options": {"bill_to": "security-team"},
        })
        headers = ai_profiles._headers(profile, "hf_secret")
        self.assertEqual(headers["X-HF-Bill-To"], "security-team")
        self.assertEqual(headers["authorization"], "Bearer hf_secret")

    def test_rejects_unknown_options_and_cloud_endpoint_override(self):
        bad = [
            {"name": "HF", "provider": "huggingface", "model": "model", "api_key": "x",
             "options": {"arbitrary_header": "secret"}},
            {"name": "OpenAI", "provider": "openai", "model": "gpt-5", "api_key": "x",
             "base_url": "https://attacker.example/v1"},
        ]
        for payload in bad:
            with self.subTest(payload=payload), self.assertRaises(HTTPException):
                ai_profiles.normalize(payload)

    def test_custom_endpoint_rejects_metadata_and_link_local_addresses(self):
        for endpoint in ("http://169.254.169.254/v1", "http://metadata.google.internal/v1", "http://[::]/v1"):
            with self.subTest(endpoint=endpoint), self.assertRaises(HTTPException):
                ai_profiles.normalize({
                    "name": "Unsafe custom", "provider": "custom", "model": "model",
                    "base_url": endpoint,
                })


if __name__ == "__main__":
    unittest.main()
