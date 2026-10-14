"""First-run setup state: completed once, kept server-side, recorded in the change log."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

import app
import auth
import store


class SetupStateTests(unittest.TestCase):
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

    def tearDown(self):
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE, store.DATA_DIR, store.DB_PATH = self.old
        self.tmp.cleanup()

    def test_not_completed_on_a_new_console(self):
        state = asyncio.run(app.setup_state(sub="admin@example.com"))
        self.assertEqual(state, {"completed": False, "completed_at": None})

    def test_complete_persists_and_is_audited(self):
        out = asyncio.run(app.setup_complete(payload={}, sub="admin@example.com"))
        self.assertTrue(out["ok"])
        state = asyncio.run(app.setup_state(sub="admin@example.com"))
        self.assertTrue(state["completed"])
        self.assertEqual(state["completed_at"], out["completed_at"])
        self.assertEqual(auth.read_changes(10)[0]["action"], "setup_completed")

    def test_skip_is_recorded_as_skip(self):
        asyncio.run(app.setup_complete(payload={"skipped": True}, sub="admin@example.com"))
        self.assertTrue(asyncio.run(app.setup_state(sub="admin@example.com"))["completed"])
        self.assertEqual(auth.read_changes(10)[0]["action"], "setup_skipped")


if __name__ == "__main__":
    unittest.main()
