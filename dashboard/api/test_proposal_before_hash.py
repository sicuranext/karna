"""Legacy assistant proposals apply only to the Karna plugin they were made
against, like actions (2026-10-23 review)."""
from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import app
import store

PLUGIN = {"id": "p1", "name": "karna", "updated_at": 1, "config": {"limit_arg_num": 255}}


class _TempStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_store = (store.DATA_DIR, store.DB_PATH)
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR = self.tmp.name
        store.DB_PATH = str(Path(self.tmp.name) / "events.db")

    def tearDown(self):
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR, store.DB_PATH = self.old_store
        self.tmp.cleanup()


class ProposalBeforeHashTests(_TempStore):
    def setUp(self):
        super().setUp()
        store.init()
        self.plugin = json.loads(json.dumps(PLUGIN))
        conv = store.create_conversation("profile-id", "t")
        self.proposal = store.add_assistant_proposal(
            conv["id"], "m1", "harmless", {"type": "update_config", "plugin_id": "p1",
                                           "changes": {"redis_keepalive_pool_size": 32}},
            before_hash=app._digest(self.plugin))

    def apply(self):
        kong = AsyncMock(side_effect=lambda method, path, body=None: (200, json.loads(json.dumps(self.plugin))))
        with patch.object(app, "_kong_call", kong), \
             patch.object(app, "patch_engine", AsyncMock(return_value={"ok": True})) as patched, \
             patch.object(app, "_plugin_service_name", AsyncMock(return_value="shop")):
            try:
                return asyncio.run(app.assistant_proposal_apply(self.proposal["id"], {}, sub="admin")), patched
            except HTTPException as exc:
                return exc, patched

    def test_unchanged_plugin_applies(self):
        out, patched = self.apply()
        self.assertTrue(out["ok"])
        patched.assert_awaited_once()
        self.assertNotIn("before_hash", out["proposal"])

    def test_changed_plugin_is_refused_and_nothing_is_written(self):
        self.plugin["config"]["paranoia_level"] = 2
        out, patched = self.apply()
        self.assertIsInstance(out, HTTPException)
        self.assertEqual(out.status_code, 409)
        patched.assert_not_called()
        self.assertEqual(store.get_assistant_proposal(self.proposal["id"])["status"], "expired")

    def test_presented_proposal_does_not_carry_the_hash(self):
        with patch.object(app, "_plugin_service_name", AsyncMock(return_value="shop")):
            out = asyncio.run(app._present_proposal(store.get_assistant_proposal(self.proposal["id"])))
        self.assertNotIn("before_hash", out)


class ProposalMigrationTests(_TempStore):
    def test_database_without_the_column_is_migrated(self):
        Path(self.tmp.name).mkdir(exist_ok=True)
        old = sqlite3.connect(store.DB_PATH)
        old.execute("CREATE TABLE assistant_proposals (id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, "
                    "message_id TEXT NOT NULL, summary TEXT NOT NULL, operation TEXT NOT NULL, "
                    "status TEXT NOT NULL DEFAULT 'pending', error TEXT, created_at INTEGER NOT NULL, "
                    "updated_at INTEGER NOT NULL)")
        old.commit()
        old.close()
        store.init()
        conv = store.create_conversation("profile-id", "t")
        proposal = store.add_assistant_proposal(conv["id"], "m1", "s", {"type": "update_config",
                                                                       "plugin_id": "p1", "changes": {}},
                                                before_hash="abc")
        self.assertEqual(store.get_assistant_proposal(proposal["id"])["before_hash"], "abc")


if __name__ == "__main__":
    unittest.main()
