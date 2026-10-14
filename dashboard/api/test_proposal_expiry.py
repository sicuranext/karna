"""Legacy assistant proposals expire after ACTION_TTL_SECONDS, like actions."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import app
import store


class ProposalExpiryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_store = (store.DATA_DIR, store.DB_PATH)
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR = self.tmp.name
        store.DB_PATH = str(Path(self.tmp.name) / "events.db")
        store.init()
        conv = store.create_conversation("profile-id", "t")
        self.proposal = store.add_assistant_proposal(conv["id"], "m1", "raise paranoia", {
            "type": "update_config", "plugin_id": "p1", "changes": {"paranoia_level": 2}})

    def tearDown(self):
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR, store.DB_PATH = self.old_store
        self.tmp.cleanup()

    def age(self, seconds):
        with store._lock:
            c = store._connect()
            c.execute("UPDATE assistant_proposals SET created_at=created_at-? WHERE id=?",
                      (seconds * 1000, self.proposal["id"]))
            c.commit()

    def present(self):
        with patch.object(app, "_plugin_service_name", AsyncMock(return_value="shop")):
            return asyncio.run(app._present_proposal(store.get_assistant_proposal(self.proposal["id"])))

    def test_fresh_proposal_carries_its_deadline(self):
        out = self.present()
        self.assertEqual(out["status"], "pending")
        self.assertEqual(out["expires_at"], self.proposal["created_at"] + app.ACTION_TTL_SECONDS * 1000)

    def test_old_proposal_turns_expired_and_cannot_be_applied(self):
        self.age(app.ACTION_TTL_SECONDS + 1)
        self.assertEqual(self.present()["status"], "expired")
        self.assertEqual(store.get_assistant_proposal(self.proposal["id"])["status"], "expired")
        with patch.object(app, "patch_engine", AsyncMock()) as patched, \
             patch.object(app, "_plugin_service_name", AsyncMock(return_value="shop")):
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(app.assistant_proposal_apply(self.proposal["id"], {"confirm_service": "shop"}, sub="admin"))
        self.assertEqual(ctx.exception.status_code, 410)
        patched.assert_not_called()


if __name__ == "__main__":
    unittest.main()
