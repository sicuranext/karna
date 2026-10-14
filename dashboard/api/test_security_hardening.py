"""Edits and deletes by position need the entry's content tag; the changelog keeps old content."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

import httpx

import app
import assistant_runtime
import auth
import store

RULE_A = json.dumps({"id": "a", "conditions": [{"variables": ["request.uri"], "op": "rx", "value": "x"}]})
RULE_B = json.dumps({"id": "b", "conditions": [{"variables": ["request.uri"], "op": "rx", "value": "y"}]})


class EntryTagTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = (auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE)
        d = Path(self.tmp.name)
        auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE = str(d), str(d / "auth.json"), str(d / "changes.jsonl")
        self.plugin = {"id": "p1", "name": "karna", "service": {"id": "s1"},
                       "config": {"rules_request": [RULE_A, RULE_B]}}
        self.patched = mock.AsyncMock()
        self.patches = [
            mock.patch.object(app, "_kong_get_plugin", new=mock.AsyncMock(side_effect=lambda c, pid: json.loads(json.dumps(self.plugin)))),
            mock.patch.object(app, "_patch_cfg", new=self.patched),
            mock.patch.object(app, "_kong_service_name", new=mock.AsyncMock(return_value="shop")),
            mock.patch.object(app, "_kong_headers", return_value={}),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE = self.old
        self.tmp.cleanup()

    async def test_delete_without_tag_is_refused(self):
        with self.assertRaises(HTTPException) as ctx:
            await app.delete_rule("p1", "native", 0, None, "admin@example.com")
        self.assertEqual(ctx.exception.status_code, 428)
        self.patched.assert_not_awaited()

    async def test_stale_tag_is_refused(self):
        # the operator saw rule "a" at index 0, but meanwhile "b" moved there
        seen = app._etag(RULE_A)
        self.plugin["config"]["rules_request"] = [RULE_B]
        with self.assertRaises(HTTPException) as ctx:
            await app.delete_rule("p1", "native", 0, seen, "admin@example.com")
        self.assertEqual(ctx.exception.status_code, 409)
        self.patched.assert_not_awaited()

    async def test_matching_tag_deletes_and_records_the_old_content(self):
        await app.delete_rule("p1", "native", 1, app._etag(RULE_B), "admin@example.com")
        cfg = self.patched.await_args.args[2]
        self.assertEqual(cfg["rules_request"], [RULE_A])
        change = auth.read_changes(1)[0]
        self.assertEqual(change["action"], "rule_remove")
        self.assertEqual(json.loads(change["before"])["id"], "b")

    async def test_edit_records_before_and_after(self):
        new = {"id": "a", "conditions": [{"variables": ["request.uri"], "op": "rx", "value": "z"}],
               "action": {"fixed_response": {"status_code": 403}}}
        await app.edit_rule("p1", "native", 0, {"rule": new}, app._etag(RULE_A), "admin@example.com")
        change = auth.read_changes(1)[0]
        self.assertEqual(json.loads(change["before"])["conditions"][0]["value"], "x")
        self.assertEqual(json.loads(change["after"])["conditions"][0]["value"], "z")


class StoreCapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = (store.DATA_DIR, store.DB_PATH, store.MAX_EVENTS)
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR, store.DB_PATH = self.tmp.name, str(Path(self.tmp.name) / "events.db")
        store.init()

    def tearDown(self):
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR, store.DB_PATH, store.MAX_EVENTS = self.old
        self.tmp.cleanup()

    def test_oldest_rows_beyond_the_ceiling_are_dropped(self):
        import time
        now = int(time.time() * 1000)
        c = store._connect()
        for i in range(10):
            c.execute("INSERT INTO events(request_id,ts,raw) VALUES(?,?,?)", (f"r{i}", now - (10 - i) * 1000, "{}"))
        c.commit()
        store.MAX_EVENTS = 6
        self.assertEqual(store.cleanup_ttl(), 4)
        kept = [r[0] for r in store._connect().execute("SELECT request_id FROM events ORDER BY ts")]
        self.assertEqual(kept, [f"r{i}" for i in range(4, 10)])
        self.assertEqual(store.stats()["max_events"], 6)


class StreamAndSecretTests(unittest.IsolatedAsyncioTestCase):
    async def lines(self, body: bytes, limit: int):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body))) as c:
            response = await c.get("http://provider.test/")
            return [line async for line in assistant_runtime._bounded_lines(response, limit)]

    async def test_lines_are_split_and_an_endless_line_is_refused(self):
        self.assertEqual(await self.lines(b'data: {"a":1}\r\n\ndata: x\nlast', 100),
                         ['data: {"a":1}', "", "data: x", "last"])
        with self.assertRaises(HTTPException) as ctx:
            await self.lines(b"data: " + b"x" * 5000, 1000)
        self.assertEqual(ctx.exception.status_code, 502)

    def test_short_signing_secret_is_refused(self):
        with mock.patch.dict("os.environ", {"KARNA_DASH_SECRET": "too-short"}):
            with self.assertRaises(auth.AuthError):
                auth._secret()
        with mock.patch.dict("os.environ", {"KARNA_DASH_SECRET": "x" * 32}):
            self.assertEqual(auth._secret(), b"x" * 32)


if __name__ == "__main__":
    unittest.main()
