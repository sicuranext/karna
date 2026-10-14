"""Assistant tools: the deterministic classifier, redaction, and the authorization flow.

The model and Kong are faked: the model is a scripted list of rounds, Kong a dict
of entities. What matters is that no write reaches Kong without an authorization
for exactly the reviewed operation."""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

import app
import assistant_runtime
import assistant_tools as tools
import auth
import store


class ClassifierTests(unittest.TestCase):
    def test_reads(self):
        for name, args in (("search_events", {"rule_id": "942100"}), ("list_services", {}),
                           ("read_skill", {"file": "rules"}), ("get_event", {"request_id": "abc"}),
                           ("kong_request", {"method": "GET", "path": "/services"})):
            with self.subTest(name=name):
                self.assertEqual(tools.classify(name, args).kind, "read")

    def test_every_non_get_kong_call_is_a_write(self):
        self.assertEqual(tools.classify("kong_request", {"method": "DELETE", "path": "/routes/r1"}).kind, "write")
        for method in ("POST", "PUT", "PATCH"):
            with self.subTest(method=method):
                verdict = tools.classify("kong_request", {"method": method, "path": "/services", "body": {"name": "a"}})
                self.assertEqual(verdict.kind, "write")

    def test_typed_writes(self):
        self.assertEqual(tools.classify("karna_update_config", {"service": "s", "changes": {"paranoia_level": 2}}).kind, "write")
        self.assertEqual(tools.classify("console_set_retention", {"days": 7}).kind, "write")

    def test_blocked(self):
        cases = [
            ("drop_database", {}),                                                  # unknown tool
            ("kong_request", {"method": "TRACE", "path": "/"}),                     # method
            ("kong_request", {"method": "GET", "path": "http://evil/"}),            # absolute URL
            ("kong_request", {"method": "GET", "path": "/services/../admin"}),      # traversal
            ("kong_request", {"method": "GET", "path": "//evil.example/x"}),        # host smuggling
            ("kong_request", {"method": "GET", "path": "/a%2f..%2fb"}),             # encoded separators
            ("kong_request", {"method": "GET", "path": "/services", "body": {}}),   # GET with body
            ("kong_request", {"method": "POST", "path": "/services"}),              # missing body
            ("kong_request", {"method": "PATCH", "path": "/plugins/p",              # redacted write-back
                              "body": {"config": {"redis_password": "[REDACTED]"}}}),
            ("search_events", {"limit": 500}),                                      # out of range
            ("search_events", {"surprise": 1}),                                     # unknown argument
            ("read_skill", {"file": "../../etc/passwd"}),                           # enum
            ("get_event", "not-an-object"),
        ]
        for name, args in cases:
            with self.subTest(name=name, args=args):
                self.assertEqual(tools.classify(name, args).kind, "blocked")

    def test_query_string_is_kept(self):
        verdict = tools.classify("kong_request", {"method": "GET", "path": "/plugins?name=karna&size=100"})
        self.assertEqual(verdict.args["path"], "/plugins?name=karna&size=100")


class RedactionTests(unittest.TestCase):
    def test_secrets_are_masked_recursively(self):
        out = tools.redact({
            "config": {"redis_password": "s3cret", "paranoia_level": 2, "redis_host": "redis"},
            "credentials": [{"key": "abc"}],
            "data": [{"password": "x", "username": "bob"}],
            "request": {"headers": {"authorization": "Bearer t", "cookie": "a=b", "host": "h"}},
            "cert": {"key": "-----BEGIN PRIVATE KEY-----", "cert": "public"},
        })
        text = json.dumps(out)
        for secret in ("s3cret", "abc", "\"x\"", "Bearer t", "a=b", "PRIVATE KEY"):
            self.assertNotIn(secret, text)
        self.assertEqual(out["config"]["paranoia_level"], 2)
        self.assertEqual(out["data"][0]["username"], "bob")
        self.assertEqual(out["cert"]["cert"], "public")

    def test_unset_secret_stays_unset(self):
        self.assertIsNone(tools.redact({"redis_password": None})["redis_password"])

    def test_results_are_capped(self):
        self.assertIn("truncated", tools.to_result({"x": "a" * 100_000}))


class FakeKong:
    """Admin API stand-in: entities by path, every call recorded."""

    def __init__(self):
        self.calls = []
        self.entities = {
            "/services/s1": {"id": "s1", "name": "shop", "host": "shop.internal"},
            "/plugins/p1": {"id": "p1", "name": "karna", "enabled": True, "service": {"id": "s1"},
                            "config": {"engine_blocking_mode": True, "redis_password": "s3cret"}},
            "/routes/r1": {"id": "r1", "name": "shop-root", "service": {"id": "s1"}},
        }

    async def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        entity_path = path.split("?", 1)[0]
        if method == "GET":
            if entity_path in self.entities:
                return 200, self.entities[entity_path]
            return 200, {"data": list(self.entities.values())} if entity_path == "/services" else (404, {"message": "Not found"})
        if method == "DELETE":
            self.entities.pop(entity_path, None)
            return 204, None
        if method == "PATCH":
            self.entities[entity_path] = app._merge_patch(self.entities.get(entity_path, {}), body)
            return 200, self.entities[entity_path]
        return 201, body

    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]


INVENTORY = {"connected": True, "services": [{"id": "s1", "name": "shop", "host": "shop.internal"}],
             "karna_plugin_id_by_service": {"s1": "p1"}, "karna_by_service": {"s1": {"engine_blocking_mode": True}}}


def scripted(rounds):
    """A fake agent_round that plays one scripted round per call."""
    queue = list(rounds)

    async def fake(profile, api_key, system, items, specs):
        text, calls = queue.pop(0)
        if text:
            yield ("delta", text)
        yield ("done", {"text": text, "tool_calls": calls})
    return fake


class AgentFlowTests(unittest.TestCase):
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
        self.kong = FakeKong()
        self.patches = [
            patch.object(app, "_kong_call", self.kong),
            patch.object(app, "fetch_kong", self._inventory),
            patch.object(app, "_invalidate_cache", lambda: None),
            patch.object(app, "_invalidate_kong_inventory", lambda: None),
        ]
        for p in self.patches:
            p.start()
        self.conversation = store.create_conversation("profile", "test")["id"]
        self.profile = {"id": "profile", "name": "fake", "provider": "openai", "model": "m",
                        "base_url": "http://model.invalid/v1"}

    async def _inventory(self, force=False):
        return INVENTORY

    def tearDown(self):
        for p in self.patches:
            p.stop()
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        auth.DATA_DIR, auth.AUTH_FILE, auth.CHANGES_FILE, store.DATA_DIR, store.DB_PATH = self.old
        self.tmp.cleanup()

    def run_agent(self, rounds, user="go"):
        store.append_transcript(self.conversation, [{"role": "user", "content": user}])

        def event(kind, data):
            return {"type": kind, **data}

        async def collect():
            out = []
            with patch.object(assistant_runtime, "agent_round", scripted(rounds)):
                async for line in app._agent_run(self.conversation, "run", self.profile, None, event, 0):
                    out.append(line)
            return out
        return asyncio.run(collect())

    def call(self, name, args, cid="c1"):
        return {"id": cid, "name": name, "arguments": args}

    def tool_results(self):
        return [json.loads(i["content"]) for i in store.get_transcript(self.conversation) if i["role"] == "tool"]

    def test_read_runs_and_redacts_without_writing(self):
        events = self.run_agent([("", [self.call("kong_request", {"method": "GET", "path": "/plugins/p1"})]),
                                 ("Karna is in blocking mode.", [])])
        self.assertEqual(self.kong.writes(), [])
        result = self.tool_results()[0]
        self.assertEqual(result["body"]["config"]["redis_password"], "[REDACTED]")
        self.assertTrue(any(e["type"] == "message.completed" for e in events))

    def test_write_waits_and_never_reaches_kong_without_authorization(self):
        events = self.run_agent([("I'll delete the route.", [self.call("kong_request", {"method": "DELETE", "path": "/routes/r1"})])])
        self.assertEqual(self.kong.writes(), [])
        action = next(e["action"] for e in events if e["type"] == "action.created")
        self.assertEqual(action["status"], "pending")
        self.assertTrue(action["review"]["risks"])
        self.assertEqual(action["review"]["confirm_text"], "shop")
        self.assertEqual(self.tool_results()[0]["status"], "waiting_for_user_authorization")

    def test_risky_action_needs_the_typed_confirmation(self):
        events = self.run_agent([("", [self.call("kong_request", {"method": "DELETE", "path": "/routes/r1"})])])
        action = next(e["action"] for e in events if e["type"] == "action.created")
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(app.assistant_action_authorize(action["id"], {"confirm": "wrong"}, sub="admin"))
        self.assertEqual(ctx.exception.status_code, 428)
        self.assertEqual(self.kong.writes(), [])
        out = asyncio.run(app.assistant_action_authorize(action["id"], {"confirm": "shop"}, sub="admin"))
        self.assertTrue(out["ok"])
        self.assertEqual(self.kong.writes(), [("DELETE", "/routes/r1", None)])
        notes = [i["content"] for i in store.get_transcript(self.conversation) if i["role"] == "user"]
        self.assertTrue(notes[-1].startswith("[Console] The user authorized"))
        # single use
        with self.assertRaises(HTTPException) as again:
            asyncio.run(app.assistant_action_authorize(action["id"], {"confirm": "shop"}, sub="admin"))
        self.assertEqual(again.exception.status_code, 409)

    def test_safe_action_is_one_click_and_karna_config_goes_through_the_validator(self):
        events = self.run_agent([("", [self.call("karna_update_config", {"service": "shop", "changes": {"paranoia_level": 2}})])])
        action = next(e["action"] for e in events if e["type"] == "action.created")
        self.assertEqual(action["review"]["operation"]["plugin_id"], "p1")
        with patch.object(app, "patch_engine") as patched:
            async def ok(*a, **k):
                return {"ok": True}
            patched.side_effect = ok
            # paranoia changes are flagged risky by the shared review: confirm with the service name
            out = asyncio.run(app.assistant_action_authorize(action["id"], {"confirm": "shop"}, sub="admin"))
        self.assertTrue(out["ok"])
        patched.assert_called_once()

    def test_invalid_karna_change_is_refused_before_any_card(self):
        events = self.run_agent([("", [self.call("karna_update_config", {"service": "shop", "changes": {"nope": 1}})]),
                                 ("That field does not exist.", [])])
        self.assertFalse(any(e["type"] == "action.created" for e in events))
        self.assertIn("Not proposed", self.tool_results()[0]["error"])

    def test_reject_records_and_runs_nothing(self):
        events = self.run_agent([("", [self.call("kong_request", {"method": "PATCH", "path": "/services/s1", "body": {"host": "x"}})])])
        action = next(e["action"] for e in events if e["type"] == "action.created")
        out = asyncio.run(app.assistant_action_reject(action["id"], sub="admin"))
        self.assertEqual(out["action"]["status"], "rejected")
        self.assertEqual(self.kong.writes(), [])
        with self.assertRaises(HTTPException):
            asyncio.run(app.assistant_action_authorize(action["id"], {}, sub="admin"))

    def test_only_one_write_waits_per_turn(self):
        events = self.run_agent([("", [
            self.call("kong_request", {"method": "PATCH", "path": "/services/s1", "body": {"host": "a"}}, "c1"),
            self.call("kong_request", {"method": "PATCH", "path": "/services/s1", "body": {"host": "b"}}, "c2"),
        ])])
        self.assertEqual(sum(1 for e in events if e["type"] == "action.created"), 1)
        self.assertIn("Only one change", self.tool_results()[1]["error"])

    def test_tampered_action_is_refused(self):
        events = self.run_agent([("", [self.call("kong_request", {"method": "PATCH", "path": "/services/s1", "body": {"host": "a"}})])])
        action = next(e["action"] for e in events if e["type"] == "action.created")
        self.assertEqual(action["review"]["confirm_text"], "shop")  # a host change is risky
        with store._lock:
            c = store._connect()
            c.execute("UPDATE assistant_actions SET args=? WHERE id=?",
                      (json.dumps({"method": "DELETE", "path": "/services/s1"}), action["id"]))
            c.commit()
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(app.assistant_action_authorize(action["id"], {"confirm": "shop"}, sub="admin"))
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(self.kong.writes(), [])

    def test_entity_changed_since_review_is_refused(self):
        events = self.run_agent([("", [self.call("kong_request", {"method": "PATCH", "path": "/services/s1", "body": {"host": "a"}})])])
        action = next(e["action"] for e in events if e["type"] == "action.created")
        self.kong.entities["/services/s1"]["host"] = "changed-elsewhere"
        out = asyncio.run(app.assistant_action_authorize(action["id"], {"confirm": "shop"}, sub="admin"))
        self.assertFalse(out["ok"])
        self.assertEqual(out["action"]["status"], "failed")
        self.assertEqual(self.kong.writes(), [])

    def test_expired_action_is_refused(self):
        events = self.run_agent([("", [self.call("kong_request", {"method": "PATCH", "path": "/services/s1", "body": {"host": "a"}})])])
        action = next(e["action"] for e in events if e["type"] == "action.created")
        with store._lock:
            c = store._connect()
            c.execute("UPDATE assistant_actions SET expires_at=0 WHERE id=?", (action["id"],))
            c.commit()
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(app.assistant_action_authorize(action["id"], {}, sub="admin"))
        self.assertEqual(ctx.exception.status_code, 410)
        self.assertEqual(self.kong.writes(), [])

    def test_blocked_call_reaches_neither_kong_nor_a_card(self):
        events = self.run_agent([("", [self.call("kong_request", {"method": "GET", "path": "http://169.254.169.254/"})]),
                                 ("Sorry.", [])])
        self.assertEqual(self.kong.calls, [])
        self.assertFalse(any(e["type"] == "action.created" for e in events))
        self.assertIn("Blocked by the console", self.tool_results()[0]["error"])


class TranscriptFormatTests(unittest.TestCase):
    ITEMS = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "", "tool_calls": [{"id": "t1", "name": "list_services", "arguments": {}}]},
        {"role": "tool", "tool_call_id": "t1", "name": "list_services", "content": "{}"},
        {"role": "user", "content": "[Console] note"},
        {"role": "assistant", "content": "done"},
    ]

    def test_openai_shape(self):
        msgs = assistant_runtime._openai_messages("sys", self.ITEMS)
        self.assertEqual([m["role"] for m in msgs], ["system", "user", "assistant", "tool", "user", "assistant"])
        self.assertEqual(msgs[2]["tool_calls"][0]["function"]["name"], "list_services")

    def test_anthropic_merges_tool_results_and_notes_into_one_user_turn(self):
        msgs = assistant_runtime._anthropic_messages(self.ITEMS)
        self.assertEqual([m["role"] for m in msgs], ["user", "assistant", "user", "assistant"])
        self.assertEqual([b["type"] for b in msgs[2]["content"]], ["tool_result", "text"])

    def test_trim_starts_at_a_user_turn(self):
        trimmed = app._trim_transcript(self.ITEMS, max_items=3)
        self.assertEqual(trimmed[0]["role"], "user")


if __name__ == "__main__":
    unittest.main()
