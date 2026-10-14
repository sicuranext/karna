"""The review of raw Admin API writes (kong_request): every shape of the
2026-10-13 review that used to come back with no risks now needs the typed
confirmation, and the few benign shapes still go through with one click."""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

import app

KARNA_ID = "1e298995-0529-55d8-b342-3073dbd9e106"
SERVICE = {"id": "a7d6e0b8-620f-53ce-96df-34f9cb6f7ff1", "name": "demo", "host": "echo", "port": 80,
           "protocol": "http", "path": "/"}
KARNA = {"id": KARNA_ID, "name": "karna", "enabled": True, "protocols": ["http", "https"],
         "service": {"id": SERVICE["id"]}, "route": None, "consumer": None,
         "config": {"engine_blocking_mode": True, "coreruleset_enabled": True, "paranoia_level": 1,
                    "rules_request": [], "custom_secrules": [], "rule_action_overrides": [],
                    "rule_response_overrides": [], "default_block_response_body": None, "tags": None}}
OTHER_PLUGIN = {"id": "p2", "name": "cors", "enabled": True, "service": {"id": SERVICE["id"]}, "config": {}}


def _kong(method, path):
    entity = {f"/plugins/{KARNA_ID}": KARNA, f"/services/{SERVICE['id']}": SERVICE, "/services/demo": SERVICE,
              "/plugins/p2": OTHER_PLUGIN}.get(path)
    return (200, json.loads(json.dumps(entity))) if entity else (404, {"message": "Not found"})


def review(method, path, body=None):
    args = {"method": method, "path": path}
    if body is not None:
        args["body"] = body
    with patch.object(app, "_kong_call", AsyncMock(side_effect=_kong)), \
         patch.object(app, "fetch_kong", AsyncMock(return_value={"services": [SERVICE]})):
        return asyncio.run(app._review_write("kong_request", args))[1]


def rule(entry):
    return json.dumps(entry)


class KongWriteReviewTests(unittest.TestCase):
    def assertRisky(self, rev, needle=None):
        self.assertTrue(rev["risks"], rev)
        self.assertEqual(rev.get("confirm_text"), "demo")
        if needle:
            self.assertTrue(any(needle in r for r in rev["risks"]), rev["risks"])

    # ---- the rows of the review's table ----
    def test_null_on_a_karna_boolean_is_refused(self):
        for field in ("engine_blocking_mode", "coreruleset_enabled"):
            with self.subTest(field=field), self.assertRaises(app.ToolError):
                review("PATCH", f"/plugins/{KARNA_ID}", {"config": {field: None}})

    def test_string_on_a_karna_boolean_is_refused(self):
        with self.assertRaises(app.ToolError):
            review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"engine_blocking_mode": "false"}})

    def test_passthrough_any_override_is_named(self):
        entry = rule({"selector": {"any": True}, "action": {"type": "passthrough"}})
        rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"rule_action_overrides": [entry]}})
        self.assertRisky(rev, "passthrough")
        self.assertRisky(rev, "every rule")
        self.assertIn("passthrough", rev["content"][0]["text"])

    def test_seclang_engine_off_is_named(self):
        sec = 'SecRule REQUEST_URI "@unconditionalMatch" "id:1,phase:1,pass,ctl:ruleEngine=Off"'
        rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"custom_secrules": [sec]}})
        self.assertRisky(rev, "ctl:ruleEngine=Off")
        self.assertEqual(rev["content"][0], {"label": "custom_secrules", "text": sec})

    def test_seclang_rule_remove_and_body_off_are_named(self):
        sec = 'SecRule REQUEST_URI "@beginsWith /x" "id:2,phase:1,pass,ctl:ruleRemoveById=942100,ctl:requestBodyAccess=Off"'
        rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"custom_secrules": [sec]}})
        self.assertRisky(rev, "ruleRemoveById")
        self.assertRisky(rev, "requestBodyAccess=Off")

    def test_native_rule_engine_off_is_named(self):
        entry = rule({"id": "x1", "phase": "access", "conditions": [{"variables": ["request.path"], "op": "unconditionalMatch"}],
                      "rule_control": [{"engine_off": True}]})
        rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"rules_request": [entry]}})
        self.assertRisky(rev, "engine_off")

    def test_emptying_a_rule_array_is_risky(self):
        before = KARNA["config"]
        KARNA["config"] = dict(before, rules_request=[rule({"id": "keep"})])
        try:
            rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"rules_request": []}})
        finally:
            KARNA["config"] = before
        self.assertRisky(rev, "native rules (0 entries)")

    def test_karna_rescoped_by_protocols(self):
        self.assertRisky(review("PATCH", f"/plugins/{KARNA_ID}", {"protocols": ["grpc"]}), "protocols")

    def test_karna_moved_to_another_service(self):
        self.assertRisky(review("PATCH", f"/plugins/{KARNA_ID}", {"service": {"id": "other"}}), "service")

    def test_service_host_hijack(self):
        rev = review("PATCH", f"/services/{SERVICE['id']}", {"host": "attacker.example", "port": 80})
        self.assertRisky(rev, "host")

    def test_pre_function_shows_the_code(self):
        lua = 'kong.response.exit(200, "pwned")'
        for name in ("pre-function", "post-function"):
            with self.subTest(name=name):
                rev = review("POST", "/plugins", {"name": name, "service": {"id": SERVICE["id"]},
                                                  "config": {"access": [lua]}})
                self.assertRisky(rev, "custom code")
                self.assertIn(lua, rev["content"][0]["text"])

    def test_request_termination(self):
        rev = review("POST", f"/services/{SERVICE['id']}/plugins",
                     {"name": "request-termination", "config": {"status_code": 200}})
        self.assertRisky(rev, "request-termination")

    def test_enabled_null_disables(self):
        self.assertRisky(review("PATCH", "/plugins/p2", {"enabled": None}), "Disables")

    def test_unknown_karna_field_is_risky(self):
        rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"some_new_field": 1}})
        self.assertRisky(rev, "does not review")

    def test_other_writes_fall_back_to_the_generic_risk(self):
        for method, path, body in (("POST", "/services", {"name": "new", "url": "http://x"}),
                                   ("PATCH", "/plugins/p2", {"config": {"origins": ["*"]}}),
                                   ("PATCH", f"/plugins/{KARNA_ID}", {"name": "karna", "instance_name": "x"})):
            with self.subTest(method=method, path=path):
                rev = review(method, path, body)
                self.assertTrue(rev["risks"], rev)
                self.assertIn("confirm_text", rev)

    # ---- what still goes through with one click ----
    def test_tags_only_is_benign(self):
        rev = review("PATCH", f"/services/{SERVICE['id']}", {"tags": ["team-a"]})
        self.assertEqual(rev["risks"], [])
        self.assertNotIn("confirm_text", rev)

    def test_harmless_karna_setting_is_benign(self):
        rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"default_block_response_body": "Blocked."}})
        self.assertEqual(rev["risks"], [])

    def test_strengthening_karna_is_benign(self):
        KARNA["config"]["engine_blocking_mode"] = False
        try:
            rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"engine_blocking_mode": True}})
        finally:
            KARNA["config"]["engine_blocking_mode"] = True
        self.assertEqual(rev["risks"], [])

    def test_known_weakening_still_flagged(self):
        rev = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"engine_blocking_mode": False}})
        self.assertRisky(rev, "blocking off")
        self.assertRisky(review("DELETE", f"/plugins/{KARNA_ID}"), "Removes Karna")


if __name__ == "__main__":
    unittest.main()
