import json
import unittest

from fastapi import HTTPException

import app


class NativeRuleValidationTests(unittest.TestCase):
    def test_accepts_scoped_target_exclusion_without_terminal_action(self):
        rule = {
            "id": "exclude_934110_redirect_to",
            "phase": "access",
            "conditions": [{
                "variables": ["request.raw_path"],
                "op": "eq",
                "value": "/wp-login.php",
            }],
            "rule_control": [{
                "remove_target_from_rule_by_id": {
                    "rule_id": "934110",
                    "target": "request.arg.value:redirect_to",
                },
            }],
        }

        self.assertEqual(json.loads(app._serialize_rule("native", rule)), rule)

    def test_rejects_rule_without_action_or_controls(self):
        rule = {
            "id": "empty",
            "phase": "access",
            "conditions": [{"variables": ["request.raw_path"], "op": "eq", "value": "/"}],
        }
        with self.assertRaises(HTTPException) as raised:
            app._serialize_rule("native", rule)
        self.assertEqual(raised.exception.status_code, 422)

    def test_rejects_malformed_control_container(self):
        rule = {
            "id": "bad-control",
            "phase": "access",
            "conditions": [{"variables": ["request.raw_path"], "op": "eq", "value": "/"}],
            "rule_control": {"remove_rule": {"rule_id": "1"}},
        }
        with self.assertRaises(HTTPException) as raised:
            app._serialize_rule("native", rule)
        self.assertEqual(raised.exception.status_code, 422)

    def test_rejects_non_object_control_entry(self):
        rule = {
            "id": "bad-entry",
            "phase": "access",
            "conditions": [{"variables": ["request.raw_path"], "op": "eq", "value": "/"}],
            "rule_control": ["remove everything"],
        }
        with self.assertRaises(HTTPException) as raised:
            app._serialize_rule("native", rule)
        self.assertEqual(raised.exception.status_code, 422)


if __name__ == "__main__":
    unittest.main()
