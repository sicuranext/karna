import json
import unittest
from unittest.mock import patch

import app


def event(service, *rule_ids):
    return {
        "request_id": f"{service}-request",
        "timestamp": "2026-07-30T10:00:00Z",
        "service": {"name": service},
        "matches": [
            {"rule_id": rule_id, "message": f"Matched {rule_id}", "action": "detect"}
            for rule_id in rule_ids
        ],
    }


class RuleHitTests(unittest.TestCase):
    def test_aggregate_counts_every_match_and_keeps_service_scope(self):
        aggregated = app.aggregate([
            event("wordpress", "first", "ratelimit_login"),
            event("echo", "ratelimit_login"),
        ])

        self.assertEqual(aggregated["rule_hits_by_service"][("wordpress", "ratelimit_login")], 1)
        self.assertEqual(aggregated["rule_hits_by_service"][("echo", "ratelimit_login")], 1)
        self.assertEqual(
            {item["rule_id"]: item["hits"] for item in aggregated["top_rules"]},
            {"ratelimit_login": 2, "first": 1},
        )

    @patch("app.store.stats", return_value={"count": 1, "oldest": None, "newest": None, "db_bytes": 0})
    @patch("app.store.get_ttl_days", return_value=30)
    def test_payload_assigns_hits_to_native_and_seclang_rules(self, _ttl, _stats):
        kong = {
            "connected": True,
            "services": [{
                "id": "wordpress-id", "name": "wordpress", "host": "wordpress",
                "protocol": "http", "port": 80,
            }],
            "karna_by_service": {
                "wordpress-id": {
                    "rules_request": [json.dumps({
                        "id": "ratelimit_login", "phase": "access",
                        "action": {"rate_limit": {"limit": 5, "window_seconds": 60}},
                    })],
                    "custom_secrules": [
                        'SecRule REQUEST_URI "@contains wp-login" "id:990001,phase:1,pass"'
                    ],
                },
            },
            "routes_by_service": {},
            "karna_plugin_id_by_service": {"wordpress-id": "plugin-id"},
            "crs_inventory_by_plugin": {},
        }

        payload = app.build_payload([
            event("wordpress", "ratelimit_login", "990001"),
            event("wordpress", "ratelimit_login"),
        ], kong)

        self.assertEqual(payload["LOCAL_RULES"][0]["hits"], 2)
        self.assertEqual(payload["CUSTOM_SECRULES"][0]["id"], "990001")
        self.assertEqual(payload["CUSTOM_SECRULES"][0]["hits"], 1)


if __name__ == "__main__":
    unittest.main()
