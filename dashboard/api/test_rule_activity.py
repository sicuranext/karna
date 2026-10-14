import unittest
from datetime import datetime, timedelta, timezone

import app


def event(ts, service, ip, *matches):
    return {
        "request_id": f"{service}-{ip}-{ts.isoformat()}",
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "service": {"name": service},
        "client": {"ip": ip},
        "matches": [{"rule_id": rid, "message": f"Matched {rid}", "action": act} for rid, act in matches],
    }


class RuleActivityTests(unittest.TestCase):
    def test_last_24h_per_rule_hourly_ips_services_and_blocked_share(self):
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=3)
        agg = app.aggregate([
            event(now, "shop", "10.0.0.1", ("942100", "block")),
            event(now, "shop", "10.0.0.1", ("942100", "block")),
            event(now - timedelta(hours=2), "blog", "10.0.0.2", ("942100", "detect"), ("913100", "detect")),
            event(old, "shop", "10.0.0.9", ("930120", "block")),   # outside the window
        ])
        acts = {a["rule_id"]: a for a in agg["rule_activity"]}
        self.assertEqual(list(acts), ["942100", "913100"])
        sqli = acts["942100"]
        self.assertEqual(sqli["hits"], 3)
        self.assertEqual(len(sqli["hourly"]), 24)
        self.assertEqual(sqli["hourly"][23], 2)
        self.assertEqual(sqli["hourly"][21], 1)
        self.assertEqual(sqli["ips"], 2)
        self.assertEqual(sqli["services"], 2)
        self.assertEqual(sqli["top_service"], "shop")
        self.assertEqual(sqli["blocked_pct"], 66.7)
        # the all-time ranking still counts the old event
        self.assertIn("930120", {r["rule_id"] for r in agg["top_rules"]})

    def test_at_most_ten_rules(self):
        now = datetime.now(timezone.utc)
        agg = app.aggregate([event(now, "s", "1.1.1.1", *[(f"r{i}", "detect") for i in range(14)])])
        self.assertEqual(len(agg["rule_activity"]), 10)


if __name__ == "__main__":
    unittest.main()
