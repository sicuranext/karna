"""What reaches the AI provider: the credential shapes of the 2026-10-13 review
are masked, and what the assistant needs to reason about rules is kept."""
from __future__ import annotations

import json
import unittest

import assistant_tools as tools

R = tools.REDACTED


def seen(value) -> str:
    return tools.to_result(value)


class RedactionTests(unittest.TestCase):
    def test_kong_plugin_secrets_by_key_pattern(self):
        out = tools.redact({"name": "aws-lambda", "config": {"aws_key": "AKIA_X", "aws_secret": "S3CR3T",
                                                              "aws_region": "eu-west-1", "timeout": 6000}})
        self.assertEqual(out["config"]["aws_key"], R)
        self.assertEqual(out["config"]["aws_secret"], R)
        self.assertEqual(out["config"]["aws_region"], "eu-west-1")
        self.assertEqual(tools.redact({"provision_key": "PK_1"})["provision_key"], R)

    def test_header_strings(self):
        out = tools.redact({"config": {"add": {"headers": ["X-Upstream-Key:RT_HEADER_SECRET_789", "X-Trace:on"]}}})
        self.assertEqual(out["config"]["add"]["headers"], ["X-Upstream-Key:" + R, "X-Trace:on"])
        self.assertEqual(tools.redact(["Authorization: Bearer abc"]), ["Authorization: " + R])

    def test_healthcheck_header_map(self):
        out = tools.redact({"healthchecks": {"active": {"headers": {"X-Hc-Token": ["HC_1"], "X-Probe": ["yes"]}}}})
        self.assertEqual(out["healthchecks"]["active"]["headers"], {"X-Hc-Token": R, "X-Probe": ["yes"]})

    def test_uri_query_parameters(self):
        out = tools.redact({"request": {"uri": "/login?apikey=QUERY_APIKEY_444&password=QUERY_PW_555&q=shoes"}})
        self.assertEqual(out["request"]["uri"], f"/login?apikey={R}&password={R}&q=shoes")

    def test_raw_body(self):
        out = tools.redact({"body_raw": "user=bob&password=hunter2&remember=1"})
        self.assertEqual(out["body_raw"], f"user=bob&password={R}&remember=1")
        out = tools.redact({"body_raw": '{"user": "bob", "password": "hunter2"}'})
        self.assertEqual(out["body_raw"], f'{{"user": "bob", "password": "{R}"}}')

    def test_matched_parts(self):
        parts = [{"on": "request.arg.value:password", "value": "x' OR 1=1--"},
                 {"on": "request.cookie.value:PHPSESSID", "value": "abc' OR 1=1"},
                 {"on": "request.cookie.value:tracking", "value": "1' OR '1'='1"},
                 {"on": "request.body", "value": "user=a&token=T0K&q=<script>"}]
        out = tools.redact({"matched_parts": parts})["matched_parts"]
        self.assertEqual([p["value"] for p in out], [R, R, "1' OR '1'='1", f"user=a&token={R}&q=<script>"])
        self.assertEqual(out[0]["on"], "request.arg.value:password")

    def test_what_the_assistant_needs_is_kept(self):
        rule = {"id": "r1", "conditions": [{"variables": ["request.cookie.value:session", "request.header.value:authorization"],
                                            "op": "rx", "value": "^x"}]}
        self.assertEqual(tools.redact({"rules_request": [rule]}), {"rules_request": [rule]})
        sec = 'SecRule REQUEST_HEADERS:Authorization "@rx ^Basic" "id:5,phase:1,pass"'
        self.assertEqual(tools.redact({"custom_secrules": [sec]})["custom_secrules"], [sec])
        cfg = {"key_names": ["apikey"], "hide_credentials": True, "key_in_header": True,
               "mcp_redact_session_id_in_audit": True, "redis_keepalive_pool_size": 30, "token_expiration": 7200}
        self.assertEqual(tools.redact(cfg), cfg)

    def test_existing_exact_names_still_masked(self):
        out = tools.redact({"key": "k1", "password": "p", "redis_password": "r", "headers": {"authorization": "Basic x"}})
        self.assertEqual(out, {"key": R, "password": R, "redis_password": R, "headers": {"authorization": R}})

    def test_config_is_refused_in_any_method(self):
        for method in ("GET", "POST"):
            args = {"method": method, "path": "/config"}
            if method == "POST":
                args["body"] = {"config": "_format_version: '3.0'"}
            self.assertEqual(tools.classify("kong_request", args).kind, "blocked")
        self.assertEqual(tools.classify("kong_request", {"method": "GET", "path": "/config?x=1"}).kind, "blocked")
        self.assertEqual(tools.classify("kong_request", {"method": "GET", "path": "/configs"}).kind, "read")

    def test_markers_never_reach_the_result(self):
        doc = {"plugins": [{"config": {"add": {"headers": ["X-Upstream-Key:RT_HEADER_SECRET_789"]}}},
                           {"config": {"aws_key": "AWS_KEY_MARK", "aws_secret": "AWS_SECRET_MARK"}}],
               "events": [{"uri": "/login?apikey=QUERY_APIKEY_444"}]}
        text = seen(doc)
        for marker in ("RT_HEADER_SECRET_789", "AWS_KEY_MARK", "AWS_SECRET_MARK", "QUERY_APIKEY_444"):
            self.assertNotIn(marker, text)
        json.loads(text)


class Round2RedactionTests(unittest.TestCase):
    """Shapes the 2026-10-23 review still saw reach the provider."""

    def test_ai_proxy_credentials_under_auth(self):
        out = tools.redact({"config": {"auth": {"header_name": "Authorization", "header_value": "Bearer sk-AI",
                                                "param_name": "key", "param_value": "PV",
                                                "gcp_service_account_json": '{"private_key":"PK"}',
                                                "allow_override": False}}})["config"]["auth"]
        self.assertEqual(out["header_name"], "Authorization")
        self.assertEqual(out["param_name"], "key")
        self.assertIs(out["allow_override"], False)
        for field in ("header_value", "param_value", "gcp_service_account_json"):
            self.assertEqual(out[field], tools.REDACTED, field)

    def test_urls_lose_userinfo_and_sensitive_query(self):
        out = tools.redact({"http_endpoint": "https://user:PW@logs.example/in?api_key=Q&x=1",
                            "traces_endpoint": "https://otel.example/v1?token=T",
                            "url": "https://GHTOKEN@github.com/repo"})
        self.assertEqual(out["http_endpoint"], f"https://user:{tools.REDACTED}@logs.example/in?api_key={tools.REDACTED}&x=1")
        self.assertEqual(out["traces_endpoint"], f"https://otel.example/v1?token={tools.REDACTED}")
        self.assertEqual(out["url"], f"https://{tools.REDACTED}@github.com/repo")

    def test_location_header_query(self):
        out = tools.redact({"headers": {"location": "https://app/cb?access_token=LOC&state=s"}})
        self.assertEqual(out["headers"]["location"], f"https://app/cb?access_token={tools.REDACTED}&state=s")

    def test_multipart_and_xml_bodies(self):
        mp = ('--b\r\nContent-Disposition: form-data; name="password"\r\n\r\nMPPW\r\n'
              '--b\r\nContent-Disposition: form-data; name="user"\r\n\r\nbob\r\n--b--')
        out = tools.redact({"body_raw": mp})["body_raw"]
        self.assertNotIn("MPPW", out)
        self.assertIn("bob", out)
        xml = '<login><user>bob</user><ns:password a="1">XMLPW</ns:password></login>'
        out = tools.redact({"body_raw": xml})["body_raw"]
        self.assertNotIn("XMLPW", out)
        self.assertIn("<user>bob</user>", out)
        matched = tools.redact({"on": "request.body", "value": "<password>MV</password>"})
        self.assertNotIn("MV", matched["value"])

    def test_rule_variables_and_plain_urls_survive(self):
        self.assertEqual(tools.redact("request.cookie.value:session"), "request.cookie.value:session")
        self.assertEqual(tools.redact("https://docs.example/rules?page=2"), "https://docs.example/rules?page=2")


if __name__ == "__main__":
    unittest.main()
