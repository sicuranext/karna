import unittest

from fastapi import HTTPException

import app


class ServiceConfigurationTests(unittest.TestCase):
    def test_accepts_schema_backed_configuration_groups(self):
        changes = app._normalize_service_changes({
            "mcp_enabled": True,
            "mcp_routes": ["/mcp", "/agents"],
            "request_methods_allowed": ["GET", "POST"],
            "default_block_response_headers": {"Content-Type": "text/html"},
            "auditlog_format": "v2",
            "redis_port": 6380,
            "redis_on_error": "fail_closed",
            "crs_plugins_path": "/opt/custom-plugins",
        })

        self.assertTrue(changes["mcp_enabled"])
        self.assertEqual(changes["default_block_response_headers"], {"content-type": "text/html"})
        self.assertEqual(changes["crs_plugins_path"], "/opt/custom-plugins/")

    def test_rejects_unknown_fields_and_unsafe_paths(self):
        for payload in (
            {"arbitrary_kong_field": True},
            {"crs_plugins_path": "../../tmp"},
            {"auditlog_path": "/var/log/../secrets"},
            {"redis_host": "redis.local/path"},
        ):
            with self.subTest(payload=payload), self.assertRaises(HTTPException) as raised:
                app._normalize_service_changes(payload)
            self.assertEqual(raised.exception.status_code, 422)

    def test_public_config_never_contains_redis_password(self):
        public = app._public_service_config({
            "redis_password": "super-secret",
            "redis_host": "redis.internal",
        })

        self.assertNotIn("redis_password", public)
        self.assertTrue(public["redis_password_configured"])
        self.assertEqual(public["redis_host"], "redis.internal")

    def test_password_is_redacted_from_audit_and_response_shapes(self):
        self.assertEqual(
            app._audit_safe_config({"redis_password": "super-secret", "redis_host": "redis"}),
            {"redis_password": {"configured": True}, "redis_host": "redis"},
        )
        self.assertEqual(
            app._audit_safe_config({"redis_password": None}),
            {"redis_password": {"configured": False}},
        )

    def test_rejects_oversized_lists_and_invalid_header_names(self):
        for payload in (
            {"mcp_routes": [f"/route/{index}" for index in range(257)]},
            {"default_block_response_headers": {"bad header": "value"}},
        ):
            with self.subTest(payload=list(payload)), self.assertRaises(HTTPException) as raised:
                app._normalize_service_changes(payload)
            self.assertEqual(raised.exception.status_code, 422)


if __name__ == "__main__":
    unittest.main()
