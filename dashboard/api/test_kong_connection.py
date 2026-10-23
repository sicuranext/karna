import unittest

import app
import kong_connection


class KongConnectionTest(unittest.TestCase):
    def test_accepts_and_normalizes_expected_targets(self):
        self.assertEqual(
            kong_connection.validate({"protocol": " HTTPS ", "host": "KONG.internal.", "port": "8444"}),
            {"protocol": "https", "host": "KONG.internal", "port": 8444},
        )
        ipv6 = kong_connection.validate({"protocol": "http", "host": "[2001:db8::1]", "port": 8001})
        self.assertEqual(kong_connection.url(ipv6), "http://[2001:db8::1]:8001")

    def test_rejects_url_smuggling_and_invalid_ports(self):
        invalid = [
            {"protocol": "file", "host": "kong", "port": 8001},
            {"protocol": "http", "host": "user@kong", "port": 8001},
            {"protocol": "http", "host": "kong/admin", "port": 8001},
            {"protocol": "http", "host": "kong?next=metadata", "port": 8001},
            {"protocol": "http", "host": "kong", "port": 0},
            {"protocol": "http", "host": "kong", "port": 65536},
            {"protocol": "http", "host": "kong", "port": True},
            {"protocol": "http", "host": "kong", "port": 8001.5},
            {"protocol": "http", "host": "0.0.0.0", "port": 8001},
            {"protocol": "http", "host": "kong", "port": 8001, "path": "/admin"},
        ]
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                kong_connection.validate(candidate)

    def test_environment_default_has_no_path_or_credentials(self):
        self.assertEqual(
            kong_connection.from_url("https://admin.example.test"),
            {"protocol": "https", "host": "admin.example.test", "port": 443},
        )
        self.assertEqual(
            kong_connection.from_url("http://user:pass@admin.example.test:8001/path"),
            {"protocol": "http", "host": "kong", "port": 8001},
        )

    def test_dashboard_target_identity_exposes_only_public_connection_metadata(self):
        public = app._public_connection({
            "id": "primary",
            "name": "Production",
            "protocol": "https",
            "host": "kong.internal",
            "port": 8444,
            "source": "settings",
            "admin_token": "must-not-leak",
            "metadata": {"version": "3.9.3", "hostname": "kong-01"},
        }, "primary")

        self.assertEqual(public["url"], "https://kong.internal:8444")
        self.assertTrue(public["active"])
        self.assertNotIn("admin_token", public)


class MetadataHostnameTest(unittest.TestCase):
    def test_metadata_names_are_refused_with_the_right_reason(self):
        for host in ("metadata.google.internal", "METADATA.google.internal.", "metadata.google"):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "metadata address"):
                kong_connection.validate({"protocol": "http", "host": host, "port": 8001})

    def test_names_that_only_contain_the_word_are_accepted(self):
        for host in ("kong-metadata.internal", "unspecified-kong"):
            with self.subTest(host=host):
                self.assertEqual(kong_connection.validate({"protocol": "http", "host": host, "port": 8001})["host"], host)


if __name__ == "__main__":
    unittest.main()
