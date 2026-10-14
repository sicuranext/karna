import unittest

from fastapi import HTTPException

import app


class CoreRuleSetPluginValidationTests(unittest.TestCase):
    def test_normalizes_unique_installed_style_names(self):
        self.assertEqual(
            app._normalize_crs_plugins_enabled([
                "wordpress-rule-exclusions-plugin",
                "drupal_plugin.v2",
                "wordpress-rule-exclusions-plugin",
            ]),
            ["drupal_plugin.v2", "wordpress-rule-exclusions-plugin"],
        )

    def test_rejects_path_traversal_and_shell_metacharacters(self):
        for value in (
            ["../wordpress"],
            ["wordpress/plugin"],
            ["wordpress;touch-pwned"],
            ["."],
            [".."],
        ):
            with self.subTest(value=value), self.assertRaises(HTTPException) as raised:
                app._normalize_crs_plugins_enabled(value)
            self.assertEqual(raised.exception.status_code, 422)

    def test_rejects_non_arrays_and_oversized_lists(self):
        for value in ("wordpress", {"wordpress": True}, [f"plugin-{i}" for i in range(33)]):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(HTTPException) as raised:
                app._normalize_crs_plugins_enabled(value)
            self.assertEqual(raised.exception.status_code, 422)


if __name__ == "__main__":
    unittest.main()
