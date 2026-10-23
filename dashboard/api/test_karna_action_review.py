"""Karna settings and actions proposed by the assistant (2026-10-23 review):
only the settings known to be neutral go through with one click, and a
karna_* action runs only on the configuration it was reviewed against."""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import app


def config_review(changes):
    return app._proposal_review({"type": "update_config", "plugin_id": "p", "changes": changes})


class SettingsReviewTests(unittest.TestCase):
    def test_weakening_switches_from_the_old_allow_list_are_risky(self):
        cases = {
            "mcp_origins_allowed": ["https://attacker.example"], "mcp_routes": [],
            "mcp_detection_heuristic": False, "try_bas64decode_if_possible": False,
            "redis_inspect_enabled": False, "redis_database": 3, "redis_timeout_ms": 1,
            "set_karna_headers": True, "auditlog_only_on_match": True, "auditlog_format": "v1",
            "limit_arg_value_length": 10, "inspection_table_convert": ["x"],
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                self.assertTrue(config_review({field: value})["risks"])

    def test_neutral_and_strengthening_changes_are_one_click(self):
        for changes in ({"engine_re2_scan": False}, {"redis_keepalive_pool_size": 32},
                        {"auditlog_error_log_on_match": True}, {"redis_inspect_enabled": True},
                        {"try_bas64decode_if_possible": True}, {"set_karna_headers": False},
                        {"engine_blocking_mode": True, "auditlog_enabled": True}):
            with self.subTest(changes=changes):
                self.assertEqual(config_review(changes)["risks"], [])

    def test_every_service_field_is_classified(self):
        classified = (set(app._WEAKER_WHEN_FALSE) | set(app._WEAKER_WHEN_TRUE) | set(app._RISKY_ANY_CHANGE)
                      | set(app._RESPONSE_PAGE_FIELDS) | app._NEUTRAL_FIELDS | {"redis_password"})
        unclassified = app._SERVICE_FIELDS - classified
        # Not an error (they get the generic risk), but a new field should be
        # given its own line or declared neutral.
        self.assertEqual(unclassified, set())


PLUGIN = {"id": "k1", "name": "karna", "updated_at": 1, "config": {"limit_arg_num": 255}}
SERVICE = {"id": "s1", "name": "demo"}


class KarnaActionBeforeHashTests(unittest.TestCase):
    def setUp(self):
        self.plugin = json.loads(json.dumps(PLUGIN))

    def _kong(self, method, path, body=None):
        return 200, json.loads(json.dumps(self.plugin))

    def _review(self):
        with patch.object(app, "_kong_call", AsyncMock(side_effect=self._kong)), \
             patch.object(app, "fetch_kong", AsyncMock(return_value={
                 "services": [SERVICE], "karna_plugin_id_by_service": {"s1": "k1"}})):
            return asyncio.run(app._review_write("karna_update_config",
                                                 {"service": "demo", "changes": {"limit_arg_num": 300}}))

    def _execute(self, exec_args, review):
        action = {"tool": "karna_update_config", "args": exec_args, "review": review}
        with patch.object(app, "_kong_call", AsyncMock(side_effect=self._kong)), \
             patch.object(app, "patch_engine", AsyncMock(return_value={"ok": True})) as patch_engine:
            result = asyncio.run(app._execute_action(action, "admin@test"))
        return result, patch_engine

    def test_unchanged_plugin_runs(self):
        exec_args, review = self._review()
        self.assertTrue(review["before_hash"])
        result, patch_engine = self._execute(exec_args, review)
        self.assertEqual(result, {"ok": True})
        patch_engine.assert_awaited_once()

    def test_plugin_changed_after_the_card_is_refused(self):
        exec_args, review = self._review()
        self.plugin["config"]["paranoia_level"] = 2
        self.plugin["updated_at"] = 2
        with self.assertRaises(HTTPException) as ctx:
            self._execute(exec_args, review)
        self.assertEqual(ctx.exception.status_code, 409)


class RedirectTests(unittest.TestCase):
    def test_no_trailing_slash_redirects(self):
        self.assertFalse(app.app.router.redirect_slashes)


if __name__ == "__main__":
    unittest.main()
