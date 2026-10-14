"""Regression tests for the audit-log ingestion boundary."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import store


class AuditIngestionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_dir = Path(self.tmp.name, "audit")
        self.data_dir = Path(self.tmp.name, "data")
        self.audit_dir.mkdir()
        self.data_dir.mkdir()

        self.old_data_dir = store.DATA_DIR
        self.old_db_path = store.DB_PATH
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR = str(self.data_dir)
        store.DB_PATH = str(self.data_dir / "events.db")
        store.init()

    def tearDown(self):
        if store._conn is not None:
            store._conn.close()
        store._conn = None
        store.DATA_DIR = self.old_data_dir
        store.DB_PATH = self.old_db_path
        self.tmp.cleanup()

    @staticmethod
    def _event(request_id: str, value: str = "ok") -> dict:
        return {
            "request_id": request_id,
            "timestamp": "2026-07-23T12:00:00Z",
            "service": {"name": "wordpress"},
            "response": {"status": 403},
            "matches": [{
                "rule_id": "934110",
                "action": "block",
                "matched_parts": [{"on": "request.arg.value:x", "value": value}],
            }],
        }

    def _closed_path(self, worker: int = 0) -> Path:
        path = self.audit_dir / f"karna_auditlog_{worker}_200001010000.jsonl"
        return path

    def test_closed_file_salvages_invalid_utf8_and_continues(self):
        invalid = json.dumps(self._event("invalid-utf8", "bad")).encode("utf-8")
        invalid = invalid.replace(b'"bad"', b'"bad' + bytes([0xFF]) + b'"')
        valid = json.dumps(self._event("valid-after-invalid")).encode("utf-8")
        path = self._closed_path()
        path.write_bytes(invalid + b"\n" + valid + b"\n")
        os.utime(path, (1, 1))

        result = store.ingest_dir(str(self.audit_dir))

        self.assertEqual(result, {"ingested": 2, "deleted": 1, "skipped": 0})
        self.assertFalse(path.exists())
        events = store.recent_events(10)
        self.assertEqual({event["request_id"] for event in events},
                         {"invalid-utf8", "valid-after-invalid"})
        salvaged = next(event for event in events
                        if event["request_id"] == "invalid-utf8")
        self.assertIn("\ufffd", salvaged["matches"][0]["matched_parts"][0]["value"])

    def test_bad_json_does_not_block_later_valid_event(self):
        path = self._closed_path(1)
        valid = json.dumps(self._event("valid")).encode("utf-8")
        path.write_bytes(b'{"request_id":\n' + valid + b"\n")
        os.utime(path, (1, 1))

        result = store.ingest_dir(str(self.audit_dir))

        self.assertEqual(result["ingested"], 1)
        self.assertEqual(store.stats()["count"], 1)
        self.assertFalse(path.exists())

    def test_active_file_retries_invalid_utf8_without_storing_it(self):
        minute = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        path = self.audit_dir / f"karna_auditlog_0_{minute}.jsonl"
        invalid = json.dumps(self._event("active-invalid", "bad")).encode("utf-8")
        invalid = invalid.replace(b'"bad"', b'"bad' + bytes([0xFF]) + b'"')
        path.write_bytes(invalid + b"\n")

        result = store.ingest_dir(str(self.audit_dir))

        self.assertEqual(result, {"ingested": 0, "deleted": 0, "skipped": 1})
        self.assertTrue(path.exists())
        self.assertEqual(store.stats()["count"], 0)


if __name__ == "__main__":
    unittest.main()
