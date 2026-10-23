"""SQLite-backed event store for the Karna dashboard.

Karna writes audit log v2 as JSON Lines, one file per worker per minute
(karna_auditlog_<worker>_<YYYYMMDDHHMM>.jsonl), appending one record per line.
This module is the ingester + store: a background loop reads those files line
by line, inserts each record into a local SQLite DB (in the writable /data
volume), and deletes a file once it is closed (its minute has elapsed) and
safely stored. The file for the current minute is still being appended to, so
it is tail-read idempotently (INSERT OR IGNORE on the request_id primary key)
and left in place until it closes. The DB is the queryable source for the API.

Retention is governed by a user-configurable TTL in days; rows older than the
TTL are pruned. Purge wipes the store (and any not-yet-ingested files) on
explicit, confirmed request.

Pure stdlib (sqlite3) — no extra dependency, no extra container. A single
module-level connection guarded by a lock serialises the (small, fast) writes
from the ingester loop against reads from request handlers; WAL mode keeps it
snappy.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

DATA_DIR = os.getenv("KARNA_DASH_DATA", "/data")
DB_PATH = os.path.join(DATA_DIR, "events.db")

DEFAULT_TTL_DAYS = int(os.getenv("KARNA_DASH_TTL_DAYS", "30"))
TTL_MIN_DAYS = 1
TTL_MAX_DAYS = 3650  # ~10y ceiling
# Row ceiling on top of the TTL: busy traffic with auditlog_only_on_match off
# could otherwise fill /data, and once SQLite writes fail the audit files stop
# being consumed and fill Kong's log volume too.
MAX_EVENTS = max(1000, int(os.getenv("KARNA_DASH_MAX_EVENTS", "1000000")))

# A legacy file that fails to parse but is older than this is treated as corrupt
# and dropped, so a single bad file can't wedge the ingester forever.
_CORRUPT_AGE_S = 120

# After a per-minute file's minute has elapsed it gets no further writes, but we
# still wait this long (on mtime) before deleting it, to tolerate clock skew
# between this container and Kong's.
_MINUTE_GRACE_S = 5

# Current scheme: one JSON Lines file per worker per minute.
_GLOB = "karna_auditlog_*_*.jsonl"
# Legacy scheme: one JSON object per file. Still matched so leftover files from
# before the rotation change are drained (a legacy file is a valid one-line
# JSONL record, so the line parser ingests it transparently).
_GLOB_LEGACY = "*-ka-auditlog-*.json"
_GLOBS = (_GLOB, _GLOB_LEGACY)

# Names like karna_auditlog_<worker>_<YYYYMMDDHHMM>.jsonl
_MINUTE_RE = re.compile(r"^karna_auditlog_\d+_(\d{12})\.jsonl$")

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
    return _conn


def init() -> None:
    """Create the schema and seed the default TTL. Safe to call repeatedly."""
    with _lock:
        c = _connect()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
              request_id TEXT PRIMARY KEY,
              ts         INTEGER NOT NULL,   -- epoch milliseconds
              ts_iso     TEXT,
              service    TEXT,
              client_ip  TEXT,
              status     INTEGER,
              action     TEXT,               -- coarse disposition (blocked/detected/...)
              rule_ids   TEXT,               -- comma-separated matched rule ids
              raw        TEXT NOT NULL        -- full audit log v2 JSON
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_service ON events(service, ts);
            CREATE INDEX IF NOT EXISTS idx_events_action  ON events(action, ts);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS ai_profiles (
              id              TEXT PRIMARY KEY,
              name            TEXT NOT NULL,
              provider        TEXT NOT NULL,
              base_url        TEXT NOT NULL,
              model           TEXT NOT NULL,
              options         TEXT NOT NULL DEFAULT '{}',
              api_key_cipher  TEXT,
              is_default      INTEGER NOT NULL DEFAULT 0,
              created_at      INTEGER NOT NULL,
              updated_at      INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_profiles_name
              ON ai_profiles(name COLLATE NOCASE);
            CREATE TABLE IF NOT EXISTS assistant_conversations (
              id          TEXT PRIMARY KEY,
              title       TEXT NOT NULL,
              profile_id  TEXT NOT NULL,
              created_at  INTEGER NOT NULL,
              updated_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assistant_conversations_updated
              ON assistant_conversations(updated_at DESC);
            CREATE TABLE IF NOT EXISTS assistant_messages (
              id               TEXT PRIMARY KEY,
              conversation_id  TEXT NOT NULL,
              role             TEXT NOT NULL,
              content          TEXT NOT NULL,
              mentions         TEXT NOT NULL DEFAULT '[]',
              created_at       INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assistant_messages_conversation
              ON assistant_messages(conversation_id,created_at,id);
            CREATE TABLE IF NOT EXISTS assistant_activities (
              id               TEXT PRIMARY KEY,
              conversation_id  TEXT NOT NULL,
              run_id           TEXT NOT NULL,
              seq              INTEGER NOT NULL,
              kind             TEXT NOT NULL,
              status           TEXT NOT NULL,
              label            TEXT NOT NULL,
              detail           TEXT NOT NULL DEFAULT '{}',
              created_at       INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assistant_activities_conversation
              ON assistant_activities(conversation_id,created_at,seq);
            CREATE TABLE IF NOT EXISTS assistant_proposals (
              id               TEXT PRIMARY KEY,
              conversation_id  TEXT NOT NULL,
              message_id       TEXT NOT NULL,
              summary          TEXT NOT NULL,
              operation        TEXT NOT NULL,
              status           TEXT NOT NULL DEFAULT 'pending',
              error            TEXT,
              created_at       INTEGER NOT NULL,
              updated_at       INTEGER NOT NULL,
              before_hash      TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_assistant_proposals_conversation
              ON assistant_proposals(conversation_id,created_at,id);
            CREATE TABLE IF NOT EXISTS assistant_transcript (
              conversation_id  TEXT NOT NULL,
              seq              INTEGER NOT NULL,
              item             TEXT NOT NULL,
              PRIMARY KEY (conversation_id, seq)
            );
            CREATE TABLE IF NOT EXISTS assistant_actions (
              id               TEXT PRIMARY KEY,
              conversation_id  TEXT NOT NULL,
              tool_call_id     TEXT NOT NULL,
              tool             TEXT NOT NULL,
              args             TEXT NOT NULL,
              args_hash        TEXT NOT NULL,
              review           TEXT NOT NULL,
              status           TEXT NOT NULL DEFAULT 'pending',
              result           TEXT,
              error            TEXT,
              created_at       INTEGER NOT NULL,
              updated_at       INTEGER NOT NULL,
              expires_at       INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assistant_actions_conversation
              ON assistant_actions(conversation_id,created_at,id);
            """
        )
        # Databases created before proposals carried the plugin's digest.
        if "before_hash" not in {row["name"] for row in c.execute("PRAGMA table_info(assistant_proposals)")}:
            c.execute("ALTER TABLE assistant_proposals ADD COLUMN before_hash TEXT")
        if c.execute("SELECT 1 FROM settings WHERE key='ttl_days'").fetchone() is None:
            c.execute("INSERT INTO settings(key,value) VALUES('ttl_days',?)", (str(DEFAULT_TTL_DAYS),))
        c.commit()


# ---- record extraction (minimal; the API derives the rest from `raw`) ----
def _epoch_ms(ev: dict, fallback_path: str | None) -> int:
    ts = ev.get("timestamp")
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except (ValueError, AttributeError):
            pass
    if fallback_path and os.path.exists(fallback_path):
        try:
            return int(os.path.getmtime(fallback_path) * 1000)
        except OSError:
            pass
    return int(time.time() * 1000)


def _disposition(ev: dict) -> str:
    acts = [m.get("action") for m in ev.get("matches", []) or []]
    for a in ("block", "rate_limited", "sanitized", "detect"):
        if a in acts:
            return {"block": "blocked", "detect": "detected"}.get(a, a)
    if acts and all(a == "log" for a in acts):
        return "observed"
    return "allowed"


def _row(ev: dict, path: str | None, lineno: int = 0) -> tuple | None:
    rid = ev.get("request_id")
    if not rid:
        # No request_id in the record. Fall back to a per-line-unique key so
        # distinct records sharing a file don't collide on the PK (v2 always
        # sets request_id, so this is defensive).
        rid = f"{os.path.basename(path)}:{lineno}" if path else None
    if not rid:
        return None
    rule_ids = ",".join(str(m.get("rule_id")) for m in (ev.get("matches") or []) if m.get("rule_id"))
    return (
        str(rid),
        _epoch_ms(ev, path),
        ev.get("timestamp"),
        ((ev.get("service") or {}).get("name")),
        ((ev.get("client") or {}).get("ip")),
        ((ev.get("response") or {}).get("status")),
        _disposition(ev),
        rule_ids,
        json.dumps(ev, separators=(",", ":")),
    )


# ---- ingestion ----
def _is_closed(path: str, now_minute: str) -> bool:
    """True if the file gets no further writes and can be deleted after ingest.

    A current-scheme file is closed once its minute is strictly before the
    current UTC minute (plus a short mtime grace for clock skew). A legacy file
    (no parseable minute) is closed once untouched for longer than the
    corrupt-age grace.
    """
    m = _MINUTE_RE.match(os.path.basename(path))
    if m:
        if m.group(1) >= now_minute:
            return False
        try:
            return time.time() - os.path.getmtime(path) > _MINUTE_GRACE_S
        except OSError:
            return True
    try:
        return time.time() - os.path.getmtime(path) > _CORRUPT_AGE_S
    except OSError:
        return True


def ingest_dir(auditlog_dir: str) -> dict:
    """Ingest audit records (JSON Lines) from the dir into the DB.

    Closed files (their minute has elapsed) are ingested line by line and then
    deleted. The current-minute file is still being appended to, so its lines
    are ingested idempotently (INSERT OR IGNORE on the request_id PK) and the
    file is left in place until it closes — re-reading it is harmless.

    Returns {ingested, deleted, skipped}. Never raises — a bad line is skipped
    and retried on the next pass once the writer has finished it.
    """
    ingested = deleted = skipped = 0
    paths = []
    for pat in _GLOBS:
        try:
            paths.extend(glob.glob(os.path.join(auditlog_dir, pat)))
        except OSError:
            pass
    # Deterministic, de-duplicated order keeps recovery predictable when a
    # backlog spans many worker/minute files.
    paths = sorted(set(paths))

    now_minute = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")

    for p in paths:
        closed = _is_closed(p, now_minute)
        inserts = bad_lines = 0
        with _lock:
            c = _connect()
            try:
                # Read bytes first. Audit values originate in untrusted HTTP
                # input and can contain octets that are not valid UTF-8.
                with open(p, "rb") as fh:
                    for lineno, raw_line in enumerate(fh):
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue
                        try:
                            line = raw_line.decode("utf-8")
                        except UnicodeDecodeError:
                            bad_lines += 1
                            if not closed:
                                # It may be a multibyte character split across
                                # an in-progress append. Retry once the file is
                                # immutable instead of storing a damaged event.
                                continue
                            # A closed file cannot heal. Preserve the event and
                            # replace only invalid octets so one hostile value
                            # cannot wedge the entire ingestion pipeline.
                            line = raw_line.decode("utf-8", errors="replace")
                        try:
                            ev = json.loads(line)
                            row = _row(ev, p, lineno) if isinstance(ev, dict) else None
                        except (ValueError, TypeError, AttributeError):
                            row = None
                        if row is None:
                            bad_lines += 1
                            continue
                        cur = c.execute(
                            "INSERT OR IGNORE INTO events"
                            "(request_id,ts,ts_iso,service,client_ip,status,action,rule_ids,raw)"
                            " VALUES(?,?,?,?,?,?,?,?,?)",
                            row,
                        )
                        inserts += cur.rowcount or 0
                # Commit each file before deleting it. A later malformed file
                # can no longer strand an uncommitted batch or lose prior data.
                if c.in_transaction:
                    c.commit()
            except FileNotFoundError:
                if c.in_transaction:
                    c.rollback()
                continue
            except (OSError, sqlite3.Error):
                if c.in_transaction:
                    c.rollback()
                skipped += 1
                continue

        ingested += inserts
        # Delete only closed files after their transaction is durable; the
        # active file stays so later lines get picked up on a subsequent pass.
        if closed:
            try:
                os.remove(p); deleted += 1
            except OSError:
                pass
        elif bad_lines:
            skipped += 1
    return {"ingested": ingested, "deleted": deleted, "skipped": skipped}


# ---- retention ----
def get_ttl_days() -> int:
    with _lock:
        c = _connect()
        r = c.execute("SELECT value FROM settings WHERE key='ttl_days'").fetchone()
    try:
        return int(r["value"]) if r else DEFAULT_TTL_DAYS
    except (ValueError, TypeError):
        return DEFAULT_TTL_DAYS


def set_ttl_days(days: int) -> int:
    d = int(days)
    if d < TTL_MIN_DAYS or d > TTL_MAX_DAYS:
        raise ValueError(f"ttl_days must be between {TTL_MIN_DAYS} and {TTL_MAX_DAYS}")
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO settings(key,value) VALUES('ttl_days',?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(d),),
        )
        c.commit()
    return d


def get_settings(keys: tuple[str, ...]) -> dict[str, str]:
    """Return the requested persisted console settings.

    Keeping this as an allow-listed key lookup avoids turning the settings table
    into a generic API surface. Callers still own validation for each value.
    """
    if not keys:
        return {}
    placeholders = ",".join("?" for _ in keys)
    with _lock:
        c = _connect()
        rows = c.execute(
            f"SELECT key,value FROM settings WHERE key IN ({placeholders})",
            keys,
        ).fetchall()
    return {r["key"]: r["value"] for r in rows}


def set_settings(values: dict[str, str]) -> None:
    """Atomically persist a validated group of console settings."""
    if not values:
        return
    rows = [(str(k), str(v)) for k, v in values.items()]
    with _lock:
        c = _connect()
        c.executemany(
            "INSERT INTO settings(key,value) VALUES(?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            rows,
        )
        c.commit()


# ---- AI provider profiles ----
def list_ai_profiles() -> list[dict]:
    """Return saved AI profiles without decrypting or exposing credentials."""
    with _lock:
        c = _connect()
        rows = c.execute(
            "SELECT id,name,provider,base_url,model,options,api_key_cipher,"
            "is_default,created_at,updated_at FROM ai_profiles "
            "ORDER BY is_default DESC, name COLLATE NOCASE"
        ).fetchall()
    return [_ai_profile_row(row, include_cipher=False) for row in rows]


def get_ai_profile(profile_id: str, include_cipher: bool = False) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT id,name,provider,base_url,model,options,api_key_cipher,"
            "is_default,created_at,updated_at FROM ai_profiles WHERE id=?",
            (profile_id,),
        ).fetchone()
    return _ai_profile_row(row, include_cipher=include_cipher) if row else None


def _ai_profile_row(row: sqlite3.Row, include_cipher: bool) -> dict:
    try:
        options = json.loads(row["options"] or "{}")
    except (TypeError, ValueError):
        options = {}
    result = {
        "id": row["id"],
        "name": row["name"],
        "provider": row["provider"],
        "base_url": row["base_url"],
        "model": row["model"],
        "options": options if isinstance(options, dict) else {},
        "api_key_configured": bool(row["api_key_cipher"]),
        "is_default": bool(row["is_default"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if include_cipher:
        result["api_key_cipher"] = row["api_key_cipher"]
    return result


def save_ai_profile(profile: dict, api_key_cipher: str | None, keep_api_key: bool = False) -> dict:
    """Insert/update one validated profile and atomically maintain its default flag."""
    now = int(time.time())
    with _lock:
        c = _connect()
        current = c.execute(
            "SELECT api_key_cipher,created_at FROM ai_profiles WHERE id=?",
            (profile["id"],),
        ).fetchone()
        cipher = current["api_key_cipher"] if current and keep_api_key else api_key_cipher
        created_at = current["created_at"] if current else now
        if profile.get("is_default"):
            c.execute("UPDATE ai_profiles SET is_default=0")
        elif not current and c.execute("SELECT 1 FROM ai_profiles LIMIT 1").fetchone() is None:
            profile = {**profile, "is_default": True}
        c.execute(
            "INSERT INTO ai_profiles(id,name,provider,base_url,model,options,api_key_cipher,"
            "is_default,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET name=excluded.name,provider=excluded.provider,"
            "base_url=excluded.base_url,model=excluded.model,options=excluded.options,"
            "api_key_cipher=excluded.api_key_cipher,is_default=excluded.is_default,"
            "updated_at=excluded.updated_at",
            (
                profile["id"], profile["name"], profile["provider"], profile["base_url"],
                profile["model"], json.dumps(profile.get("options") or {}, separators=(",", ":")),
                cipher, 1 if profile.get("is_default") else 0, created_at, now,
            ),
        )
        c.commit()
    return get_ai_profile(profile["id"])


def delete_ai_profile(profile_id: str) -> dict | None:
    """Delete a profile; if it was default, promote the oldest remaining one."""
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT id,name,is_default FROM ai_profiles WHERE id=?", (profile_id,)
        ).fetchone()
        if row is None:
            return None
        c.execute("DELETE FROM ai_profiles WHERE id=?", (profile_id,))
        if row["is_default"]:
            replacement = c.execute(
                "SELECT id FROM ai_profiles ORDER BY created_at,id LIMIT 1"
            ).fetchone()
            if replacement:
                c.execute("UPDATE ai_profiles SET is_default=1 WHERE id=?", (replacement["id"],))
        c.commit()
    return {"id": row["id"], "name": row["name"]}


# ---- assistant conversations ----
def _next_assistant_ts(c: sqlite3.Connection, conversation_id: str) -> int:
    row = c.execute(
        "SELECT updated_at FROM assistant_conversations WHERE id=?", (conversation_id,)
    ).fetchone()
    if row is None:
        raise KeyError("conversation not found")
    return max(int(time.time() * 1000), int(row["updated_at"]) + 1)


def create_conversation(profile_id: str, title: str) -> dict:
    now = int(time.time() * 1000)
    conversation_id = str(uuid.uuid4())
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO assistant_conversations(id,title,profile_id,created_at,updated_at)"
            " VALUES(?,?,?,?,?)",
            (conversation_id, title, profile_id, now, now),
        )
        c.commit()
    return {"id": conversation_id, "title": title, "profile_id": profile_id,
            "created_at": now, "updated_at": now}


def list_conversations(limit: int = 100) -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute(
            "SELECT c.id,c.title,c.profile_id,c.created_at,c.updated_at,"
            "(SELECT content FROM assistant_messages m WHERE m.conversation_id=c.id "
            " ORDER BY m.created_at DESC,m.id DESC LIMIT 1) last_message "
            "FROM assistant_conversations c ORDER BY c.updated_at DESC LIMIT ?",
            (max(1, min(int(limit), 500)),),
        ).fetchall()
    return [dict(row) for row in rows]


def get_conversation(conversation_id: str) -> dict | None:
    with _lock:
        c = _connect()
        conversation = c.execute(
            "SELECT id,title,profile_id,created_at,updated_at FROM assistant_conversations WHERE id=?",
            (conversation_id,),
        ).fetchone()
        if conversation is None:
            return None
        messages = c.execute(
            "SELECT id,role,content,mentions,created_at FROM assistant_messages "
            "WHERE conversation_id=? ORDER BY created_at,id", (conversation_id,)
        ).fetchall()
        activities = c.execute(
            "SELECT id,run_id,seq,kind,status,label,detail,created_at FROM assistant_activities "
            "WHERE conversation_id=? ORDER BY created_at,seq,id", (conversation_id,)
        ).fetchall()
        proposals = c.execute(
            "SELECT id,message_id,summary,operation,status,error,created_at,updated_at "
            "FROM assistant_proposals WHERE conversation_id=? ORDER BY created_at,id",
            (conversation_id,),
        ).fetchall()
        actions = c.execute(
            f"SELECT {_ACTION_COLUMNS} FROM assistant_actions WHERE conversation_id=? ORDER BY created_at,id",
            (conversation_id,),
        ).fetchall()
    result = dict(conversation)
    result["actions"] = [_action_row(row) for row in actions]
    result["messages"] = []
    for row in messages:
        item = dict(row)
        try:
            item["mentions"] = json.loads(item["mentions"] or "[]")
        except (TypeError, ValueError):
            item["mentions"] = []
        result["messages"].append(item)
    result["activities"] = []
    for row in activities:
        item = dict(row)
        try:
            item["detail"] = json.loads(item["detail"] or "{}")
        except (TypeError, ValueError):
            item["detail"] = {}
        result["activities"].append(item)
    result["proposals"] = []
    for row in proposals:
        item = dict(row)
        try:
            item["operation"] = json.loads(item["operation"])
        except (TypeError, ValueError):
            item["operation"] = {}
        result["proposals"].append(item)
    return result


def set_conversation_profile(conversation_id: str, profile_id: str) -> None:
    now = int(time.time() * 1000)
    with _lock:
        c = _connect()
        cur = c.execute(
            "UPDATE assistant_conversations SET profile_id=?,updated_at=? WHERE id=?",
            (profile_id, now, conversation_id),
        )
        if not cur.rowcount:
            raise KeyError("conversation not found")
        c.commit()


def add_assistant_message(conversation_id: str, role: str, content: str, mentions=None) -> dict:
    message_id = str(uuid.uuid4())
    with _lock:
        c = _connect()
        now = _next_assistant_ts(c, conversation_id)
        c.execute(
            "INSERT INTO assistant_messages(id,conversation_id,role,content,mentions,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (message_id, conversation_id, role, content,
             json.dumps(mentions or [], separators=(",", ":")), now),
        )
        c.execute("UPDATE assistant_conversations SET updated_at=? WHERE id=?", (now, conversation_id))
        c.commit()
    return {"id": message_id, "role": role, "content": content,
            "mentions": mentions or [], "created_at": now}


def add_assistant_activity(conversation_id: str, run_id: str, seq: int, kind: str,
                           status: str, label: str, detail=None) -> dict:
    activity_id = str(uuid.uuid4())
    with _lock:
        c = _connect()
        now = _next_assistant_ts(c, conversation_id)
        c.execute(
            "INSERT INTO assistant_activities(id,conversation_id,run_id,seq,kind,status,label,detail,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (activity_id, conversation_id, run_id, int(seq), kind, status, label,
             json.dumps(detail or {}, separators=(",", ":")), now),
        )
        c.execute("UPDATE assistant_conversations SET updated_at=? WHERE id=?", (now, conversation_id))
        c.commit()
    return {"id": activity_id, "run_id": run_id, "seq": int(seq), "kind": kind,
            "status": status, "label": label, "detail": detail or {}, "created_at": now}


def add_assistant_proposal(conversation_id: str, message_id: str, summary: str,
                           operation: dict, before_hash: str | None = None) -> dict:
    """`before_hash`: digest of the Karna plugin the proposal was made against;
    applying it is refused once the plugin no longer matches."""
    proposal_id = str(uuid.uuid4())
    with _lock:
        c = _connect()
        now = _next_assistant_ts(c, conversation_id)
        c.execute(
            "INSERT INTO assistant_proposals(id,conversation_id,message_id,summary,operation,status,error,created_at,updated_at,before_hash) "
            "VALUES(?,?,?,?,?,'pending',NULL,?,?,?)",
            (proposal_id, conversation_id, message_id, summary,
             json.dumps(operation, separators=(",", ":")), now, now, before_hash),
        )
        c.execute("UPDATE assistant_conversations SET updated_at=? WHERE id=?", (now, conversation_id))
        c.commit()
    return {"id": proposal_id, "message_id": message_id, "summary": summary,
            "operation": operation, "status": "pending", "error": None,
            "created_at": now, "updated_at": now}


def get_assistant_proposal(proposal_id: str) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT id,conversation_id,message_id,summary,operation,status,error,created_at,updated_at,before_hash "
            "FROM assistant_proposals WHERE id=?", (proposal_id,),
        ).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["operation"] = json.loads(item["operation"])
    return item


def transition_assistant_proposal(proposal_id: str, expected: str, status: str,
                                  error: str | None = None) -> dict | None:
    now = int(time.time() * 1000)
    with _lock:
        c = _connect()
        cur = c.execute(
            "UPDATE assistant_proposals SET status=?,error=?,updated_at=? WHERE id=? AND status=?",
            (status, error, now, proposal_id, expected),
        )
        c.commit()
    return get_assistant_proposal(proposal_id) if cur.rowcount else None


# ---- assistant transcript (provider-neutral, see assistant_runtime) ----
def append_transcript(conversation_id: str, items: list[dict]) -> None:
    if not items:
        return
    with _lock:
        c = _connect()
        row = c.execute("SELECT COALESCE(MAX(seq),0) m FROM assistant_transcript WHERE conversation_id=?",
                        (conversation_id,)).fetchone()
        seq = int(row["m"])
        for item in items:
            seq += 1
            c.execute("INSERT INTO assistant_transcript(conversation_id,seq,item) VALUES(?,?,?)",
                      (conversation_id, seq, json.dumps(item, ensure_ascii=False, separators=(",", ":"))))
        c.commit()


def get_transcript(conversation_id: str) -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute("SELECT item FROM assistant_transcript WHERE conversation_id=? ORDER BY seq",
                         (conversation_id,)).fetchall()
    out = []
    for row in rows:
        try:
            out.append(json.loads(row["item"]))
        except (TypeError, ValueError):
            continue
    return out


# ---- assistant actions: writes waiting for the user's authorization ----
_ACTION_COLUMNS = ("id,conversation_id,tool_call_id,tool,args,args_hash,review,status,result,error,"
                   "created_at,updated_at,expires_at")


def _action_row(row) -> dict:
    item = dict(row)
    for key, default in (("args", {}), ("review", {})):
        try:
            item[key] = json.loads(item[key])
        except (TypeError, ValueError):
            item[key] = default
    return item


def add_assistant_action(conversation_id: str, tool_call_id: str, tool: str, args: dict,
                         args_hash: str, review: dict, ttl_seconds: int = 600) -> dict:
    action_id = str(uuid.uuid4())
    with _lock:
        c = _connect()
        now = _next_assistant_ts(c, conversation_id)
        c.execute(
            f"INSERT INTO assistant_actions({_ACTION_COLUMNS}) VALUES(?,?,?,?,?,?,?,'pending',NULL,NULL,?,?,?)",
            (action_id, conversation_id, tool_call_id, tool,
             json.dumps(args, ensure_ascii=False, separators=(",", ":")), args_hash,
             json.dumps(review, ensure_ascii=False, separators=(",", ":")), now, now, now + ttl_seconds * 1000),
        )
        c.execute("UPDATE assistant_conversations SET updated_at=? WHERE id=?", (now, conversation_id))
        c.commit()
    return get_assistant_action(action_id)


def get_assistant_action(action_id: str) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute(f"SELECT {_ACTION_COLUMNS} FROM assistant_actions WHERE id=?", (action_id,)).fetchone()
    return _action_row(row) if row else None


def transition_assistant_action(action_id: str, expected: str, status: str,
                                result: str | None = None, error: str | None = None) -> dict | None:
    now = int(time.time() * 1000)
    with _lock:
        c = _connect()
        cur = c.execute(
            "UPDATE assistant_actions SET status=?,result=COALESCE(?,result),error=?,updated_at=? "
            "WHERE id=? AND status=?",
            (status, result, error, now, action_id, expected),
        )
        c.commit()
    return get_assistant_action(action_id) if cur.rowcount else None


def expire_pending_actions(conversation_id: str) -> list[dict]:
    """Mark every pending action of a conversation expired; returns them."""
    now = int(time.time() * 1000)
    with _lock:
        c = _connect()
        rows = c.execute(f"SELECT {_ACTION_COLUMNS} FROM assistant_actions WHERE conversation_id=? AND status='pending'",
                         (conversation_id,)).fetchall()
        c.execute("UPDATE assistant_actions SET status='expired',updated_at=? WHERE conversation_id=? AND status='pending'",
                  (now, conversation_id))
        c.commit()
    return [_action_row(row) for row in rows]


def delete_conversation(conversation_id: str) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT id,title FROM assistant_conversations WHERE id=?", (conversation_id,)).fetchone()
        if row is None:
            return None
        c.execute("DELETE FROM assistant_messages WHERE conversation_id=?", (conversation_id,))
        c.execute("DELETE FROM assistant_activities WHERE conversation_id=?", (conversation_id,))
        c.execute("DELETE FROM assistant_proposals WHERE conversation_id=?", (conversation_id,))
        c.execute("DELETE FROM assistant_transcript WHERE conversation_id=?", (conversation_id,))
        c.execute("DELETE FROM assistant_actions WHERE conversation_id=?", (conversation_id,))
        c.execute("DELETE FROM assistant_conversations WHERE id=?", (conversation_id,))
        c.commit()
    return dict(row)


def cleanup_ttl() -> int:
    """Delete rows older than the configured TTL, then the oldest rows beyond
    MAX_EVENTS. Returns rows removed."""
    cutoff = int((time.time() - get_ttl_days() * 86400) * 1000)
    with _lock:
        c = _connect()
        removed = c.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount or 0
        excess = c.execute("SELECT COUNT(*) FROM events").fetchone()[0] - MAX_EVENTS
        if excess > 0:
            removed += c.execute(
                "DELETE FROM events WHERE request_id IN "
                "(SELECT request_id FROM events ORDER BY ts, request_id LIMIT ?)", (excess,),
            ).rowcount or 0
        c.commit()
        return removed


def purge(auditlog_dir: str | None = None) -> dict:
    """Wipe the store and (optionally) any not-yet-ingested files."""
    with _lock:
        c = _connect()
        n = c.execute("DELETE FROM events").rowcount or 0
        c.commit()
        c.execute("VACUUM")
    files = 0
    if auditlog_dir:
        for pat in _GLOBS:
            try:
                for p in glob.glob(os.path.join(auditlog_dir, pat)):
                    try:
                        os.remove(p); files += 1
                    except OSError:
                        pass
            except OSError:
                pass
    return {"events": n, "files": files}


# ---- queries ----
def recent_events(limit: int = 3000) -> list[dict]:
    """Newest audit log v2 records first, as parsed dicts (for build_payload)."""
    with _lock:
        c = _connect()
        rows = c.execute("SELECT raw FROM events ORDER BY ts DESC LIMIT ?", (int(limit),)).fetchall()
    out = []
    for r in rows:
        try:
            out.append(json.loads(r["raw"]))
        except (ValueError, TypeError):
            continue
    return out


def query_events(service: str | None = None, rule_id: str | None = None, client_ip: str | None = None,
                 action: str | None = None, since_ms: int | None = None, path_contains: str | None = None,
                 limit: int = 20, scan: int = 5000) -> list[dict]:
    """Newest matching audit records. Indexed columns filter in SQL; the path
    filter scans at most `scan` candidate rows."""
    where, params = [], []
    for column, value in (("service", service), ("client_ip", client_ip), ("action", action)):
        if value:
            where.append(f"{column}=?")
            params.append(value)
    if rule_id:
        where.append("(','||rule_ids||',') LIKE ?")
        params.append(f"%,{rule_id},%")
    if since_ms:
        where.append("ts>=?")
        params.append(int(since_ms))
    sql = "SELECT raw FROM events" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY ts DESC LIMIT ?"
    params.append(int(scan if path_contains else limit))
    with _lock:
        c = _connect()
        rows = c.execute(sql, params).fetchall()
    out = []
    for row in rows:
        try:
            ev = json.loads(row["raw"])
        except (TypeError, ValueError):
            continue
        if path_contains and path_contains not in str(((ev.get("request") or {}).get("uri")) or ((ev.get("request") or {}).get("path")) or ""):
            continue
        out.append(ev)
        if len(out) >= limit:
            break
    return out


def get_event(request_id: str) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT raw FROM events WHERE request_id=?", (request_id,)).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row["raw"])
    except (TypeError, ValueError):
        return None


def stats() -> dict:
    with _lock:
        c = _connect()
        r = c.execute("SELECT COUNT(*) n, MIN(ts) lo, MAX(ts) hi FROM events").fetchone()
    n = r["n"] if r else 0
    to_iso = lambda ms: datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat().replace("+00:00", "Z") if ms else None
    size = 0
    try:
        size = os.path.getsize(DB_PATH)
    except OSError:
        pass
    return {"count": n, "oldest": to_iso(r["lo"] if r else None), "newest": to_iso(r["hi"] if r else None),
            "db_bytes": size, "max_events": MAX_EVENTS}
