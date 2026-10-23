"""Karna dashboard backend.

Ingests Karna audit log v2 files into a local SQLite store (see store.py) and
reads from that store + the Kong Admin API, and (auth-required) writes back to
the Admin API only for Karna plugin policy: per-service engine config, rules,
and overrides. Kong services, upstreams, and routes are read-only here. All writes are audited. It
returns the raw shapes the frontend's data layer already knows.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

import auth
import egress
import ai_profiles
import assistant_runtime
import assistant_tools
import kong_connection as kong_target
import store

AUDITLOG_DIR = os.getenv("KARNA_AUDITLOG_DIR", "/var/log/karna")
KONG_ADMIN_DEFAULT_URL = os.getenv("KONG_ADMIN_URL", "http://kong:8001").rstrip("/")
KONG_ADMIN_TOKEN = os.getenv("KONG_ADMIN_TOKEN", "")
# The Admin API token is bound to one origin chosen by the operator, never to
# whatever host the active (UI-editable) connection points at: otherwise a
# session could send the token to any server it names.
KONG_ADMIN_TOKEN_ORIGIN = os.getenv("KONG_ADMIN_TOKEN_ORIGIN", "")
CRS_VERSION = os.getenv("KARNA_CRS_VERSION", "4.x")
MAX_FILES = int(os.getenv("KARNA_MAX_AUDIT_FILES", "3000"))
MAX_EVENTS = int(os.getenv("KARNA_MAX_EVENTS", "300"))
CACHE_TTL = float(os.getenv("KARNA_CACHE_TTL", "4"))
KONG_INVENTORY_TTL = max(1.0, float(os.getenv("KARNA_KONG_INVENTORY_TTL", "300")))
KONG_FORCE_REFRESH_MIN_INTERVAL = 5.0
KONG_PAGE_SIZE = 1000
KONG_MAX_PAGES = 100
INGEST_INTERVAL = float(os.getenv("KARNA_INGEST_INTERVAL", "5"))


async def _ingest_loop():
    """Consume audit-log files into the SQLite store and prune by TTL."""
    while True:
        try:
            res = await asyncio.to_thread(store.ingest_dir, AUDITLOG_DIR)
            removed = await asyncio.to_thread(store.cleanup_ttl)
            if res.get("ingested") or removed:
                _invalidate_cache()
        except Exception:
            pass
        await asyncio.sleep(INGEST_INTERVAL)


def _announce_setup_token() -> None:
    """Print how to create the admin while none exists (docker logs reads stdout)."""
    try:
        token, from_env = auth.ensure_setup_token()
    except auth.AuthError as exc:
        print(f"[karna-console] {exc.detail}", flush=True)
        return
    if not token:
        return
    shown = "the value of KARNA_DASH_SETUP_TOKEN" if from_env else token
    bar = "=" * 72
    print(f"""
{bar}
 Karna Console: first-run setup

 No administrator exists yet. Open the console in your browser and, to
 create the admin account, enter this one-time setup token:

     {shown}

 Only someone who can read this log can create the admin. The token stops
 working as soon as the admin exists.
{bar}
""", flush=True)


def _announce_config_warnings() -> None:
    secret = os.getenv("KARNA_DASH_SECRET")
    if secret and len(secret) < auth.SECRET_MIN_LENGTH:
        print(f"[karna-console] ERROR: KARNA_DASH_SECRET is shorter than {auth.SECRET_MIN_LENGTH} "
              "characters; sign-in will fail until it is fixed or unset.", flush=True)
    if not os.getenv("KARNA_DASH_CREDENTIAL_KEY"):
        print("[karna-console] note: KARNA_DASH_CREDENTIAL_KEY is not set, so the key that encrypts "
              "AI provider credentials is stored on the same /data volume as the credentials. "
              "Set it from a secret manager to keep the two apart.", flush=True)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        store.init()
    except Exception:
        pass
    _announce_config_warnings()
    _announce_setup_token()
    task = asyncio.create_task(_ingest_loop())
    try:
        yield
    finally:
        task.cancel()


# No trailing-slash redirects: behind nginx they would point at port 80.
app = FastAPI(title="Karna dashboard API", docs_url=None, redoc_url=None,
              openapi_url=None, lifespan=lifespan, redirect_slashes=False)

# ---- category derivation (mirror of web/src/data/categories.js) ----
_PREFIX = {
    "913": "scanner", "920": "proto", "921": "proto", "922": "proto",
    "930": "lfi", "931": "rfi", "932": "rce", "933": "php", "934": "generic",
    "941": "xss", "942": "sqli", "943": "session", "944": "java",
}


# rule ids Karna's always-on validation gates write in the audit log (ka_engine.lua)
_GATE_IDS = frozenset({
    "method_allowed", "uri_path_check_violation", "check_request_headers_allowed",
    "check_request_content_type_charset", "check_request_content_type_enforce",
    "request_body_parser_violation", "limit_arg_num", "check_arg_len",
})


def category_for_rule(rule_id: str, tags) -> str:
    rid = str(rule_id or "")
    if rid.startswith("mcp"):
        return "mcp"
    if rid in _GATE_IDS or (rid[:1].isalpha() and rid.startswith(("ka_", "gate_", "method", "content_type", "path", "arg"))):
        return "gate"
    fam = _PREFIX.get(rid[:3])
    if fam:
        return fam
    low = [str(t).lower() for t in (tags or [])]
    if any("sqli" in t or "sql_injection" in t for t in low):
        return "sqli"
    if any("xss" in t for t in low):
        return "xss"
    if any("rce" in t or "command" in t for t in low):
        return "rce"
    if any("lfi" in t for t in low):
        return "lfi"
    if any("scanner" in t for t in low):
        return "scanner"
    return "other"


def disposition(ev: dict) -> str:
    acts = [m.get("action") for m in ev.get("matches", [])]
    if "block" in acts:
        return "blocked"
    if "rate_limited" in acts:
        return "rate_limited"
    if "sanitized" in acts:
        return "sanitized"
    if "detect" in acts:
        return "detected"
    if acts and all(a == "log" for a in acts):
        return "observed"
    return "allowed"


_ENFORCED = {"blocked", "rate_limited", "sanitized"}

# ---- static facts the engine carries (not exposed live) ----
CRS_FIX_IMPACT = {
    "pruned": 95, "bridged": 6,
    "buckets": [
        {"name": "Protocol well-formedness (Kong/nginx already enforce)", "count": 38},
        {"name": "Host / Connection semantics (Kong owns routing)", "count": 22},
        {"name": "Browser-nicety, FP-prone on API clients", "count": 18},
        {"name": "Config-as-rule (schema gates are authoritative)", "count": 17},
    ],
}
DEFAULT_RULESETS = {
    "method_enforcement": True, "scanner_detection": True, "protocol_enforcement": False,
    "protocol_attack": True, "multipart_attack": True, "lfi": True, "rfi": True, "rce": True,
    "php": True, "generic": True, "xss": True, "sqli": True, "session_fixation": True, "java": True,
}

_cache: dict = {"ts": 0.0, "data": None}
_kong_inventory_cache: dict = {
    "ts": 0.0, "key": None, "data": None, "task": None, "generation": 0,
}
_kong_inventory_lock = asyncio.Lock()

_KONG_LEGACY_KEYS = ("kong_protocol", "kong_host", "kong_port")
_KONG_CONNECTIONS_KEY = "kong_connections"
_KONG_ACTIVE_KEY = "kong_active_id"
_KONG_ALL_SETTING_KEYS = (*_KONG_LEGACY_KEYS, _KONG_CONNECTIONS_KEY, _KONG_ACTIVE_KEY)
_KONG_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_KONG_CONNECTIONS = 32


def _fallback_kong_connection(saved: dict[str, str]) -> dict:
    default = kong_target.from_url(KONG_ADMIN_DEFAULT_URL)
    source = "environment"
    connection = default
    if all(key in saved for key in _KONG_LEGACY_KEYS):
        try:
            connection = kong_target.validate({
                "protocol": saved["kong_protocol"],
                "host": saved["kong_host"],
                "port": saved["kong_port"],
            })
            source = "legacy"
        except ValueError:
            pass
    return {
        "id": source,
        "name": "Default Kong" if source == "environment" else "Kong",
        **connection,
        "source": source,
    }


def _normalize_kong_record(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    record_id = raw.get("id")
    if not isinstance(record_id, str) or not _KONG_ID_RE.fullmatch(record_id):
        return None
    try:
        name = kong_target.validate_name(raw.get("name"))
        connection = kong_target.validate({key: raw.get(key) for key in ("protocol", "host", "port")})
    except ValueError:
        return None
    record = {"id": record_id, "name": name, **connection, "source": "settings"}
    metadata = raw.get("metadata")
    if isinstance(metadata, dict):
        clean = {}
        for key in ("version", "hostname"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                clean[key] = value[:128]
        for key in ("services_count", "karna_plugins_count"):
            value = metadata.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                clean[key] = value
        if clean:
            record["metadata"] = clean
    tested = raw.get("last_tested_at")
    if isinstance(tested, int) and not isinstance(tested, bool) and tested > 0:
        record["last_tested_at"] = tested
    return record


def _kong_connections_state() -> tuple[list[dict], str]:
    saved = store.get_settings(_KONG_ALL_SETTING_KEYS)
    records = []
    try:
        raw_records = json.loads(saved.get(_KONG_CONNECTIONS_KEY, "[]"))
    except (TypeError, ValueError):
        raw_records = []
    if isinstance(raw_records, list):
        for raw in raw_records[:_MAX_KONG_CONNECTIONS]:
            record = _normalize_kong_record(raw)
            if record and all(existing["id"] != record["id"] for existing in records):
                records.append(record)
    if not records:
        records = [_fallback_kong_connection(saved)]
    active_id = saved.get(_KONG_ACTIVE_KEY)
    if not isinstance(active_id, str) or all(record["id"] != active_id for record in records):
        active_id = records[0]["id"]
    return records, active_id


def _persist_kong_connections(records: list[dict], active_id: str) -> None:
    persisted = []
    for record in records:
        persisted.append({key: value for key, value in record.items() if key != "source"})
    store.set_settings({
        _KONG_CONNECTIONS_KEY: json.dumps(persisted, separators=(",", ":")),
        _KONG_ACTIVE_KEY: active_id,
    })


def _kong_connection() -> dict:
    records, active_id = _kong_connections_state()
    return next(record for record in records if record["id"] == active_id)


def _kong_admin_url() -> str:
    return kong_target.url(_kong_connection())


def read_events() -> list[dict]:
    """Newest audit log v2 records first, from the SQLite store, capped."""
    return store.recent_events(MAX_FILES)


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return round(s[k], 2)


def aggregate(events: list[dict]) -> dict:
    now = datetime.now(timezone.utc)
    # 24 hourly buckets ending at the current hour
    buckets = []
    base_hour = now.replace(minute=0, second=0, microsecond=0)
    idx = {}
    for i in range(24):
        h = base_hour.timestamp() - (23 - i) * 3600
        idx[int(h // 3600)] = i
        label = datetime.fromtimestamp(h, timezone.utc).strftime("%H:00")
        buckets.append({"h": i, "label": label, "requests": 0, "blocked": 0, "allowed": 0})

    cat_counts = Counter()
    rule_hits = Counter()
    rule_hits_by_service = Counter()
    rule_24h = defaultdict(lambda: {"hits": 0, "hourly": [0] * 24, "ips": set(), "services": Counter(), "blocked": 0})
    rule_msg = {}
    rule_action = {}
    kong_lat = []
    per_service = defaultdict(lambda: {"req": 0, "blk": 0, "lat": []})
    engine = None

    for ev in events:
        if engine is None and isinstance(ev.get("engine"), dict):
            engine = ev["engine"]
        dt = _parse_ts(ev.get("timestamp", ""))
        disp = disposition(ev)
        blocked = disp in _ENFORCED
        b = None
        if dt:
            b = idx.get(int(dt.timestamp() // 3600))
            if b is not None:
                buckets[b]["requests"] += 1
                if blocked:
                    buckets[b]["blocked"] += 1
        svc = (ev.get("service") or {}).get("name") or "—"
        per_service[svc]["req"] += 1
        if blocked:
            per_service[svc]["blk"] += 1
        lat = ((ev.get("response") or {}).get("latencies") or {}).get("kong")
        if isinstance(lat, (int, float)):
            kong_lat.append(lat)
            per_service[svc]["lat"].append(lat)
        matches = ev.get("matches") or []
        for m in matches:
            if not isinstance(m, dict) or m.get("rule_id") is None:
                continue
            rid = str(m["rule_id"])
            if not rid:
                continue
            cat_counts[category_for_rule(rid, m.get("tags"))] += 1
            rule_hits[rid] += 1
            rule_hits_by_service[(svc, rid)] += 1
            rule_msg.setdefault(rid, m.get("message", ""))
            if b is not None:
                # last-24h activity per rule, for the Overview rule timeline
                ra = rule_24h[rid]
                ra["hits"] += 1
                ra["hourly"][b] += 1
                ra["services"][svc] += 1
                ip = (ev.get("client") or {}).get("ip")
                if ip:
                    ra["ips"].add(ip)
                if m.get("action") in ("block", "rate_limited"):
                    ra["blocked"] += 1
            act = m.get("action", "log")
            rule_action[rid] = "block" if act in ("block", "rate_limited") else ("detect" if act in ("detect", "sanitized") else rule_action.get(rid, "detect"))

    for b in buckets:
        b["allowed"] = b["requests"] - b["blocked"]

    total_req = sum(b["requests"] for b in buckets)
    total_blk = sum(b["blocked"] for b in buckets)

    category_counts = [{"id": cid, "count": c} for cid, c in cat_counts.most_common()]
    top_rules = [
        {"rule_id": rid, "message": rule_msg.get(rid, ""), "hits": h, "action": rule_action.get(rid, "detect")}
        for rid, h in rule_hits.most_common(10)
    ]
    rule_activity = [
        {
            "rule_id": rid, "message": rule_msg.get(rid, ""), "action": rule_action.get(rid, "detect"),
            "hits": ra["hits"], "hourly": ra["hourly"], "ips": len(ra["ips"]),
            "services": len(ra["services"]), "top_service": ra["services"].most_common(1)[0][0],
            "blocked_pct": round(100.0 * ra["blocked"] / ra["hits"], 1),
        }
        for rid, ra in sorted(rule_24h.items(), key=lambda kv: (-kv[1]["hits"], kv[0]))[:10]
    ]
    latency = {
        "p50": _percentile(kong_lat, 50), "p95": _percentile(kong_lat, 95),
        "p99": _percentile(kong_lat, 99), "max": round(max(kong_lat), 2) if kong_lat else 0,
    }
    if engine:
        commit = engine.get("commit", "unknown")
        engine = {
            "name": engine.get("name", "karna"),
            "version": engine.get("version", "unknown"),
            "commit": commit,
            "commit_short": (commit[:7] if commit and commit != "unknown" else "unknown"),
            "built_at": "unknown",
            "crs_version": CRS_VERSION,
        }
    else:
        engine = {"name": "karna", "version": "unknown", "commit": "unknown",
                  "commit_short": "unknown", "built_at": "unknown", "crs_version": CRS_VERSION}

    return {
        "engine": engine,
        "traffic": buckets,
        "category_counts": category_counts,
        "top_rules": top_rules,
        "rule_activity": rule_activity,
        "latency": latency,
        "events": events[:MAX_EVENTS],
        "per_service": per_service,
        "rule_hits_by_service": rule_hits_by_service,
    }


def _empty_kong_inventory() -> dict:
    return {
        "services": [],
        "karna_by_service": {},
        "routes_by_service": defaultdict(list),
        "crs_inventory_by_plugin": {},
        "connection": _kong_connection(),
        "connected": False,
    }


def _kong_page_url(admin_url: str, next_value: str) -> str:
    """Resolve a Kong pagination cursor without allowing it to change origin."""
    base = admin_url.rstrip("/") + "/"
    candidate = urljoin(base, next_value)
    expected = urlsplit(base)
    actual = urlsplit(candidate)
    if actual.scheme != expected.scheme or actual.netloc != expected.netloc:
        raise ValueError("Kong pagination cursor changed origin")
    return candidate


async def _fetch_kong_pages(client: httpx.AsyncClient, admin_url: str, resource: str) -> list[dict]:
    """Read every cursor page for one Kong Admin API collection."""
    url = f"{admin_url.rstrip('/')}/{resource.lstrip('/')}?size={KONG_PAGE_SIZE}"
    rows: list[dict] = []
    seen: set[str] = set()
    for _ in range(KONG_MAX_PAGES):
        if url in seen:
            raise ValueError("Kong returned a repeated pagination cursor")
        seen.add(url)
        response = await client.get(url)
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("Kong collection response is not an object")
        page = body.get("data", [])
        if not isinstance(page, list):
            raise ValueError("Kong collection data is not an array")
        rows.extend(item for item in page if isinstance(item, dict))
        next_value = body.get("next")
        if not next_value:
            return rows
        if not isinstance(next_value, str):
            raise ValueError("Kong pagination cursor is not a string")
        url = _kong_page_url(admin_url, next_value)
    raise ValueError("Kong pagination exceeded the safety limit")


def _crs_inventory_groups(plugins: list[dict]) -> dict[str, list[dict]]:
    """Group Karna instances that read the same CRS plugin directory."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for plugin in plugins:
        if plugin.get("name") != "karna" or not plugin.get("id"):
            continue
        path = (plugin.get("config") or {}).get("crs_plugins_path") or "/opt/coreruleset-plugins/"
        if not isinstance(path, str) or not path:
            path = "/opt/coreruleset-plugins/"
        normalized = path if path.endswith("/") else f"{path}/"
        groups[normalized].append(plugin)
    return groups


async def _load_kong_inventory() -> dict:
    """Load the complete Kong topology and Karna configuration once."""
    headers = _kong_headers()
    out = _empty_kong_inventory()
    admin_url = _kong_admin_url()
    try:
        async with egress.client(timeout=10.0, headers=headers) as client:
            svcs, routes, plugins = await asyncio.gather(
                _fetch_kong_pages(client, admin_url, "services"),
                _fetch_kong_pages(client, admin_url, "routes"),
                _fetch_kong_pages(client, admin_url, "plugins"),
            )
    except (httpx.HTTPError, ValueError):
        return out
    out["connected"] = True
    out["services"] = svcs
    for r in routes:
        sid = (r.get("service") or {}).get("id")
        if sid:
            out["routes_by_service"][sid].append(r)
    out["karna_plugin_id_by_service"] = {}
    for p in plugins:
        if p.get("name") == "karna":
            sid = (p.get("service") or {}).get("id")
            if sid:
                out["karna_by_service"][sid] = p.get("config", {})
                out["karna_plugin_id_by_service"][sid] = p.get("id")

    inventory_groups = _crs_inventory_groups(plugins)
    if inventory_groups:
        representatives = [group[0] for group in inventory_groups.values()]
        async with egress.client(timeout=10.0, headers=headers) as client:
            inventory_results = await asyncio.gather(*(
                client.get(f"{admin_url}/karna/crs-plugins/{plugin['id']}")
                for plugin in representatives
            ), return_exceptions=True)
        for group, result in zip(inventory_groups.values(), inventory_results):
            if isinstance(result, httpx.Response) and result.status_code == 200:
                try:
                    inventory = result.json()
                except ValueError:
                    continue
                if isinstance(inventory, dict) and isinstance(inventory.get("plugins"), list):
                    for plugin in group:
                        out["crs_inventory_by_plugin"][plugin["id"]] = inventory
    return out


async def _refresh_kong_inventory(force: bool = False) -> dict:
    """Refresh the shared inventory cache, coalescing concurrent refreshes."""
    async with _kong_inventory_lock:
        key = _kong_admin_url()
        now = time.monotonic()
        max_age = KONG_FORCE_REFRESH_MIN_INTERVAL if force else KONG_INVENTORY_TTL
        if (_kong_inventory_cache["data"] is not None
                and _kong_inventory_cache["key"] == key
                and (now - _kong_inventory_cache["ts"]) < max_age):
            return _kong_inventory_cache["data"]
        generation = _kong_inventory_cache["generation"]
        data = await _load_kong_inventory()
        # Do not publish a response under a different target if the active
        # connection or plugin configuration changed while it was in flight.
        if key == _kong_admin_url() and generation == _kong_inventory_cache["generation"]:
            _kong_inventory_cache.update({"ts": time.monotonic(), "key": key, "data": data})
        return data


def _inventory_refresh_done(task: asyncio.Task) -> None:
    if _kong_inventory_cache.get("task") is task:
        _kong_inventory_cache["task"] = None
    try:
        task.result()
    except Exception:
        pass


async def fetch_kong(force: bool = False) -> dict:
    """Return cached topology; refresh stale data in the background."""
    key = _kong_admin_url()
    now = time.monotonic()
    cached = _kong_inventory_cache.get("data")
    same_target = cached is not None and _kong_inventory_cache.get("key") == key
    fresh = same_target and (now - _kong_inventory_cache["ts"]) < KONG_INVENTORY_TTL
    if force or not same_target:
        return await _refresh_kong_inventory(force=force)
    if fresh:
        return cached

    task = _kong_inventory_cache.get("task")
    if task is None or task.done():
        task = asyncio.create_task(_refresh_kong_inventory())
        _kong_inventory_cache["task"] = task
        task.add_done_callback(_inventory_refresh_done)
    return cached


def _count_json_array(arr) -> int:
    return len(arr) if isinstance(arr, list) else 0


_SERVICE_CONFIG_DEFAULTS = {
    "set_karna_headers": False,
    "local_rules_enabled": True,
    "mcp_enabled": False,
    "mcp_routes": [],
    "mcp_detection_heuristic": False,
    "mcp_protocol_versions_allowed": ["2025-11-25", "2025-06-18", "2025-03-26"],
    "mcp_block_legacy_sse_transport": False,
    "mcp_origin_check_enabled": True,
    "mcp_origins_allowed": [],
    "mcp_max_event_size_bytes": 1048576,
    "mcp_max_stream_buffer_bytes": 8388608,
    "mcp_redact_session_id_in_audit": True,
    "mcp_redact_authorization_in_audit": True,
    "ignore_from_local_ips": False,
    "check_invalid_chars_in_path": False,
    "limit_invalid_chars_in_path": 1,
    "check_special_chars_in_path": True,
    "limit_special_chars_in_path": 3,
    "request_methods_allowed": ["GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS", "PATCH", "PROPFIND"],
    "request_headers_denied": ["content-encoding", "proxy", "lock-token", "content-range", "if"],
    "total_arg_value_length": 64000,
    "restricted_extensions": [],
    "request_content_type_charset_allowed": ["utf-8", "iso-8859-1", "iso-8859-15", "windows-1252"],
    "request_content_type_allowed": [
        "application/x-www-form-urlencoded", "multipart/form-data", "multipart/related",
        "text/xml", "application/xml", "application/soap+xml", "application/json",
        "application/cloudevents+json", "application/cloudevents-batch+json",
    ],
    "request_content_type_enforce": True,
    "limit_arg_name_length": 100,
    "limit_arg_value_length": 400,
    "limit_arg_num": 255,
    "inspection_table_convert": [],
    "validate_utf8_encoding": True,
    "try_bas64decode_if_possible": False,
    "crs_plugins_path": "/opt/coreruleset-plugins/",
    "default_block_response_body": None,
    "default_block_response_headers": {},
    "default_ratelimit_response_body": None,
    "default_ratelimit_response_headers": {},
    "default_50x_response_body": None,
    "default_50x_response_headers": {},
    "auditlog_enabled": True,
    "auditlog_path": "/usr/local/openresty/nginx/logs",
    "auditlog_format": "v2",
    "auditlog_only_on_match": False,
    "auditlog_modsec": False,
    "auditlog_error_log_on_match": False,
    "redis_host": "localhost",
    "redis_port": 6379,
    "redis_inspect_enabled": False,
    "redis_database": 0,
    "redis_timeout_ms": 50,
    "redis_keepalive_pool_size": 64,
    "redis_keepalive_idle_ms": 60000,
    "redis_on_error": "skip",
    "private_debug": False,
}


def _public_service_config(cfg: dict) -> dict:
    """Return every service-scoped schema option except rule payloads and secrets."""
    out = {}
    for field, default in _SERVICE_CONFIG_DEFAULTS.items():
        value = cfg.get(field, default)
        # Avoid leaking mutable defaults into the cached dashboard payload.
        if isinstance(value, list):
            value = list(value)
        elif isinstance(value, dict):
            value = dict(value)
        out[field] = value
    out["redis_password_configured"] = bool(cfg.get("redis_password"))
    return out


def build_payload(events: list[dict], kong: dict) -> dict:
    agg = aggregate(events)
    per_service = agg.pop("per_service")
    rule_hits_by_service = agg.pop("rule_hits_by_service")

    services = []
    overrides_action = []
    overrides_response = []
    local_rules = []
    custom_secrules = []
    crs_plugins_by_name = {}
    rulesets = DEFAULT_RULESETS
    redis = {"host": "—", "port": 6379, "database": 0, "inspect_enabled": False,
             "on_error": "skip", "timeout_ms": 50, "keepalive_pool_size": 64}
    first_cfg_seen = False

    for s in kong.get("services", []):
        sid = s.get("id")
        cfg = kong.get("karna_by_service", {}).get(sid)
        if cfg is None:
            continue  # only services carrying a karna plugin
        routes = kong.get("routes_by_service", {}).get(sid, [])
        r0 = routes[0] if routes else {}
        route_hosts = r0.get("hosts") or []
        route_paths = r0.get("paths") or []
        host = route_hosts[0] if route_hosts else (route_paths[0] if route_paths else (s.get("host") or "—"))
        proto = s.get("protocol") or "http"
        sport = s.get("port") or (443 if proto == "https" else 80)
        upstream_url = f"{proto}://{s.get('host') or ''}:{sport}{s.get('path') or ''}"
        ps = per_service.get(s.get("name") or "—", {"req": 0, "blk": 0, "lat": []})
        block_rate = round((ps["blk"] / ps["req"] * 100), 1) if ps["req"] else 0.0
        plugin_id = kong.get("karna_plugin_id_by_service", {}).get(sid)
        inventory = kong.get("crs_inventory_by_plugin", {}).get(plugin_id, {})
        available_plugins = inventory.get("plugins") if isinstance(inventory.get("plugins"), list) else []
        enabled_plugins = cfg.get("crs_plugins_enabled") or []
        services.append({
            "id": sid, "plugin_id": plugin_id,
            "name": s.get("name") or sid, "host": host, "routes": len(routes),
            "upstream_url": upstream_url, "route_id": r0.get("id"),
            "route_hosts": route_hosts, "route_paths": route_paths,
            "config": {
                **_public_service_config(cfg),
                "engine_blocking_mode": bool(cfg.get("engine_blocking_mode", False)),
                "engine_fast_path": bool(cfg.get("engine_fast_path", True)),
                "engine_re2_scan": bool(cfg.get("engine_re2_scan", True)),
                "engine_ac_pm": bool(cfg.get("engine_ac_pm", True)),
                "engine_re2_match": bool(cfg.get("engine_re2_match", True)),
                "paranoia_level": int(cfg.get("paranoia_level", 1) or 1),
                "coreruleset_enabled": bool(cfg.get("coreruleset_enabled", True)),
                "coreruleset_rulesets": cfg.get("coreruleset_rulesets") or DEFAULT_RULESETS,
                "rules_request_count": _count_json_array(cfg.get("rules_request")),
                "custom_secrules_count": _count_json_array(cfg.get("custom_secrules")),
                "crs_plugins_path": inventory.get("path") or cfg.get("crs_plugins_path") or "/opt/coreruleset-plugins/",
                "crs_plugins_enabled": enabled_plugins,
                "crs_plugins_available": available_plugins,
            },
            "observed": {
                "reqs_24h": ps["req"], "block_rate": block_rate,
                "latency_p95_ms": _percentile(ps["lat"], 95),
                "status": "tuning" if block_rate > 4 else "healthy",
            },
        })

        sname = s.get("name") or sid
        pid = kong.get("karna_plugin_id_by_service", {}).get(sid)
        if not first_cfg_seen:
            rulesets = cfg.get("coreruleset_rulesets") or DEFAULT_RULESETS
            redis = {
                "host": cfg.get("redis_host", "—"), "port": int(cfg.get("redis_port", 6379) or 6379),
                "database": int(cfg.get("redis_database", 0) or 0),
                "inspect_enabled": bool(cfg.get("redis_inspect_enabled", False)),
                "on_error": cfg.get("redis_on_error", "skip"),
                "timeout_ms": int(cfg.get("redis_timeout_ms", 50) or 50),
                "keepalive_pool_size": int(cfg.get("redis_keepalive_pool_size", 64) or 64),
            }
            first_cfg_seen = True

        for i, raw in enumerate(cfg.get("rule_action_overrides") or []):
            try:
                o = json.loads(raw)
                overrides_action.append({"service": sname, "plugin_id": pid, "index": i, "etag": _etag(raw),
                                         "selector": o.get("selector", {}),
                                         "action": o.get("action", {}), "note": "", "by": "", "hits": 0})
            except (ValueError, TypeError):
                continue
        for i, raw in enumerate(cfg.get("rule_response_overrides") or []):
            try:
                o = json.loads(raw)
                overrides_response.append({"service": sname, "plugin_id": pid, "index": i, "etag": _etag(raw),
                                           "selector": o.get("selector", {}),
                                           "response": o.get("response", {}), "by": ""})
            except (ValueError, TypeError):
                continue
        for i, raw in enumerate(cfg.get("rules_request") or []):
            try:
                rule = json.loads(raw)
                action = rule.get("action", {})
                controls = rule.get("rule_control")
                kind = next(iter(action.keys()), "—") if isinstance(action, dict) else "—"
                if kind == "—" and isinstance(controls, list) and controls:
                    kind = "exclusion"
                local_rules.append({"id": str(rule.get("id", "—")), "service": sname,
                                    "plugin_id": pid, "index": i, "etag": _etag(raw), "rule": rule,
                                    "phase": rule.get("phase", "access"), "message": rule.get("message", ""),
                                    "action_kind": kind,
                                    "hits": rule_hits_by_service[(sname, str(rule.get("id", "—")))]})
            except (ValueError, TypeError):
                continue
        for i, raw in enumerate(cfg.get("custom_secrules") or []):
            text = str(raw)
            match = re.search(r"\bid\s*:\s*[\"']?(\d+)", text, re.IGNORECASE)
            rule_id = match.group(1) if match else f"{sname}:{i}"
            custom_secrules.append({"id": rule_id, "service": sname,
                                    "plugin_id": pid, "index": i, "etag": _etag(raw), "text": text,
                                    "hits": rule_hits_by_service[(sname, rule_id)]})
        available_by_name = {
            item.get("name"): item for item in available_plugins
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        for name in sorted(set(available_by_name) | set(enabled_plugins)):
            item = available_by_name.get(name, {})
            plugin_summary = crs_plugins_by_name.setdefault(name, {
                "name": name,
                "installed": name in available_by_name,
                "config_file_count": int(item.get("config_file_count", 0) or 0),
                "services": [],
            })
            if name in enabled_plugins:
                plugin_summary["services"].append(sname)

    st = store.stats()
    ttl_days = store.get_ttl_days()
    log_store = {"engine": "sqlite", "ttl_days": ttl_days, "count": st["count"],
                 "oldest": st["oldest"], "newest": st["newest"], "db_bytes": st["db_bytes"]}
    log_sources = [{"id": "sqlite", "name": "Event store (SQLite)",
                    "detail": f"{st['count']} events · {ttl_days}-day TTL",
                    "format": "audit v2 · ingested from files", "on": True}]

    active_connection = kong.get("connection")
    public_connection = (
        _public_connection(active_connection, active_connection.get("id"))
        if isinstance(active_connection, dict) and active_connection.get("id") else None
    )
    return {
        "ENGINE": agg["engine"],
        "TRAFFIC": agg["traffic"],
        "CATEGORY_COUNTS": agg["category_counts"],
        "TOP_RULES": agg["top_rules"],
        "RULE_ACTIVITY": agg["rule_activity"],
        "SERVICES": services,
        "EVENTS": agg["events"],
        "RULE_ACTION_OVERRIDES": overrides_action,
        "RULE_RESPONSE_OVERRIDES": overrides_response,
        "CRS_RULESETS": rulesets,
        "LOCAL_RULES": local_rules,
        "CUSTOM_SECRULES": custom_secrules,
        "CRS_PLUGINS": sorted(crs_plugins_by_name.values(), key=lambda item: item["name"]),
        "CRS_FIX_IMPACT": CRS_FIX_IMPACT,
        "REDIS": redis,
        "LOG_SOURCES": log_sources,
        "LOG_STORE": log_store,
        "LATENCY": agg["latency"],
        "KONG_CONNECTED": kong.get("connected", False),
        "KONG_CONNECTION": public_connection,
    }


# ---- auth ----
async def require_auth(authorization: str | None = Header(default=None)) -> str:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    sub = auth.verify_token(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Authentication required")
    return sub


def _auth_error(e: auth.AuthError):
    return JSONResponse({"detail": e.detail}, status_code=e.status)


@app.get("/api/healthz")
async def healthz():
    # Liveness only. Internal topology (admin URL, log dir) is deliberately not
    # disclosed on this unauthenticated endpoint.
    return {"ok": True}


@app.get("/api/auth/status")
async def auth_status():
    registered = auth.account_exists()
    return {"registered": registered, "setup_token_required": not registered}


_auth_throttle = auth.Throttle()


async def _throttled(request: Request, fn, *args):
    """Run a blocking credential check off the event loop, counting failures.
    The lockout is global (see auth.Throttle)."""
    wait = _auth_throttle.wait()
    if wait:
        return JSONResponse({"detail": f"Sign-in is locked after too many failed attempts. Try again in {wait} s."},
                            status_code=429, headers={"Retry-After": str(wait)})
    try:
        result = await asyncio.to_thread(fn, *args)
    except auth.AuthError as e:
        if e.status in (401, 403):
            _auth_throttle.failure()
        return _auth_error(e)
    _auth_throttle.success()
    return result


@app.post("/api/auth/register")
async def auth_register(request: Request, payload: dict = Body(...)):
    email = payload.get("email", "")
    out = await _throttled(request, auth.register, email, payload.get("password", ""),
                           payload.get("setup_token", ""))
    if isinstance(out, JSONResponse):
        return out
    return {"token": out, "email": email.strip().lower()}


@app.post("/api/auth/login")
async def auth_login(request: Request, payload: dict = Body(...)):
    email = payload.get("email", "")
    out = await _throttled(request, auth.check_login, email, payload.get("password", ""))
    if isinstance(out, JSONResponse):
        return out
    return {"token": out, "email": email.strip().lower()}


@app.post("/api/auth/logout")
async def auth_logout(sub: str = Depends(require_auth)):
    """Sign out everywhere: every token issued so far stops working."""
    auth.revoke_sessions()
    auth.append_change({"actor": sub, "action": "sessions_revoked", "service": "—", "before": None, "after": None})
    return {"ok": True}


@app.post("/api/auth/password")
async def auth_password(request: Request, payload: dict = Body(...), sub: str = Depends(require_auth)):
    out = await _throttled(request, auth.change_password, sub, payload.get("current_password", ""),
                           payload.get("new_password", ""))
    if isinstance(out, JSONResponse):
        return out
    auth.append_change({"actor": sub, "action": "password_changed", "service": "—", "before": None, "after": None})
    return {"token": out, "email": sub}


@app.get("/api/auth/me")
async def auth_me(sub: str = Depends(require_auth)):
    return {"email": sub}


# ---- read ----
@app.get("/api/dashboard")
async def dashboard(sub: str = Depends(require_auth)):
    now = time.monotonic()
    if _cache["data"] is not None and (now - _cache["ts"]) < CACHE_TTL:
        return JSONResponse(_cache["data"])
    events = read_events()
    kong = await fetch_kong()
    payload = build_payload(events, kong)
    _cache["data"] = payload
    _cache["ts"] = now
    return JSONResponse(payload)


@app.get("/api/changes")
async def changes(sub: str = Depends(require_auth)):
    return {"changes": auth.read_changes(100)}


# ---- AI provider profiles ----
@app.get("/api/ai/providers")
async def ai_provider_catalog(sub: str = Depends(require_auth)):
    return {"providers": ai_profiles.provider_catalog()}


@app.get("/api/ai/profiles")
async def ai_profile_list(sub: str = Depends(require_auth)):
    return {"profiles": store.list_ai_profiles()}


@app.post("/api/ai/profiles")
async def ai_profile_save(payload: dict = Body(...), sub: str = Depends(require_auth)):
    existing = None
    if payload.get("id"):
        existing = store.get_ai_profile(str(payload["id"]))
        if not existing:
            raise HTTPException(status_code=404, detail="AI profile not found.")
    profile, cipher, keep_key = ai_profiles.normalize(payload, existing)
    try:
        saved = store.save_ai_profile(profile, cipher, keep_api_key=keep_key)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="An AI profile with this name already exists.") from exc
    auth.append_change({
        "actor": sub,
        "action": "ai_profile_update" if existing else "ai_profile_create",
        "service": "—",
        "detail": {
            "id": saved["id"], "name": saved["name"], "provider": saved["provider"],
            "model": saved["model"], "api_key_configured": saved["api_key_configured"],
            "is_default": saved["is_default"],
        },
    })
    return {"ok": True, "profile": saved}


@app.post("/api/ai/profiles/test")
async def ai_profile_test(payload: dict = Body(...), sub: str = Depends(require_auth)):
    existing = store.get_ai_profile(str(payload.get("id"))) if payload.get("id") else None
    if payload.get("id") and not existing:
        raise HTTPException(status_code=404, detail="AI profile not found.")
    profile, cipher, keep_key = ai_profiles.normalize(payload, existing)
    if cipher:
        api_key = auth.decrypt_credential(cipher)
    elif keep_key and existing:
        _, api_key = ai_profiles.saved_with_key(existing["id"])
    else:
        api_key = None
    return await ai_profiles.probe(profile, api_key)


@app.delete("/api/ai/profiles/{profile_id}")
async def ai_profile_delete(profile_id: str, sub: str = Depends(require_auth)):
    removed = store.delete_ai_profile(profile_id)
    if not removed:
        raise HTTPException(status_code=404, detail="AI profile not found.")
    auth.append_change({"actor": sub, "action": "ai_profile_remove", "service": "—",
                        "detail": removed})
    return {"ok": True}


def _normalize_mentions(raw) -> list[dict]:
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > 20:
        raise HTTPException(status_code=422, detail="Mentions must be an array of at most 20 resources.")
    out = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="Each mention must be a resource object.")
        kind, resource_id = item.get("type"), item.get("id")
        if kind not in {"service", "config", "rules", "rule"} or not isinstance(resource_id, str) or not 1 <= len(resource_id) <= 200:
            raise HTTPException(status_code=422, detail="Unsupported assistant resource mention.")
        key = (kind, resource_id)
        if key not in seen:
            out.append({"type": kind, "id": resource_id})
            seen.add(key)
    return out


async def _assistant_resources(mentions: list[dict]) -> list[dict]:
    if not mentions:
        return []
    payload = build_payload(read_events(), await fetch_kong())
    services = {item["id"]: item for item in payload["SERVICES"]}
    native = {f"native:{item['plugin_id']}:{item['index']}": item for item in payload["LOCAL_RULES"]}
    seclang = {f"seclang:{item['plugin_id']}:{item['index']}": item for item in payload["CUSTOM_SECRULES"]}
    observed = {}
    for item in payload.get("TOP_RULES") or []:
        rule_id = str(item.get("rule_id") or "").strip() if isinstance(item, dict) else ""
        if rule_id:
            observed[f"observed:{rule_id}"] = {"id": rule_id, "source": "observed",
                                                  "message": item.get("message", ""),
                                                  "hits": int(item.get("hits", 0) or 0),
                                                  "action": item.get("action", "detect")}
    for audit_event in payload.get("EVENTS") or []:
        for match in audit_event.get("matches") or []:
            if not isinstance(match, dict):
                continue
            rule_id = str(match.get("rule_id") or "").strip()
            if not rule_id:
                continue
            entry = observed.setdefault(f"observed:{rule_id}", {
                "id": rule_id, "source": "observed", "message": match.get("message", ""),
                "hits": 0, "action": match.get("action", "detect"), "tags": match.get("tags") or [],
            })
            if not entry.get("message"):
                entry["message"] = match.get("message", "")
            if not entry.get("tags"):
                entry["tags"] = match.get("tags") or []
    rules = {**native, **seclang, **observed}
    resolved = []
    for mention in mentions:
        kind, resource_id = mention["type"], mention["id"]
        if kind in {"service", "config", "rules"}:
            service = services.get(resource_id)
            if not service:
                raise HTTPException(status_code=404, detail=f"Mentioned service no longer exists: {resource_id}")
            entry = {"type": kind, "id": resource_id, "name": service["name"]}
            entry["plugin_id"] = service["plugin_id"]
            if kind == "service":
                entry["service"] = service
                entry["rules"] = [item for item in [*native.values(), *seclang.values()] if item["plugin_id"] == service["plugin_id"]]
            elif kind == "config":
                entry["config"] = service["config"]
            else:
                entry["rules"] = [item for item in [*native.values(), *seclang.values()] if item["plugin_id"] == service["plugin_id"]]
            resolved.append(entry)
        else:
            rule = rules.get(resource_id)
            if not rule:
                raise HTTPException(status_code=404, detail=f"Mentioned rule no longer exists: {resource_id}")
            resolved.append({"type": "rule", "id": resource_id, "rule": rule})
    encoded = json.dumps(resolved, ensure_ascii=False)
    if len(encoded.encode("utf-8")) > 250_000:
        raise HTTPException(status_code=413, detail="Selected resources exceed the assistant context limit.")
    return resolved


def _normalize_assistant_proposal(raw, resources: list[dict]) -> dict:
    if not isinstance(raw, dict) or set(raw) != {"summary", "operation"}:
        raise HTTPException(status_code=422, detail="Proposal must contain only summary and operation.")
    summary, operation = raw["summary"], raw["operation"]
    if not isinstance(summary, str) or not summary.strip() or len(summary.encode("utf-8")) > 500:
        raise HTTPException(status_code=422, detail="Proposal summary must contain 1–500 UTF-8 bytes.")
    if not isinstance(operation, dict):
        raise HTTPException(status_code=422, detail="Proposal operation must be an object.")
    allowed_plugin_ids = {
        item.get("plugin_id") or (item.get("rule") or {}).get("plugin_id")
        for item in resources if isinstance(item, dict)
    } - {None}
    plugin_id = operation.get("plugin_id")
    if not isinstance(plugin_id, str) or plugin_id not in allowed_plugin_ids:
        raise HTTPException(status_code=422, detail="Proposal target must be present in the selected @ context.")

    operation_type = operation.get("type")
    if operation_type == "add_rule":
        if set(operation) != {"type", "plugin_id", "kind", "rule"} or operation.get("kind") != "native":
            raise HTTPException(status_code=422, detail="Assistant proposals may add one native Karna rule.")
        normalized_rule = json.loads(_serialize_rule("native", operation.get("rule")))
        normalized_operation = {"type": "add_rule", "plugin_id": plugin_id,
                                "kind": "native", "rule": normalized_rule}
    elif operation_type == "update_config":
        if set(operation) != {"type", "plugin_id", "changes"}:
            raise HTTPException(status_code=422, detail="Invalid configuration proposal shape.")
        changes = _normalize_service_changes(operation.get("changes"))
        if not changes:
            raise HTTPException(status_code=422, detail="Configuration proposal is empty.")
        if "redis_password" in changes:
            raise HTTPException(status_code=422, detail="The assistant cannot propose credentials.")
        normalized_operation = {"type": "update_config", "plugin_id": plugin_id, "changes": changes}
    elif operation_type == "add_override":
        if set(operation) != {"type", "plugin_id", "kind", "entry"} or operation.get("kind") not in _OVERRIDE_FIELD:
            raise HTTPException(status_code=422, detail="Invalid override proposal shape.")
        entry = _override_entry(operation["kind"], json.loads(json.dumps(operation.get("entry"))))
        normalized_operation = {"type": "add_override", "plugin_id": plugin_id,
                                "kind": operation["kind"], "entry": entry}
    else:
        raise HTTPException(status_code=422, detail="Unsupported assistant proposal operation.")
    return {"summary": summary.strip(), "operation": normalized_operation}


# ---- review of assistant proposals ----
# Written by the server from the operation itself, never by the model: the
# model's summary can be wrong or steered, the review cannot. Any risk listed
# here makes applying the proposal require the service name typed back.
_WEAKER_WHEN_FALSE = {
    "engine_blocking_mode": "Turns blocking off: matches are only logged.",
    "coreruleset_enabled": "Turns the OWASP CoreRuleSet off.",
    "local_rules_enabled": "Turns the service's own rules off.",
    "auditlog_enabled": "Turns audit logging off.",
    "request_content_type_enforce": "Lets bodies with an unexpected Content-Type through uninspected.",
    "check_invalid_chars_in_path": "Turns off the invalid-characters-in-path gate.",
    "check_special_chars_in_path": "Turns off the special-characters-in-path gate.",
    "validate_utf8_encoding": "Turns off UTF-8 validation.",
    "mcp_enabled": "Turns MCP inspection off.",
    "mcp_origin_check_enabled": "Turns the MCP Origin check off.",
    "mcp_redact_session_id_in_audit": "Stops redacting the MCP session id in the audit log.",
    "mcp_redact_authorization_in_audit": "Stops redacting Authorization in the audit log.",
    "mcp_detection_heuristic": "Stops recognising MCP traffic outside the configured MCP routes.",
    "mcp_block_legacy_sse_transport": "Lets the legacy MCP SSE transport through.",
    "try_bas64decode_if_possible": "Stops decoding base64 values before inspection: encoded payloads go through.",
    "redis_inspect_enabled": "Stops reading Redis in rules: ban checks and other redis.* conditions stop matching.",
}
_WEAKER_WHEN_TRUE = {
    "private_debug": "Sends rule internals to clients (private_debug).",
    "ignore_from_local_ips": "Skips inspection for requests from local addresses.",
    "set_karna_headers": "Adds Karna headers to responses, telling clients which rules matched.",
    "auditlog_only_on_match": "Logs only the requests that matched a rule.",
}
_RISKY_ANY_CHANGE = {
    "paranoia_level": "Changes the paranoia level.",
    "coreruleset_rulesets": "Changes which CRS rule categories run.",
    "crs_plugins_enabled": "Changes which CRS exclusion plugins load.",
    "request_methods_allowed": "Changes the allowed HTTP methods.",
    "request_content_type_allowed": "Changes the allowed content types.",
    "request_content_type_charset_allowed": "Changes the allowed charsets.",
    "request_headers_denied": "Changes the denied request headers.",
    "restricted_extensions": "Changes the restricted file extensions.",
    "limit_arg_num": "Changes the argument-count limit.",
    "limit_invalid_chars_in_path": "Changes the invalid-characters-in-path limit.",
    "limit_special_chars_in_path": "Changes the special-characters-in-path limit.",
    "auditlog_path": "Changes where the audit log is written.",
    "crs_plugins_path": "Changes where CRS plugins are loaded from.",
    "redis_host": "Changes the Redis server Karna connects to.",
    "redis_port": "Changes the Redis server Karna connects to.",
    "redis_on_error": "Changes what Karna does when Redis fails.",
    "redis_database": "Changes the Redis database: counters and bans in the current one are no longer read.",
    "redis_timeout_ms": "Changes the Redis timeout: too low and every Redis call fails, which switches rate "
                        "limits and bans off.",
    "mcp_routes": "Changes which routes are inspected as MCP.",
    "mcp_origins_allowed": "Changes which Origins may call the MCP endpoints (the DNS-rebinding guard).",
    "mcp_protocol_versions_allowed": "Changes the allowed MCP protocol versions.",
    "mcp_max_event_size_bytes": "Changes the MCP stream limits.",
    "mcp_max_stream_buffer_bytes": "Changes the MCP stream limits.",
    "auditlog_format": "Changes the audit log format: a collector that expects the other one stops parsing it.",
    "auditlog_modsec": "Changes the audit log format: a collector that expects the other one stops parsing it.",
    "limit_arg_name_length": "Changes an argument length limit.",
    "limit_arg_value_length": "Changes an argument length limit.",
    "total_arg_value_length": "Changes an argument length limit.",
    "inspection_table_convert": "Changes how request values are decoded for inspection.",
}
# The only settings a change of which leaves protection as it is: the engine's
# no-regression speed-ups, Redis connection pooling, an extra error-log line.
# Every other field not listed above gets the generic risk.
_NEUTRAL_FIELDS = {"engine_fast_path", "engine_re2_scan", "engine_ac_pm", "engine_re2_match",
                   "redis_keepalive_pool_size", "redis_keepalive_idle_ms", "auditlog_error_log_on_match"}
# Pages Karna serves on the protected site itself: whoever writes them writes
# content (HTML, scripts, redirects) on that site's origin.
_RESPONSE_PAGE_FIELDS = {
    "default_block_response_body": "Changes the page Karna serves when it blocks a request.",
    "default_block_response_headers": "Changes the headers Karna sends when it blocks a request.",
    "default_ratelimit_response_body": "Changes the page Karna serves when it rate-limits a client.",
    "default_ratelimit_response_headers": "Changes the headers Karna sends when it rate-limits a client.",
    "default_50x_response_body": "Changes the page that replaces the upstream's 5xx errors.",
    "default_50x_response_headers": "Changes the headers sent in place of the upstream's 5xx errors.",
}
_SERVED_AS_WRITTEN = " Clients of the protected site receive it as written: read it below."
_WEAKENING_CONTROLS = ("engine_off", "detection_only", "remove_rule", "remove_rules_by_tag",
                       "remove_target_from_rule_by_id", "remove_target_rule_by_tag", "body_access_off")
_REVIEWED_RULE_ACTIONS = {"fixed_response", "fix_matched_parts", "rate_limit", "redis_incr_key", "redis_set",
                          "redis_sadd", "redis_del", "set_variable", "set_log_fields", "setvar", "log_only",
                          "mcp_event_action"}
# rx patterns that match any value: with them a condition holds for every request.
_MATCH_ALL_RX = {"", ".", ".*", ".+", "^", "$", "^.*", "^.*$", "^.+$", "(.*)", "[\\s\\S]*"}


def _status_of(response: dict, default: int):
    try:
        return int(response.get("status_code", default))
    except (TypeError, ValueError):
        return default


def _response_risks(response, default_status: int, what: str) -> list[str]:
    """Risks of a response Karna would serve: a non-error status (a 200 or a
    redirect where a block was), its own body, its own headers."""
    if not isinstance(response, dict):
        return []
    risks = []
    status = _status_of(response, default_status)
    if status < 400:
        risks.append(f"{what} answers with status {status}, not an error: a blocked request looks like a "
                     "normal answer or a redirect.")
    if response.get("body") not in (None, ""):
        risks.append(f"{what} serves its own body." + _SERVED_AS_WRITTEN)
    if response.get("headers"):
        names = ", ".join(sorted(str(k) for k in response["headers"]))[:200] \
            if isinstance(response["headers"], dict) else "?"
        risks.append(f"{what} sets its own response headers ({names}).")
    return risks


def _response_text(response: dict, default_status: int) -> str:
    out = [f"status {_status_of(response, default_status)}"]
    if response.get("headers"):
        out.append("headers " + json.dumps(response["headers"], ensure_ascii=False))
    if response.get("body") not in (None, ""):
        out += ["", str(response["body"])]
    return "\n".join(out)


def _matches_every_request(conditions) -> bool:
    for cond in conditions if isinstance(conditions, list) else []:
        if not isinstance(cond, dict) or cond.get("negated") is True:
            continue
        if cond.get("op") == "unconditionalMatch":
            return True
        if cond.get("op") == "rx" and cond.get("value") in _MATCH_ALL_RX:
            return True
    return False


def _rule_review(rule: dict) -> tuple[list[str], list[dict]]:
    """(risks, content) of one native rule: what it switches off, what it
    answers to clients, what it writes outside its own match."""
    risks, content = [], []
    controls = json.dumps(rule.get("rule_control") or {})
    found = [c for c in _WEAKENING_CONTROLS if f'"{c}"' in controls]
    if found:
        risks.append("For matching requests the rule switches parts of the WAF off: " + ", ".join(found) + ".")
    action = rule.get("action") if isinstance(rule.get("action"), dict) else {}
    fixed = action.get("fixed_response")
    if isinstance(fixed, dict):
        found = _response_risks(fixed, 403, "The rule's block response")
        risks += found
        if found:
            content.append({"label": "fixed_response", "text": _clip_content(_response_text(fixed, 403))})
    limited = (action.get("rate_limit") or {}).get("response") if isinstance(action.get("rate_limit"), dict) else None
    if isinstance(limited, dict):
        found = _response_risks(limited, 429, "The rule's rate-limit response")
        risks += found
        if found:
            content.append({"label": "rate_limit response", "text": _clip_content(_response_text(limited, 429))})
    if "fix_matched_parts" in action:
        risks.append("Rewrites matching requests before they reach the upstream (fix_matched_parts).")
    variable = action.get("set_variable")
    if isinstance(variable, dict) and variable.get("type") == "shared":
        risks.append(f"Writes kong.ctx.shared.{variable.get('name')}: other Kong plugins can read it and "
                     "change what they do.")
    if "redis_del" in action:
        risks.append("Deletes a Redis key when it matches: this can lift bans or reset counters.")
    if "setvar" in action:
        risks.append("Sets transaction variables (setvar) that other rules read.")
    mcp = action.get("mcp_event_action")
    if isinstance(mcp, dict) and mcp.get("type") in ("replace", "terminate", "inject"):
        risks.append(f"Writes its own content into the MCP stream sent to clients ({mcp.get('type')}).")
        if mcp.get("data"):
            content.append({"label": "mcp_event_action data", "text": _clip_content(str(mcp["data"]))})
    unknown = sorted(set(action) - _REVIEWED_RULE_ACTIONS)
    if unknown:
        risks.append("Uses an action the console does not review: " + ", ".join(unknown) + ".")
    if set(action) - {"log_only"} and _matches_every_request(rule.get("conditions")):
        risks.append("Matches every request: what the rule does applies to all of the service's traffic.")
    return risks, content


def _proposal_review(operation: dict) -> dict:
    """{"changes": [...], "risks": [...], "content"?: [...]} in plain words,
    derived from the operation. `content` carries the text a risk asks the
    user to read (a page body, a rule's response)."""
    changes, risks, content = [], [], []
    kind = operation.get("type")
    if kind == "update_config":
        for field, value in sorted((operation.get("changes") or {}).items()):
            changes.append(f"Set {field} to {json.dumps(value, ensure_ascii=False)[:200]}")
            if field in _WEAKER_WHEN_FALSE or field in _WEAKER_WHEN_TRUE:
                if value is False and field in _WEAKER_WHEN_FALSE:
                    risks.append(_WEAKER_WHEN_FALSE[field])
                elif value is True and field in _WEAKER_WHEN_TRUE:
                    risks.append(_WEAKER_WHEN_TRUE[field])
            elif field in _RESPONSE_PAGE_FIELDS:
                risks.append(_RESPONSE_PAGE_FIELDS[field] + _SERVED_AS_WRITTEN)
                text = value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False)
                content.append({"label": field, "text": _clip_content(text)})
            elif field in _RISKY_ANY_CHANGE:
                if _RISKY_ANY_CHANGE[field] not in risks:
                    risks.append(_RISKY_ANY_CHANGE[field])
            elif field not in _NEUTRAL_FIELDS:
                risks.append(f"Changes {field}: the console cannot tell whether this weakens protection.")
    elif kind == "add_override":
        entry = operation.get("entry") or {}
        kind_name = str(operation.get("kind"))
        changes.append(f"Add {'an' if kind_name[:1] in 'aeiou' else 'a'} {kind_name} override: "
                       f"{json.dumps(entry, ensure_ascii=False, separators=(',', ':'))[:300]}")
        action = (entry.get("action") or {}).get("type")
        if action == "passthrough":
            risks.append("Drops the terminal action of the selected rules (passthrough): they stop blocking.")
        response = entry.get("response")
        if isinstance(response, dict):
            found = _response_risks(response, 403, "The overridden response")
            risks += found
            if found:
                content.append({"label": "response", "text": _clip_content(_response_text(response, 403))})
        if (entry.get("selector") or {}).get("any") is True:
            risks.append("Applies to every rule on the service.")
    elif kind == "add_rule":
        rule = operation.get("rule") or {}
        changes.append(f"Add native rule {rule.get('id', '?')}")
        risks, content = _rule_review(rule)
    review = {"changes": changes, "risks": risks}
    if content:
        review["content"] = content
    return review


# ---- review of raw Admin API writes (kong_request) ----
# kong_request reaches everything the Admin API exposes, so this review starts
# from "risky": a write needs the confirmation text unless it is one of the few
# shapes known to leave protection as it is (tags only, or Karna settings that
# _proposal_review clears). The named risks below only make the card say why.
_RULE_FIELD_LABEL = {
    "rules_request": "native rules",
    "custom_secrules": "SecLang rules",
    "rule_action_overrides": "action overrides",
    "rule_response_overrides": "response overrides",
}
_SECLANG_WEAKENING_RE = re.compile(
    r"ctl:\s*(?:ruleEngine\s*=\s*(?:off|detectiononly)|ruleRemove\w*|requestBodyAccess\s*=\s*off)", re.I)
_SECLANG_DENY_RE = re.compile(r"(?:^|[\",])\s*(?:deny|block)\s*(?:[\",]|$)", re.I)
_SECLANG_STATUS_RE = re.compile(r"status\s*:\s*(\d{3})", re.I)
_KARNA_SCOPE_FIELDS = ("protocols", "service", "route", "consumer")
_CODE_PLUGINS = {"pre-function", "post-function", "exit-transformer",
                 "aws-lambda", "azure-functions", "openwhisk"}
_TRAFFIC_FIELDS = {
    "services": {"host", "port", "path", "protocol", "url"},
    "routes": {"hosts", "paths", "methods", "protocols", "headers", "snis", "service", "sources", "destinations"},
    "upstreams": {"host_header"},
    "targets": {"target"},
}
_GENERIC_KONG_RISK = ("Changes Kong directly through the Admin API. The console cannot tell "
                      "whether this weakens protection: read the exact operation.")
_MAX_CONTENT_CHARS = 4000


def _clip_content(text: str) -> str:
    return text if len(text) <= _MAX_CONTENT_CHARS else text[:_MAX_CONTENT_CHARS] + "\n… (truncated)"


def _code_text(config) -> str:
    """A function plugin's config as the code it runs: each phase's chunks as
    plain text, everything else as JSON (redacted)."""
    if not isinstance(config, dict):
        return json.dumps(assistant_tools.redact(config), indent=2, ensure_ascii=False)
    out, rest = [], {}
    for key, value in config.items():
        if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            out += [f"-- {key}"] + value
        else:
            rest[key] = value
    if rest:
        out.append(json.dumps(assistant_tools.redact(rest), indent=2, ensure_ascii=False))
    return "\n".join(out)


def _rule_field_review(field: str, value) -> tuple[list[str], str]:
    """Risks and display text for a new value of one of Karna's rule arrays."""
    label = _RULE_FIELD_LABEL[field]
    if not isinstance(value, list):
        return [f"Replaces the service's {label} with a non-list value."], json.dumps(value)
    entries = _decode_json_strings(value)
    risks = [f"Replaces the service's {label} ({len(entries)} "
             f"entr{'y' if len(entries) == 1 else 'ies'}): entries not listed here are removed."]
    for entry in entries:
        if field == "custom_secrules":
            text = str(entry)
            found = sorted({m.group(0) for m in _SECLANG_WEAKENING_RE.finditer(text)})
            if found:
                risks.append("A SecLang rule switches parts of the WAF off: " + ", ".join(found) + ".")
            if _SECLANG_DENY_RE.search(text):
                status = _SECLANG_STATUS_RE.search(text)
                if status and int(status.group(1)) < 400:
                    risks.append(f"A SecLang rule blocks with status {status.group(1)}, not an error.")
                if "@unconditionalmatch" in text.lower():
                    risks.append("A SecLang rule blocks every request (@unconditionalMatch).")
            continue
        if not isinstance(entry, dict):
            risks.append(f"One of the {label} is not valid JSON.")
            continue
        if field == "rules_request":
            operation = {"type": "add_rule", "rule": entry}
        else:
            operation = {"type": "add_override", "kind": "action" if field == "rule_action_overrides" else "response",
                         "entry": entry}
        risks += [r for r in _proposal_review(operation)["risks"] if r not in risks]
    text = "\n".join(e if isinstance(e, str) else json.dumps(e, ensure_ascii=False) for e in entries)
    return risks, text


def _karna_config_review(new_cfg, old_cfg: dict) -> tuple[list[str], list[dict], bool]:
    """(risks, content, benign) for a Karna `config` sent through kong_request.
    A value the console's own form would refuse (null on a boolean, a string
    for a number) raises ToolError: Kong would store it and Karna would read
    it as "off"."""
    if not isinstance(new_cfg, dict):
        return ["Replaces Karna's whole configuration."], [], False
    changed = {k: v for k, v in new_cfg.items() if old_cfg.get(k) != v}
    risks, content, benign = [], [], True
    plain = {}
    for field, value in changed.items():
        if field in _RULE_FIELD_LABEL:
            field_risks, text = _rule_field_review(field, value)
            risks += [r for r in field_risks if r not in risks]
            content.append({"label": field, "text": _clip_content(text)})
            benign = False
        elif field in _SERVICE_FIELDS and field != "redis_password":
            plain[field] = value
        else:
            risks.append(f"Changes {field}, a field the console does not review.")
            benign = False
    if plain:
        try:
            normalized = _normalize_service_changes(plain)
        except HTTPException as exc:
            raise ToolError(f"Refused: {exc.detail}. Send a valid value, never null, for a Karna setting.")
        plain_review = _proposal_review({"type": "update_config", "changes": normalized})
        risks += [r for r in plain_review["risks"] if r not in risks]
        content += plain_review.get("content", [])
    return risks, content, benign and not risks


def _kong_write_review(method: str, entity_path: str, body, before) -> tuple[list[str], list[dict]]:
    """(risks, content) for a kong_request write. Never returns no risks for a
    write outside the benign shapes."""
    risks, content = [], []
    parts = entity_path.strip("/").split("/")
    body_dict = body if isinstance(body, dict) else {}
    before_dict = before if isinstance(before, dict) else {}
    benign = method == "PATCH" and isinstance(body, dict) and set(body) <= {"tags"}

    if method == "DELETE":
        what = before_dict.get("name") or before_dict.get("id") or entity_path
        risks.append(f"Deletes {parts[-2].rstrip('s') if len(parts) >= 2 else parts[0]} {what}.")
    if entity_path == "/config":
        risks.append("Replaces Kong's whole configuration.")

    if "plugins" in parts:
        plugin_name = body_dict.get("name") or before_dict.get("name")
        if "enabled" in body_dict and body_dict["enabled"] is not True:
            risks.append(f"Disables the {plugin_name or 'selected'} plugin.")
        if plugin_name in _CODE_PLUGINS:
            risks.append(f"Runs custom code on the gateway ({plugin_name}). It can answer, rewrite or "
                         "forward requests around Karna.")
            content.append({"label": f"{plugin_name} config", "text": _clip_content(_code_text(body_dict.get("config")))})
        elif plugin_name == "request-termination":
            risks.append("Answers requests at the gateway (request-termination): the upstream is never reached.")
        if plugin_name == "karna":
            if method == "DELETE":
                risks.append("Removes Karna: the service is no longer protected.")
            if method != "POST":
                rescoped = [k for k in _KARNA_SCOPE_FIELDS if k in body_dict and body_dict[k] != before_dict.get(k)]
                if rescoped:
                    risks.append("Changes where Karna runs (" + ", ".join(rescoped) + "): some traffic may no "
                                 "longer be inspected.")
            if method in ("PATCH", "PUT", "POST") and "config" in body_dict:
                old_cfg = before_dict.get("config") if method != "POST" else {}
                cfg_risks, cfg_content, cfg_benign = _karna_config_review(body_dict["config"], old_cfg or {})
                risks += [r for r in cfg_risks if r not in risks]
                content += cfg_content
                benign = (method == "PATCH" and set(body_dict) <= {"config", "tags"} and cfg_benign)
    else:
        collection = next((c for c in reversed(parts) if c in _TRAFFIC_FIELDS), None)
        touched = sorted(set(body_dict) & _TRAFFIC_FIELDS.get(collection, set()))
        if touched and method in ("PATCH", "PUT"):
            risks.append(f"Changes where traffic goes ({', '.join(touched)}).")

    if not risks and not benign:
        risks.append(_GENERIC_KONG_RISK)
    return risks, content


async def _plugin_service_name(plugin_id: str) -> str | None:
    inventory = await _refresh_kong_inventory()
    sid = next((sid for sid, pid in (inventory.get("karna_plugin_id_by_service") or {}).items() if pid == plugin_id), None)
    service = next((svc for svc in inventory.get("services") or [] if svc.get("id") == sid), None)
    return (service or {}).get("name") or sid


def _expire_proposal(proposal: dict | None) -> dict | None:
    """Proposals expire like actions: a pending one older than ACTION_TTL_SECONDS
    turns "expired" the first time it is read or applied."""
    if not proposal:
        return proposal
    expires_at = int(proposal.get("created_at") or 0) + ACTION_TTL_SECONDS * 1000
    proposal = {**proposal, "expires_at": expires_at}
    if proposal.get("status") == "pending" and int(time.time() * 1000) > expires_at:
        expired = store.transition_assistant_proposal(proposal["id"], "pending", "expired")
        if expired:
            proposal = {**expired, "expires_at": expires_at}
    return proposal


async def _present_proposal(proposal: dict | None) -> dict | None:
    """A proposal as the browser sees it: plus the server's review and, when the
    review lists risks, the service name to type back before applying."""
    if not proposal:
        return proposal
    proposal = {k: v for k, v in _expire_proposal(proposal).items() if k != "before_hash"}
    review = _proposal_review(proposal.get("operation") or {})
    if review["risks"]:
        review["confirm_service"] = await _plugin_service_name((proposal.get("operation") or {}).get("plugin_id", ""))
    return {**proposal, "review": review}


@app.get("/api/assistant/conversations")
async def assistant_conversations(sub: str = Depends(require_auth)):
    return {"conversations": store.list_conversations()}


@app.get("/api/assistant/conversations/{conversation_id}")
async def assistant_conversation(conversation_id: str, sub: str = Depends(require_auth)):
    conversation = store.get_conversation(conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    conversation["proposals"] = [await _present_proposal(p) for p in conversation.get("proposals") or []]
    return conversation


@app.delete("/api/assistant/conversations/{conversation_id}")
async def assistant_conversation_delete(conversation_id: str, sub: str = Depends(require_auth)):
    removed = store.delete_conversation(conversation_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    auth.append_change({"actor": sub, "action": "assistant_conversation_remove", "service": "—",
                        "detail": removed})
    return {"ok": True}


# ---- assistant tools: reads run, writes wait for the user (see assistant_tools) ----
MAX_AGENT_STEPS = 10
ACTION_TTL_SECONDS = 600


class ToolError(Exception):
    """A tool call the console refused or could not run; told to the model."""


def _since_ms(minutes) -> int | None:
    return int((time.time() - int(minutes) * 60) * 1000) if minutes else None


def _event_summary(ev: dict) -> dict:
    req = ev.get("request") or {}
    return {
        "request_id": ev.get("request_id"), "time": ev.get("timestamp"),
        "service": (ev.get("service") or {}).get("name"), "client_ip": (ev.get("client") or {}).get("ip"),
        "method": req.get("method"), "uri": str(req.get("uri") or "")[:200],
        "status": (ev.get("response") or {}).get("status"),
        "matches": [{"rule_id": m.get("rule_id"), "action": m.get("action"),
                     "message": str(m.get("message") or "")[:120]}
                    for m in (ev.get("matches") or [])[:8] if isinstance(m, dict)],
    }


async def _resolve_service(ref) -> tuple[dict, str | None]:
    inventory = await fetch_kong()
    for svc in inventory.get("services") or []:
        if ref in (svc.get("id"), svc.get("name")):
            return svc, (inventory.get("karna_plugin_id_by_service") or {}).get(svc.get("id"))
    raise ToolError(f"No Kong service named {ref!r}. Use list_services.")


async def _karna_plugin_for(ref) -> tuple[dict, str]:
    svc, plugin_id = await _resolve_service(ref)
    if not plugin_id:
        raise ToolError(f"Karna does not run on service {svc.get('name') or ref!r}.")
    return svc, plugin_id


async def _kong_call(method: str, path: str, body=None) -> tuple[int, object]:
    async with egress.client(timeout=8.0, headers=_kong_headers()) as client:
        response = await client.request(method, f"{_kong_admin_url()}{path}",
                                        json=body if body is not None else None)
    try:
        data = response.json() if response.content else None
    except ValueError:
        data = response.text[:2000]
    return response.status_code, data


def _decode_json_strings(values) -> list:
    out = []
    for raw in values or []:
        try:
            out.append(json.loads(raw) if isinstance(raw, str) and raw.lstrip()[:1] in "{[" else raw)
        except ValueError:
            out.append(raw)
    return out


async def _run_read(name: str, args: dict):
    if name == "read_skill":
        try:
            return {"file": args["file"], "content": assistant_tools.read_skill_file(args["file"])}
        except OSError:
            raise ToolError("The Karna skill is not bundled with this console.")
    if name == "search_events":
        events = await asyncio.to_thread(
            store.query_events, args.get("service"), args.get("rule_id"), args.get("client_ip"),
            args.get("action"), _since_ms(args.get("since_minutes")), args.get("path_contains"),
            int(args.get("limit") or 20))
        return {"count": len(events), "events": [_event_summary(ev) for ev in events]}
    if name == "get_event":
        event = await asyncio.to_thread(store.get_event, args["request_id"])
        if event is None:
            raise ToolError("No stored event with this request_id.")
        return event
    if name == "rule_stats":
        events = await asyncio.to_thread(store.query_events, args.get("service"), None, None, None,
                                         _since_ms(args.get("since_minutes")), None, 5000)
        counts, messages = Counter(), {}
        for ev in events:
            for m in ev.get("matches") or []:
                if isinstance(m, dict) and m.get("rule_id"):
                    counts[(str(m["rule_id"]), str(m.get("action") or ""))] += 1
                    messages.setdefault(str(m["rule_id"]), str(m.get("message") or "")[:120])
        return {"events_scanned": len(events),
                "rules": [{"rule_id": rid, "action": action, "hits": n, "message": messages.get(rid, "")}
                          for (rid, action), n in counts.most_common(40)]}
    if name == "list_services":
        inventory = await fetch_kong()
        by_service = inventory.get("karna_by_service") or {}
        plugin_ids = inventory.get("karna_plugin_id_by_service") or {}
        out = []
        for svc in inventory.get("services") or []:
            cfg = by_service.get(svc.get("id"))
            out.append({"id": svc.get("id"), "name": svc.get("name"), "host": svc.get("host"),
                        "port": svc.get("port"), "protocol": svc.get("protocol"),
                        "karna": None if cfg is None else {
                            "plugin_id": plugin_ids.get(svc.get("id")),
                            "mode": "blocking" if cfg.get("engine_blocking_mode") else "detection",
                            "paranoia_level": cfg.get("paranoia_level")}})
        return {"connected": inventory.get("connected", False), "services": out}
    if name == "get_karna_config":
        svc, plugin_id = await _karna_plugin_for(args["service"])
        status, plugin = await _kong_call("GET", f"/plugins/{plugin_id}")
        if status != 200 or not isinstance(plugin, dict):
            raise ToolError(f"Kong answered {status} for the Karna plugin.")
        cfg = dict(plugin.get("config") or {})
        for field in ("rules_request", "rule_action_overrides", "rule_response_overrides"):
            if field in cfg:
                cfg[field] = _decode_json_strings(cfg[field])
        return {"service": svc.get("name"), "plugin_id": plugin_id, "enabled": plugin.get("enabled"), "config": cfg}
    if name == "console_get_settings":
        st = store.stats()
        connection = _kong_connection()
        return {"event_retention_days": store.get_ttl_days(), "stored_events": st["count"],
                "kong_connection": {"name": connection["name"], "url": kong_target.url(connection)}}
    if name == "kong_request":
        status, data = await _kong_call("GET", args["path"])
        return {"status": status, "body": data}
    raise ToolError(f"{name} is not a read tool.")


def _merge_patch(before, body):
    if not isinstance(before, dict) or not isinstance(body, dict):
        return body
    out = dict(before)
    for key, value in body.items():
        out[key] = _merge_patch(before.get(key), value) if isinstance(value, dict) and isinstance(before.get(key), dict) else value
    return out


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()


async def _service_name_for(entity: dict | None, path: str) -> str | None:
    inventory = await fetch_kong()
    sid = ((entity or {}).get("service") or {}).get("id") if isinstance(entity, dict) else None
    parts = path.strip("/").split("/")
    if not sid and len(parts) >= 2 and parts[0] == "services":
        sid = parts[1]
    if not sid and isinstance(entity, dict) and parts[:1] == ["services"]:
        sid = entity.get("id")
    for svc in inventory.get("services") or []:
        if sid in (svc.get("id"), svc.get("name")):
            return svc.get("name") or svc.get("id")
    return None


async def _review_write(name: str, args: dict) -> tuple[dict, dict]:
    """(args to execute, review). The review is written here from the operation,
    never by the model. Raises ToolError for a change that cannot be valid."""
    try:
        if name == "kong_request":
            method, path, body = args["method"], args["path"], args.get("body")
            entity_path = path.split("?", 1)[0]
            before = None
            if method in ("PATCH", "PUT", "DELETE"):
                status, current = await _kong_call("GET", entity_path)
                if status == 200 and isinstance(current, dict):
                    before = current
                elif method != "PUT":
                    raise ToolError(f"Nothing to change at {entity_path} (Kong answered {status}).")
            after = None if method == "DELETE" else (_merge_patch(before, body) if method == "PATCH" else body)
            risks, content = _kong_write_review(method, entity_path, body, before)
            review = {
                "title": f"{method} {path}",
                "changes": [f"{method} {path}"],
                "risks": risks,
                "body": assistant_tools.redact(body) if body is not None else None,
                "before": assistant_tools.redact(before) if before is not None else None,
                "after": assistant_tools.redact(after) if after is not None else None,
                "before_hash": _digest(before) if before is not None else None,
            }
            if content:
                review["content"] = content
            if risks:
                target = before if before is not None else (body if isinstance(body, dict) else None)
                review["confirm_text"] = await _service_name_for(target, entity_path) or entity_path
            return dict(args), review

        if name in ("karna_update_config", "karna_add_rule", "karna_add_override"):
            svc, plugin_id = await _karna_plugin_for(args["service"])
            if name == "karna_update_config":
                changes = _normalize_service_changes(args["changes"])
                if not changes:
                    raise ToolError("No supported fields to change.")
                if "redis_password" in changes:
                    raise ToolError("Credentials cannot be set from the assistant.")
                operation = {"type": "update_config", "plugin_id": plugin_id, "changes": changes}
            elif name == "karna_add_rule":
                rule = json.loads(_serialize_rule("native", args["rule"]))
                operation = {"type": "add_rule", "plugin_id": plugin_id, "kind": "native", "rule": rule}
            else:
                entry = _override_entry(args["kind"], json.loads(json.dumps(args["entry"])))
                operation = {"type": "add_override", "plugin_id": plugin_id, "kind": args["kind"], "entry": entry}
            review = _proposal_review(operation)
            review["title"] = f"{svc.get('name')}: " + (review["changes"][0] if review["changes"] else name)
            review["operation"] = operation
            status, plugin = await _kong_call("GET", f"/plugins/{plugin_id}")
            if status != 200 or not isinstance(plugin, dict):
                raise ToolError(f"Kong answered {status} for the Karna plugin.")
            review["before_hash"] = _digest(plugin)
            if review["risks"]:
                review["confirm_text"] = svc.get("name") or svc.get("id")
            return {"tool_args": args, "operation": operation}, review

        if name == "console_set_retention":
            days = int(args["days"])
            current = store.get_ttl_days()
            risks = [f"Deletes stored events older than {days} days."] if days < current else []
            review = {"title": f"Keep audit events for {days} days", "changes": [f"Event retention: {current} → {days} days"],
                      "risks": risks}
            if risks:
                review["confirm_text"] = f"{days} days"
            return {"days": days}, review
    except HTTPException as exc:
        raise ToolError(str(exc.detail))
    raise ToolError(f"{name} is not a write tool.")


async def _execute_action(action: dict, sub: str):
    name, args, review = action["tool"], action["args"], action["review"]
    if name == "kong_request":
        method, path, body = args["method"], args["path"], args.get("body")
        if review.get("before_hash"):
            status, current = await _kong_call("GET", path.split("?", 1)[0])
            if status != 200 or _digest(current) != review["before_hash"]:
                raise HTTPException(status_code=409, detail="The entity changed after this action was proposed. Ask the assistant to propose it again.")
        status, data = await _kong_call(method, path, body)
        _invalidate_cache()
        _invalidate_kong_inventory()
        auth.append_change({"actor": sub, "action": "assistant_kong_request", "service": "—",
                            "detail": {"method": method, "path": path,
                                       "body": assistant_tools.redact(body), "status": status}})
        if status >= 400:
            message = data.get("message") if isinstance(data, dict) else str(data)[:300]
            raise HTTPException(status_code=502, detail=f"Kong answered {status}: {message}")
        return {"status": status, "body": data}
    if name in ("karna_update_config", "karna_add_rule", "karna_add_override"):
        op = args["operation"]
        if review.get("before_hash"):
            status, current = await _kong_call("GET", f"/plugins/{op['plugin_id']}")
            if status != 200 or _digest(current) != review["before_hash"]:
                raise HTTPException(status_code=409, detail="The Karna configuration changed after this action was proposed. Ask the assistant to propose it again.")
        if op["type"] == "update_config":
            return await patch_engine(op["plugin_id"], op["changes"], sub)
        if op["type"] == "add_rule":
            return await add_rule(op["plugin_id"], {"kind": "native", "rule": op["rule"]}, sub)
        return await add_override(op["plugin_id"], op["kind"], op["entry"], sub)
    if name == "console_set_retention":
        return await logs_set_ttl({"ttl_days": args["days"]}, sub)
    raise HTTPException(status_code=422, detail="Unsupported action.")


def _console_note(text: str) -> dict:
    return {"role": "user", "content": f"[Console] {text}"}


def _trim_transcript(items: list[dict], max_items: int = 60, max_chars: int = 160_000) -> list[dict]:
    """The most recent part of the transcript that starts at a user turn."""
    total, start = 0, len(items)
    for index in range(len(items) - 1, -1, -1):
        total += len(json.dumps(items[index], ensure_ascii=False))
        if total > max_chars or len(items) - index > max_items:
            break
        if items[index].get("role") == "user":
            start = index
    return items[start:]


async def _agent_run(conversation_id: str, run_id: str, profile: dict, api_key: str | None, event, seq: int):
    """The tool loop for one run. Yields NDJSON event lines."""
    system = assistant_runtime.agent_system_prompt(assistant_tools.skill_overview())
    specs = assistant_tools.tool_specs()
    endpoint = assistant_runtime.endpoint_for(profile)
    for step in range(MAX_AGENT_STEPS):
        items = _trim_transcript(store.get_transcript(conversation_id))
        seq += 1
        yield event("activity", {"activity": store.add_assistant_activity(
            conversation_id, run_id, seq, "provider_api", "running", f"Ask {profile['name']} · {profile['model']}",
            {"method": "POST", "endpoint": endpoint, "step": step + 1, "credential_redacted": True})})
        done = None
        async for kind, data in assistant_runtime.agent_round(profile, api_key, system, items, specs):
            if kind == "delta":
                yield event("message.delta", {"run_id": run_id, "delta": data})
            else:
                done = data
        calls = done["tool_calls"]
        store.append_transcript(conversation_id, [{
            "role": "assistant", "content": done["text"],
            "tool_calls": [{"id": c["id"], "name": c["name"], "arguments": c["arguments"] or {}} for c in calls]}])
        if done["text"].strip():
            record = store.add_assistant_message(conversation_id, "assistant", done["text"].strip())
            yield event("message.completed", {"run_id": run_id, "message": record})
        if not calls:
            return
        waiting = False
        for call in calls:
            name = call["name"]
            if call["arguments"] is None:
                verdict = assistant_tools.Verdict("blocked", "the arguments are not valid JSON")
            else:
                verdict = assistant_tools.classify(name, call["arguments"])
            label = f"{name} " + json.dumps(assistant_tools.redact(call["arguments"] or {}), ensure_ascii=False)[:160]
            if verdict.kind == "blocked":
                result = {"error": f"Blocked by the console: {verdict.reason}"}
                seq += 1
                yield event("activity", {"activity": store.add_assistant_activity(
                    conversation_id, run_id, seq, "tool", "failed", f"Blocked: {label}", {"reason": verdict.reason})})
            elif verdict.kind == "read":
                try:
                    result = await _run_read(name, verdict.args)
                    status = "completed"
                except ToolError as exc:
                    result, status = {"error": str(exc)}, "failed"
                except HTTPException as exc:
                    result, status = {"error": str(exc.detail)}, "failed"
                except httpx.HTTPError:
                    result, status = {"error": "Kong is unreachable."}, "failed"
                seq += 1
                yield event("activity", {"activity": store.add_assistant_activity(
                    conversation_id, run_id, seq, "tool", status, f"Read: {label}", {})})
            elif waiting:
                result = {"error": "Only one change can wait for authorization at a time. Propose the next one "
                                   "after the user decides on the pending one."}
            else:
                try:
                    exec_args, review = await _review_write(name, verdict.args)
                    action = store.add_assistant_action(conversation_id, call["id"], name, exec_args,
                                                        assistant_tools.args_hash(name, exec_args), review,
                                                        ACTION_TTL_SECONDS)
                    yield event("action.created", {"action": action})
                    result = {"status": "waiting_for_user_authorization", "action_id": action["id"],
                              "note": "The user sees this change in the chat with an Authorize button. Do not "
                                      "call it again and do not claim it ran; a [Console] note will say what happened."}
                    waiting = True
                except ToolError as exc:
                    result = {"error": f"Not proposed: {exc}"}
                    seq += 1
                    yield event("activity", {"activity": store.add_assistant_activity(
                        conversation_id, run_id, seq, "tool", "failed", f"Refused: {label}", {"reason": str(exc)})})
                except httpx.HTTPError:
                    result = {"error": "Kong is unreachable."}
            store.append_transcript(conversation_id, [{
                "role": "tool", "tool_call_id": call["id"], "name": name,
                "content": assistant_tools.to_result(result)}])
        if waiting:
            return
    seq += 1
    yield event("activity", {"activity": store.add_assistant_activity(
        conversation_id, run_id, seq, "run", "failed", f"Stopped after {MAX_AGENT_STEPS} steps", {})})


@app.post("/api/assistant/actions/{action_id}/authorize")
async def assistant_action_authorize(action_id: str, payload: dict | None = Body(default=None),
                                     sub: str = Depends(require_auth)):
    action = store.get_assistant_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found.")
    if action["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"This action is {action['status']}.")
    if int(time.time() * 1000) > action["expires_at"]:
        store.transition_assistant_action(action_id, "pending", "expired")
        store.append_transcript(action["conversation_id"], [_console_note(
            f"Action {action_id} ({action['tool']}) expired before the user authorized it. It did not run.")])
        raise HTTPException(status_code=410, detail="This action expired. Ask the assistant to propose it again.")
    review = action["review"] or {}
    if review.get("risks"):
        typed = (payload or {}).get("confirm")
        if not isinstance(typed, str) or typed.strip() != review.get("confirm_text"):
            raise HTTPException(status_code=428, detail="This change is risky: type the confirmation text to authorize it.")
    if assistant_tools.args_hash(action["tool"], action["args"]) != action["args_hash"]:
        raise HTTPException(status_code=409, detail="The stored action does not match what was reviewed.")
    claimed = store.transition_assistant_action(action_id, "pending", "executing")
    if not claimed:
        raise HTTPException(status_code=409, detail="This action is no longer pending.")
    try:
        result = await _execute_action(claimed, sub)
    except (HTTPException, httpx.HTTPError) as exc:
        detail = str(exc.detail) if isinstance(exc, HTTPException) else "Kong is unreachable."
        failed = store.transition_assistant_action(action_id, "executing", "failed", error=detail[:500])
        store.append_transcript(action["conversation_id"], [_console_note(
            f"The user authorized action {action_id} ({action['tool']}), but it failed: {detail}")])
        return {"ok": False, "action": failed}
    result_text = assistant_tools.to_result(result)
    executed = store.transition_assistant_action(action_id, "executing", "executed", result=result_text)
    store.append_transcript(action["conversation_id"], [_console_note(
        f"The user authorized action {action_id} ({action['tool']}). It ran. Result: {result_text}")])
    auth.append_change({"actor": sub, "action": "assistant_action_execute", "service": "—",
                        "detail": {"action_id": action_id, "tool": action["tool"], "title": review.get("title")}})
    return {"ok": True, "action": executed}


@app.post("/api/assistant/actions/{action_id}/reject")
async def assistant_action_reject(action_id: str, sub: str = Depends(require_auth)):
    rejected = store.transition_assistant_action(action_id, "pending", "rejected")
    if not rejected:
        if not store.get_assistant_action(action_id):
            raise HTTPException(status_code=404, detail="Action not found.")
        raise HTTPException(status_code=409, detail="This action is no longer pending.")
    store.append_transcript(rejected["conversation_id"], [_console_note(
        f"The user rejected action {action_id} ({rejected['tool']}). It did not run.")])
    auth.append_change({"actor": sub, "action": "assistant_action_reject", "service": "—",
                        "detail": {"action_id": action_id, "tool": rejected["tool"],
                                   "title": (rejected["review"] or {}).get("title")}})
    return {"ok": True, "action": rejected}


@app.post("/api/assistant/chat")
async def assistant_chat(payload: dict = Body(...), sub: str = Depends(require_auth)):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Chat request must be an object.")
    resume = payload.get("resume") is True
    message = payload.get("message")
    if not resume:
        if not isinstance(message, str) or not message.strip() or len(message.encode("utf-8")) > 20_000:
            raise HTTPException(status_code=422, detail="Message must contain 1–20,000 UTF-8 bytes.")
        message = message.strip()
    mentions = [] if resume else _normalize_mentions(payload.get("mentions"))
    profile_id = payload.get("profile_id")
    if not isinstance(profile_id, str):
        raise HTTPException(status_code=422, detail="Select an AI profile.")
    profile, api_key = ai_profiles.saved_with_key(profile_id)

    conversation_id = payload.get("conversation_id")
    if conversation_id:
        conversation = store.get_conversation(str(conversation_id))
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found.")
        if conversation["profile_id"] != profile_id:
            store.set_conversation_profile(conversation["id"], profile_id)
            conversation["profile_id"] = profile_id
    elif resume:
        raise HTTPException(status_code=422, detail="Resume needs a conversation.")
    else:
        title = re.sub(r"\s+", " ", message)[:80]
        conversation = store.create_conversation(profile_id, title)
    conversation_id = conversation["id"]
    history = list(conversation.get("messages") or [])

    user_record = None
    notes = []
    if not resume:
        # A new message moves on: pending actions are not authorized anymore.
        for expired in store.expire_pending_actions(conversation_id):
            notes.append(f"Action {expired['id']} ({expired['tool']}) was not authorized; the user sent a new "
                         "message instead. It did not run.")
        user_record = store.add_assistant_message(conversation_id, "user", message, mentions)
        # Conversations from before tool use have no transcript: seed it from the messages.
        if not store.get_transcript(conversation_id) and history:
            store.append_transcript(conversation_id, [{"role": m["role"], "content": m["content"]}
                                                      for m in history if m.get("role") in ("user", "assistant")])
    run_id = str(uuid.uuid4())

    def event(event_type: str, data: dict) -> bytes:
        return (json.dumps({"type": event_type, **data}, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")

    async def stream():
        seq = 0
        try:
            yield event("run.started", {"run_id": run_id, "conversation_id": conversation_id, "message": user_record,
                                         "profile": {k: profile[k] for k in ("id", "name", "provider", "model")}})
            resources = []
            if mentions:
                seq += 1
                yield event("activity", {"activity": store.add_assistant_activity(
                    conversation_id, run_id, seq, "context", "running", "Resolve mentioned Karna resources",
                    {"mentions": mentions})})
                resources = await _assistant_resources(mentions)
                seq += 1
                yield event("activity", {"activity": store.add_assistant_activity(
                    conversation_id, run_id, seq, "context", "completed", f"Loaded {len(resources)} context resource(s)",
                    {"resources": [{"type": item["type"], "id": item["id"], "name": item.get("name")} for item in resources]})})
            if not resume:
                content = message
                if resources:
                    context = json.dumps(assistant_tools.redact(resources), ensure_ascii=False, separators=(",", ":"))
                    content = "<karna_resources>\n" + context + "\n</karna_resources>\n\n" + message
                store.append_transcript(conversation_id, [_console_note(n) for n in notes] + [{"role": "user", "content": content}])
            try:
                async for line in _agent_run(conversation_id, run_id, profile, api_key, event, seq):
                    yield line
            except assistant_runtime.ToolsUnsupported:
                if resume:
                    raise HTTPException(status_code=502, detail="This model no longer accepts tools.")
                seq += 20
                yield event("activity", {"activity": store.add_assistant_activity(
                    conversation_id, run_id, seq, "provider_api", "completed",
                    "This model does not support tools: answering without them, changes as proposals", {})})
                async for line in _legacy_run(conversation_id, run_id, profile, api_key, history, message,
                                              resources, event, seq):
                    yield line
            yield event("run.completed", {"run_id": run_id, "conversation_id": conversation_id})
        except asyncio.CancelledError:
            store.add_assistant_activity(conversation_id, run_id, seq + 1, "run", "cancelled", "Run cancelled by client")
            raise
        except HTTPException as exc:
            activity = store.add_assistant_activity(conversation_id, run_id, seq + 1, "run", "failed",
                                                      exc.detail, {"status_code": exc.status_code})
            yield event("activity", {"activity": activity})
            yield event("run.failed", {"run_id": run_id, "conversation_id": conversation_id,
                                        "error": exc.detail, "status_code": exc.status_code})
        except Exception:
            activity = store.add_assistant_activity(conversation_id, run_id, seq + 1, "run", "failed",
                                                      "Assistant run failed")
            yield event("activity", {"activity": activity})
            yield event("run.failed", {"run_id": run_id, "conversation_id": conversation_id,
                                        "error": "Assistant run failed", "status_code": 500})

    return StreamingResponse(stream(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


async def _legacy_run(conversation_id, run_id, profile, api_key, history, message, resources, event, seq):
    """Models without tool calling: one answer, at most one typed proposal."""
    endpoint = assistant_runtime.endpoint_for(profile)
    messages = assistant_runtime.build_messages(history, message, resources)
    model_chunks = []
    visible_filter = assistant_runtime.ProposalStreamFilter()
    async for chunk in assistant_runtime.stream_complete(profile, api_key, messages):
        model_chunks.append(chunk)
        visible = visible_filter.feed(chunk)
        if visible:
            yield event("message.delta", {"run_id": run_id, "delta": visible})
    visible = visible_filter.finish()
    if visible:
        yield event("message.delta", {"run_id": run_id, "delta": visible})
    answer, raw_proposal = assistant_runtime.extract_proposal("".join(model_chunks))
    seq += 1
    yield event("activity", {"activity": store.add_assistant_activity(
        conversation_id, run_id, seq, "provider_api", "completed", "Model response received", {"endpoint": endpoint})})
    assistant_record = store.add_assistant_message(conversation_id, "assistant", answer)
    store.append_transcript(conversation_id, [{"role": "assistant", "content": answer}])
    yield event("message.completed", {"run_id": run_id, "message": assistant_record})
    if raw_proposal is not None:
        try:
            normalized = _normalize_assistant_proposal(raw_proposal, resources)
            status, plugin = await _kong_call("GET", f"/plugins/{normalized['operation']['plugin_id']}")
            if status != 200 or not isinstance(plugin, dict):
                raise HTTPException(status_code=502, detail=f"Kong answered {status} for the Karna plugin.")
            proposal = store.add_assistant_proposal(
                conversation_id, assistant_record["id"], normalized["summary"], normalized["operation"],
                before_hash=_digest(plugin))
            yield event("proposal.created", {"proposal": await _present_proposal(proposal)})
        except (HTTPException, httpx.HTTPError) as exc:
            seq += 1
            reason = exc.detail if isinstance(exc, HTTPException) else "Kong is unreachable."
            yield event("activity", {"activity": store.add_assistant_activity(
                conversation_id, run_id, seq, "proposal", "failed",
                "Unsafe or invalid model proposal was not saved", {"reason": reason})})


@app.post("/api/assistant/proposals/{proposal_id}/apply")
async def assistant_proposal_apply(proposal_id: str, payload: dict | None = Body(default=None),
                                   sub: str = Depends(require_auth)):
    proposal = store.get_assistant_proposal(proposal_id)
    if not proposal:
        raise HTTPException(status_code=404, detail="Assistant proposal not found.")
    presented = await _present_proposal(proposal)
    if presented["status"] == "expired":
        raise HTTPException(status_code=410, detail="This proposal expired. Ask the assistant to propose it again.")
    expected = presented["review"].get("confirm_service")
    if presented["review"]["risks"]:
        if not expected:
            raise HTTPException(status_code=503, detail="The service for this plugin cannot be resolved; refresh the Kong inventory.")
        typed = (payload or {}).get("confirm_service")
        if not isinstance(typed, str) or typed.strip() != expected:
            raise HTTPException(status_code=428, detail="This change needs the service name typed back to apply it.")
    claimed = store.transition_assistant_proposal(proposal_id, "pending", "applying")
    if not claimed:
        raise HTTPException(status_code=409, detail="Assistant proposal is no longer pending.")
    operation = claimed["operation"]
    if claimed.get("before_hash"):
        try:
            status, current = await _kong_call("GET", f"/plugins/{operation['plugin_id']}")
        except httpx.HTTPError:
            store.transition_assistant_proposal(proposal_id, "applying", "pending", "Kong is unreachable.")
            raise HTTPException(status_code=502, detail="Kong is unreachable.")
        if status != 200 or _digest(current) != claimed["before_hash"]:
            detail = "The Karna configuration changed after this proposal was made. Ask the assistant to propose it again."
            store.transition_assistant_proposal(proposal_id, "applying", "expired", detail)
            raise HTTPException(status_code=409, detail=detail)
    try:
        if operation["type"] == "add_rule":
            result = await add_rule(operation["plugin_id"], {"kind": operation["kind"], "rule": operation["rule"]}, sub)
        elif operation["type"] == "update_config":
            result = await patch_engine(operation["plugin_id"], operation["changes"], sub)
        elif operation["type"] == "add_override":
            result = await add_override(operation["plugin_id"], operation["kind"], operation["entry"], sub)
        else:
            raise HTTPException(status_code=422, detail="Unsupported stored proposal operation.")
    except HTTPException as exc:
        store.transition_assistant_proposal(proposal_id, "applying", "pending", str(exc.detail)[:500])
        raise
    except Exception:
        store.transition_assistant_proposal(proposal_id, "applying", "pending", "Karna API request failed.")
        raise
    applied = store.transition_assistant_proposal(proposal_id, "applying", "applied")
    auth.append_change({"actor": sub, "action": "assistant_proposal_apply", "service": "—",
                        "plugin_id": operation["plugin_id"],
                        "detail": {"proposal_id": proposal_id, "type": operation["type"]}})
    return {"ok": True, "proposal": await _present_proposal(applied), "result": result}


@app.post("/api/assistant/proposals/{proposal_id}/reject")
async def assistant_proposal_reject(proposal_id: str, sub: str = Depends(require_auth)):
    rejected = store.transition_assistant_proposal(proposal_id, "pending", "rejected")
    if not rejected:
        proposal = store.get_assistant_proposal(proposal_id)
        if not proposal:
            raise HTTPException(status_code=404, detail="Assistant proposal not found.")
        raise HTTPException(status_code=409, detail="Assistant proposal is no longer pending.")
    auth.append_change({"actor": sub, "action": "assistant_proposal_reject", "service": "—",
                        "plugin_id": rejected["operation"].get("plugin_id"),
                        "detail": {"proposal_id": proposal_id, "type": rejected["operation"].get("type")}})
    return {"ok": True, "proposal": await _present_proposal(rejected)}


@app.post("/api/kong/inventory/refresh")
async def refresh_kong_inventory(sub: str = Depends(require_auth)):
    """Force a complete inventory refresh after out-of-band Kong changes."""
    kong = await fetch_kong(force=True)
    _invalidate_cache()
    protected = len(kong.get("karna_by_service", {}))
    services = len(kong.get("services", []))
    auth.append_change({"actor": sub, "action": "kong_inventory_refresh", "service": "—",
                        "detail": {"connected": kong.get("connected", False),
                                   "services": services, "protected_services": protected}})
    return {"ok": True, "connected": kong.get("connected", False),
            "services": services, "protected_services": protected}


# ---- Kong Admin API connection ----
def _public_connection(connection: dict, active_id: str | None = None) -> dict:
    return {
        "id": connection["id"],
        "name": connection["name"],
        "protocol": connection["protocol"],
        "host": connection["host"],
        "port": connection["port"],
        "url": kong_target.url(connection),
        "source": connection.get("source", "settings"),
        "active": connection["id"] == active_id if active_id is not None else False,
        "metadata": connection.get("metadata", {}),
        "last_tested_at": connection.get("last_tested_at"),
    }


def _connection_response(connection: dict | None = None) -> dict:
    connection = connection or _kong_connection()
    return {
        **_public_connection(connection, connection["id"]),
        "token_configured": bool(KONG_ADMIN_TOKEN),
        "token_applies": bool(_kong_headers(connection)),
    }


_KONG_VERSION_RE = re.compile(r"[0-9][0-9A-Za-z.+_-]{0,63}")
_KONG_HOSTNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")


async def _probe_kong(connection: dict) -> dict:
    """Confirm a Kong Admin API and collect a small, non-sensitive inventory."""
    url = kong_target.url(connection)
    try:
        async with egress.client(timeout=4.0, headers=_kong_headers(connection)) as client:
            response = await client.get(f"{url}/")
            response.raise_for_status()
            body = response.json()
            services, plugins = await asyncio.gather(
                _fetch_kong_pages(client, url, "services"),
                _fetch_kong_pages(client, url, "plugins"),
                return_exceptions=True,
            )
        # Only values shaped like Kong's go back to the browser, so the probe
        # cannot be used to read arbitrary content from another server.
        version = body.get("version") if isinstance(body, dict) else None
        if not isinstance(version, str) or not _KONG_VERSION_RE.fullmatch(version):
            return {"connected": False, "detail": "The endpoint responded but does not look like a Kong Admin API."}
        result = {
            "connected": True,
            "detail": "Kong Admin API reachable",
            "version": version,
            "last_tested_at": int(time.time()),
        }
        hostname = body.get("hostname")
        if isinstance(hostname, str) and _KONG_HOSTNAME_RE.fullmatch(hostname):
            result["hostname"] = hostname
        if isinstance(services, list):
            result["services_count"] = len(services)
        if isinstance(plugins, list):
            result["karna_plugins_count"] = sum(1 for plugin in plugins if plugin.get("name") == "karna")
        return result
    except httpx.HTTPStatusError as exc:
        return {"connected": False, "detail": f"Kong Admin API returned HTTP {exc.response.status_code}."}
    except (httpx.HTTPError, TypeError, ValueError):
        return {"connected": False, "detail": "Could not reach a Kong Admin API at this endpoint."}


def _validate_connection_entry(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Connection settings must be an object")
    unsupported = set(payload) - {"id", "name", "protocol", "host", "port"}
    if unsupported:
        raise HTTPException(status_code=422, detail=f"Unsupported connection fields: {', '.join(sorted(unsupported))}")
    try:
        name = kong_target.validate_name(payload.get("name"))
        connection = kong_target.validate({key: payload.get(key) for key in ("protocol", "host", "port")})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    record_id = payload.get("id")
    if record_id is not None and (not isinstance(record_id, str) or not _KONG_ID_RE.fullmatch(record_id)):
        raise HTTPException(status_code=422, detail="id is invalid")
    return {"id": record_id, "name": name, **connection}


def _probe_metadata(result: dict) -> dict:
    metadata = {}
    for key in ("version", "hostname", "services_count", "karna_plugins_count"):
        if key in result:
            metadata[key] = result[key]
    return metadata


def _upsert_kong_connection(entry: dict, probe: dict | None = None, activate: bool = False) -> tuple[dict, dict]:
    records, active_id = _kong_connections_state()
    before_active = dict(next(item for item in records if item["id"] == active_id))
    record_id = entry.get("id")
    existing_index = next((index for index, record in enumerate(records) if record["id"] == record_id), None) if record_id else None
    if record_id and existing_index is None:
        raise HTTPException(status_code=404, detail="Saved Kong connection not found")
    if any(record["name"].casefold() == entry["name"].casefold() and record["id"] != record_id for record in records):
        raise HTTPException(status_code=409, detail="A Kong connection with this name already exists")
    if existing_index is None:
        if len(records) >= _MAX_KONG_CONNECTIONS:
            raise HTTPException(status_code=409, detail=f"At most {_MAX_KONG_CONNECTIONS} Kong connections can be saved")
        record_id = uuid.uuid4().hex
        record = {"id": record_id, "name": entry["name"], **{key: entry[key] for key in ("protocol", "host", "port")}, "source": "settings"}
        records.append(record)
        existing_index = len(records) - 1
    else:
        previous = records[existing_index]
        record = {
            "id": record_id,
            "name": entry["name"],
            **{key: entry[key] for key in ("protocol", "host", "port")},
            "source": "settings",
        }
        if "metadata" in previous:
            record["metadata"] = previous["metadata"]
        if "last_tested_at" in previous:
            record["last_tested_at"] = previous["last_tested_at"]
        records[existing_index] = record
    if probe and probe.get("connected"):
        record["metadata"] = _probe_metadata(probe)
        record["last_tested_at"] = probe["last_tested_at"]
        records[existing_index] = record
    if activate:
        active_id = record_id
    _persist_kong_connections(records, active_id)
    return record, before_active


def _saved_connection(connection_id: str) -> tuple[dict, list[dict], str]:
    if not _KONG_ID_RE.fullmatch(connection_id):
        raise HTTPException(status_code=404, detail="Saved Kong connection not found")
    records, active_id = _kong_connections_state()
    record = next((item for item in records if item["id"] == connection_id), None)
    if not record:
        raise HTTPException(status_code=404, detail="Saved Kong connection not found")
    return record, records, active_id


@app.get("/api/kong/connection")
async def kong_connection(sub: str = Depends(require_auth)):
    return _connection_response()


@app.get("/api/kong/connections")
async def kong_connections(sub: str = Depends(require_auth)):
    records, active_id = _kong_connections_state()
    return {
        "active_id": active_id,
        "connections": [_public_connection(record, active_id) for record in records],
        "token_configured": bool(KONG_ADMIN_TOKEN),
    }


@app.post("/api/kong/connections")
async def save_kong_connection(payload: dict = Body(...), sub: str = Depends(require_auth)):
    entry = _validate_connection_entry(payload)
    record, _ = _upsert_kong_connection(entry)
    _invalidate_cache()
    _invalidate_kong_inventory()
    auth.append_change({"actor": sub, "action": "kong_connection_save", "service": "—",
                        "detail": {"id": record["id"], "name": record["name"], "url": kong_target.url(record)}})
    records, active_id = _kong_connections_state()
    return {"ok": True, "connection": _public_connection(record, active_id),
            "connections": [_public_connection(item, active_id) for item in records], "active_id": active_id}


@app.post("/api/kong/connections/test-activate")
@app.post("/api/kong/connection/test")
async def test_kong_connection(payload: dict = Body(...), sub: str = Depends(require_auth)):
    entry = _validate_connection_entry(payload)
    result = await _probe_kong(entry)
    candidate = {**entry, "id": entry.get("id") or "candidate", "source": "candidate"}
    if not result.get("connected"):
        return {**_public_connection(candidate), **result, "activated": False}
    record, before_active = _upsert_kong_connection(entry, probe=result, activate=True)
    _invalidate_cache()
    _invalidate_kong_inventory()
    auth.append_change({"actor": sub, "action": "kong_connection_activate", "service": "—",
                        "before": {"name": before_active["name"], "url": kong_target.url(before_active)},
                        "after": {"name": record["name"], "url": kong_target.url(record)}})
    return {**_public_connection(record, record["id"]), **result, "activated": True, "ok": True}


@app.post("/api/kong/connections/{connection_id}/activate")
async def activate_kong_connection(connection_id: str, sub: str = Depends(require_auth)):
    record, records, active_id = _saved_connection(connection_id)
    result = await _probe_kong(record)
    if not result.get("connected"):
        return {**_public_connection(record, active_id), **result, "activated": False}
    before_active = next(item for item in records if item["id"] == active_id)
    index = next(index for index, item in enumerate(records) if item["id"] == connection_id)
    record["metadata"] = _probe_metadata(result)
    record["last_tested_at"] = result["last_tested_at"]
    records[index] = record
    _persist_kong_connections(records, connection_id)
    _invalidate_cache()
    _invalidate_kong_inventory()
    auth.append_change({"actor": sub, "action": "kong_connection_activate", "service": "—",
                        "before": {"name": before_active["name"], "url": kong_target.url(before_active)},
                        "after": {"name": record["name"], "url": kong_target.url(record)}})
    return {**_public_connection(record, connection_id), **result, "activated": True, "ok": True}


@app.delete("/api/kong/connections/{connection_id}")
async def delete_kong_connection(connection_id: str, sub: str = Depends(require_auth)):
    record, records, active_id = _saved_connection(connection_id)
    if connection_id == active_id:
        raise HTTPException(status_code=409, detail="Activate another Kong before removing this connection")
    records = [item for item in records if item["id"] != connection_id]
    _persist_kong_connections(records, active_id)
    auth.append_change({"actor": sub, "action": "kong_connection_remove", "service": "—",
                        "detail": {"id": record["id"], "name": record["name"], "url": kong_target.url(record)}})
    return {"ok": True}


@app.patch("/api/kong/connection")
async def update_kong_connection(payload: dict = Body(...), sub: str = Depends(require_auth)):
    current = _kong_connection()
    entry = _validate_connection_entry({"id": current["id"], "name": payload.get("name", current["name"]),
                                        "protocol": payload.get("protocol"), "host": payload.get("host"), "port": payload.get("port")})
    before = _connection_response(current)
    saved, _ = _upsert_kong_connection(entry, activate=True)
    after = _connection_response(saved)
    _invalidate_cache()
    _invalidate_kong_inventory()
    auth.append_change({"actor": sub, "action": "kong_connection_update", "service": "—",
                        "before": {"name": before["name"], "url": before["url"]},
                        "after": {"name": after["name"], "url": after["url"]}})
    return {"ok": True, **after}


# ---- first-run setup ----
# The setup wizard shows after sign-in until it is finished or skipped once;
# kept server-side so another browser does not show it again.
_SETUP_DONE_KEY = "setup_completed_at"


@app.get("/api/setup")
async def setup_state(sub: str = Depends(require_auth)):
    done = store.get_settings((_SETUP_DONE_KEY,)).get(_SETUP_DONE_KEY)
    return {"completed": bool(done), "completed_at": done or None}


@app.post("/api/setup/complete")
async def setup_complete(payload: dict = Body(default={}), sub: str = Depends(require_auth)):
    skipped = payload.get("skipped") is True
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store.set_settings({_SETUP_DONE_KEY: now})
    auth.append_change({"actor": sub, "action": "setup_skipped" if skipped else "setup_completed",
                        "service": "—", "before": None, "after": None})
    return {"ok": True, "completed_at": now}


# ---- log store: retention (TTL) + purge ----
@app.get("/api/logs/config")
async def logs_config(sub: str = Depends(require_auth)):
    st = store.stats()
    return {"ttl_days": store.get_ttl_days(), "count": st["count"], "max_events": st["max_events"],
            "oldest": st["oldest"], "newest": st["newest"], "db_bytes": st["db_bytes"]}


@app.patch("/api/logs/config")
async def logs_set_ttl(payload: dict = Body(...), sub: str = Depends(require_auth)):
    if "ttl_days" not in payload:
        raise HTTPException(status_code=422, detail="ttl_days required")
    before = store.get_ttl_days()
    try:
        days = store.set_ttl_days(int(payload["ttl_days"]))
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=422, detail=str(e) or "ttl_days must be an integer")
    removed = await asyncio.to_thread(store.cleanup_ttl)
    _invalidate_cache()
    auth.append_change({"actor": sub, "action": "logs_ttl_update", "service": "—",
                        "before": {"ttl_days": before}, "after": {"ttl_days": days},
                        "detail": {"pruned": removed}})
    return {"ok": True, "ttl_days": days, "pruned": removed}


@app.post("/api/logs/purge")
async def logs_purge(payload: dict = Body(default={}), sub: str = Depends(require_auth)):
    if payload.get("confirm") is not True:
        raise HTTPException(status_code=400, detail="purge requires confirm:true")
    res = await asyncio.to_thread(store.purge, AUDITLOG_DIR)
    _invalidate_cache()
    auth.append_change({"actor": sub, "action": "logs_purge", "service": "—",
                        "detail": {"events": res["events"], "files": res["files"]}})
    return {"ok": True, **res}


# ---- write (control plane) ----
def _invalidate_cache():
    _cache["data"] = None
    _cache["ts"] = 0.0


def _invalidate_kong_inventory():
    _kong_inventory_cache.update({
        "ts": 0.0,
        "key": None,
        "data": None,
        "generation": _kong_inventory_cache["generation"] + 1,
    })


def _token_origin() -> str | None:
    """The only origin that receives KONG_ADMIN_TOKEN (None when no token is set)."""
    if not KONG_ADMIN_TOKEN:
        return None
    raw = KONG_ADMIN_TOKEN_ORIGIN or KONG_ADMIN_DEFAULT_URL
    try:
        return kong_target.url(kong_target.parse_url(raw))
    except ValueError:
        return None          # misconfigured: send the token nowhere


def _kong_headers(connection: dict | None = None) -> dict:
    """Admin API headers for a request to `connection` (default: the active one)."""
    origin = _token_origin()
    target = kong_target.url(connection or _kong_connection())
    return {"Kong-Admin-Token": KONG_ADMIN_TOKEN} if origin and target == origin else {}


async def _kong_get_plugin(client, plugin_id):
    r = await client.get(f"{_kong_admin_url()}/plugins/{plugin_id}")
    if r.status_code != 200:
        raise HTTPException(status_code=404, detail="Karna plugin not found")
    plugin = r.json()
    if plugin.get("name") != "karna":
        raise HTTPException(status_code=404, detail="Karna plugin not found")
    return plugin


async def _kong_service_name(client, service_id):
    if not service_id:
        return "—"
    try:
        r = await client.get(f"{_kong_admin_url()}/services/{service_id}")
        return r.json().get("name") or service_id
    except (httpx.HTTPError, ValueError):
        return service_id


_RULESET_KEYS = set(DEFAULT_RULESETS.keys())
_SERVICE_BOOLEAN_FIELDS = {
    "engine_blocking_mode", "coreruleset_enabled", "engine_fast_path",
    "engine_re2_scan", "engine_ac_pm", "engine_re2_match",
    "set_karna_headers", "local_rules_enabled", "mcp_enabled",
    "mcp_detection_heuristic", "mcp_block_legacy_sse_transport",
    "mcp_origin_check_enabled", "mcp_redact_session_id_in_audit",
    "mcp_redact_authorization_in_audit", "ignore_from_local_ips",
    "check_invalid_chars_in_path", "check_special_chars_in_path",
    "request_content_type_enforce", "validate_utf8_encoding",
    "try_bas64decode_if_possible", "auditlog_enabled",
    "auditlog_only_on_match", "auditlog_modsec",
    "auditlog_error_log_on_match", "redis_inspect_enabled", "private_debug",
}
_SERVICE_ARRAY_FIELDS = {
    "mcp_routes", "mcp_protocol_versions_allowed", "mcp_origins_allowed",
    "request_methods_allowed", "request_headers_denied", "restricted_extensions",
    "request_content_type_charset_allowed", "request_content_type_allowed",
    "inspection_table_convert",
}
_SERVICE_HEADER_MAP_FIELDS = {
    "default_block_response_headers", "default_ratelimit_response_headers",
    "default_50x_response_headers",
}
_SERVICE_OPTIONAL_TEXT_FIELDS = {
    "default_block_response_body", "default_ratelimit_response_body",
    "default_50x_response_body",
}
_SERVICE_REQUIRED_TEXT_FIELDS = {"crs_plugins_path", "auditlog_path", "redis_host"}
_SERVICE_ENUM_FIELDS = {
    "auditlog_format": {"v1", "v2"},
    "redis_on_error": {"skip", "fail_open", "fail_closed"},
}
_SERVICE_NUMBER_RANGES = {
    "mcp_max_event_size_bytes": (1, 67108864),
    "mcp_max_stream_buffer_bytes": (1, 268435456),
    "limit_invalid_chars_in_path": (0, 1000000),
    "limit_special_chars_in_path": (0, 1000000),
    "total_arg_value_length": (0, 2147483647),
    "limit_arg_name_length": (0, 2147483647),
    "limit_arg_value_length": (0, 2147483647),
    "limit_arg_num": (0, 2147483647),
    "redis_port": (1, 65535),
    "redis_database": (0, 65535),
    "redis_timeout_ms": (1, 60000),
    "redis_keepalive_pool_size": (1, 4096),
    "redis_keepalive_idle_ms": (0, 3600000),
}
_SERVICE_FIELDS = (
    _SERVICE_BOOLEAN_FIELDS | _SERVICE_ARRAY_FIELDS | _SERVICE_HEADER_MAP_FIELDS |
    _SERVICE_OPTIONAL_TEXT_FIELDS | _SERVICE_REQUIRED_TEXT_FIELDS |
    set(_SERVICE_ENUM_FIELDS) | set(_SERVICE_NUMBER_RANGES) |
    {"paranoia_level", "coreruleset_rulesets", "crs_plugins_enabled", "redis_password"}
)
_NULLABLE_SERVICE_FIELDS = _SERVICE_OPTIONAL_TEXT_FIELDS | {"redis_password"}
_PATH_FIELDS = {"crs_plugins_path", "auditlog_path"}
_MAX_ARRAY_ITEMS = 256
_MAX_ARRAY_ITEM_LENGTH = 1024
_MAX_RESPONSE_BODY_BYTES = 262144
_MAX_HEADER_COUNT = 64
_MAX_HEADER_NAME_LENGTH = 128
_MAX_HEADER_VALUE_LENGTH = 4096
_MAX_SECRET_LENGTH = 4096
_SAFE_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_REDIS_HOST_RE = re.compile(r"^[^\s/@?#\x00]{1,253}$")
_ABSOLUTE_PATH_RE = re.compile(r"^/[^\x00]*$")
_SERVICE_RULE_FIELDS = {
    "custom_secrules", "rules_request", "rule_action_overrides", "rule_response_overrides",
}
_CRS_PLUGIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_CRS_PLUGINS = 32


def _normalize_crs_plugins_enabled(value) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_CRS_PLUGINS:
        raise HTTPException(
            status_code=422,
            detail=f"crs_plugins_enabled must be an array with at most {_MAX_CRS_PLUGINS} entries",
        )
    if any(not isinstance(name, str) or not _CRS_PLUGIN_NAME_RE.fullmatch(name) or name in (".", "..")
           for name in value):
        raise HTTPException(status_code=422, detail="crs_plugins_enabled contains an invalid plugin name")
    return sorted(set(value))


def _normalize_service_array(field: str, value) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_ARRAY_ITEMS:
        raise HTTPException(
            status_code=422,
            detail=f"{field} must be an array with at most {_MAX_ARRAY_ITEMS} entries",
        )
    if any(not isinstance(item, str) or not item.strip() or
           any(char in item for char in ("\x00", "\r", "\n")) or
           len(item.encode("utf-8")) > _MAX_ARRAY_ITEM_LENGTH
           for item in value):
        raise HTTPException(status_code=422, detail=f"{field} contains an invalid value")
    return list(dict.fromkeys(item.strip() for item in value))


def _normalize_header_map(field: str, value) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > _MAX_HEADER_COUNT:
        raise HTTPException(status_code=422, detail=f"{field} must be an object with at most {_MAX_HEADER_COUNT} headers")
    out = {}
    for name, header_value in value.items():
        if (not isinstance(name, str) or len(name) > _MAX_HEADER_NAME_LENGTH or
                not _SAFE_HEADER_NAME_RE.fullmatch(name)):
            raise HTTPException(status_code=422, detail=f"{field} contains an invalid header name")
        if (not isinstance(header_value, str) or any(char in header_value for char in ("\x00", "\r", "\n")) or
                len(header_value.encode("utf-8")) > _MAX_HEADER_VALUE_LENGTH):
            raise HTTPException(status_code=422, detail=f"{field} contains an invalid header value")
        out[name.lower()] = header_value
    return out


def _normalize_service_path(field: str, value: str) -> str:
    if len(value.encode("utf-8")) > 4096 or not _ABSOLUTE_PATH_RE.fullmatch(value):
        raise HTTPException(status_code=422, detail=f"{field} must be an absolute filesystem path")
    if any(part == ".." for part in value.split("/")):
        raise HTTPException(status_code=422, detail=f"{field} cannot contain parent-directory segments")
    normalized = re.sub(r"/+", "/", value)
    if field == "crs_plugins_path" and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _normalize_service_changes(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Karna configuration must be an object")
    unsupported = set(payload) - _SERVICE_FIELDS
    if unsupported:
        hint = ""
        if unsupported & _SERVICE_RULE_FIELDS:
            hint = " Rule payloads are managed by the Rules API."
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported Karna configuration fields: {', '.join(sorted(unsupported))}.{hint}",
        )

    changes = {}
    for field, value in payload.items():
        if field in _NULLABLE_SERVICE_FIELDS and value is None:
            changes[field] = None
        elif field in _SERVICE_BOOLEAN_FIELDS:
            if not isinstance(value, bool):
                raise HTTPException(status_code=422, detail=f"{field} must be a boolean")
            changes[field] = value
        elif field in _SERVICE_ARRAY_FIELDS:
            changes[field] = _normalize_service_array(field, value)
        elif field in _SERVICE_HEADER_MAP_FIELDS:
            changes[field] = _normalize_header_map(field, value)
        elif field in _SERVICE_OPTIONAL_TEXT_FIELDS:
            if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_RESPONSE_BODY_BYTES:
                raise HTTPException(status_code=422, detail=f"{field} must be a string up to {_MAX_RESPONSE_BODY_BYTES} bytes")
            changes[field] = value
        elif field in _SERVICE_REQUIRED_TEXT_FIELDS:
            if not isinstance(value, str) or not value.strip():
                raise HTTPException(status_code=422, detail=f"{field} must be a non-empty string")
            value = value.strip()
            if field in _PATH_FIELDS:
                value = _normalize_service_path(field, value)
            elif field == "redis_host" and not _REDIS_HOST_RE.fullmatch(value):
                raise HTTPException(status_code=422, detail="redis_host must be a hostname or IP address")
            changes[field] = value
        elif field in _SERVICE_ENUM_FIELDS:
            if value not in _SERVICE_ENUM_FIELDS[field]:
                allowed = ", ".join(sorted(_SERVICE_ENUM_FIELDS[field]))
                raise HTTPException(status_code=422, detail=f"{field} must be one of: {allowed}")
            changes[field] = value
        elif field in _SERVICE_NUMBER_RANGES:
            if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
                raise HTTPException(status_code=422, detail=f"{field} must be an integer")
            try:
                number = int(value)
            except (TypeError, ValueError):
                raise HTTPException(status_code=422, detail=f"{field} must be an integer")
            minimum, maximum = _SERVICE_NUMBER_RANGES[field]
            if number < minimum or number > maximum:
                raise HTTPException(status_code=422, detail=f"{field} must be between {minimum} and {maximum}")
            changes[field] = number
        elif field == "paranoia_level":
            if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
                raise HTTPException(status_code=422, detail="paranoia_level must be an integer 1-4")
            try:
                level = int(value)
            except (TypeError, ValueError):
                raise HTTPException(status_code=422, detail="paranoia_level must be an integer 1-4")
            if level < 1 or level > 4:
                raise HTTPException(status_code=422, detail="paranoia_level must be 1-4")
            changes[field] = level
        elif field == "coreruleset_rulesets":
            if (not isinstance(value, dict) or
                    any(key not in _RULESET_KEYS or not isinstance(enabled, bool)
                        for key, enabled in value.items())):
                raise HTTPException(status_code=422, detail="coreruleset_rulesets must map known categories to booleans")
            changes[field] = value
        elif field == "crs_plugins_enabled":
            changes[field] = _normalize_crs_plugins_enabled(value)
        elif field == "redis_password":
            if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_SECRET_LENGTH:
                raise HTTPException(status_code=422, detail=f"redis_password must be a string up to {_MAX_SECRET_LENGTH} bytes")
            changes[field] = value
    return changes


def _audit_safe_config(values: dict) -> dict:
    return {
        key: ({"configured": bool(value)} if key == "redis_password" else value)
        for key, value in values.items()
    }


@app.patch("/api/plugins/{plugin_id}/engine")
async def patch_engine(plugin_id: str, payload: dict = Body(...), sub: str = Depends(require_auth)):
    changes_req = _normalize_service_changes(payload)
    if not changes_req:
        raise HTTPException(status_code=422, detail="No supported fields to update")

    async with egress.client(timeout=6.0, headers=_kong_headers()) as client:
        plugin = await _kong_get_plugin(client, plugin_id)
        cfg = plugin.get("config", {})
        if "crs_plugins_enabled" in changes_req and "crs_plugins_path" not in changes_req:
            inventory_response = await client.get(f"{_kong_admin_url()}/karna/crs-plugins/{plugin_id}")
            if inventory_response.status_code != 200:
                raise HTTPException(status_code=502, detail="Could not inspect installed CoreRuleSet plugins")
            try:
                inventory = inventory_response.json()
            except ValueError:
                raise HTTPException(status_code=502, detail="Kong returned an invalid CoreRuleSet plugin inventory")
            available = {
                item.get("name") for item in (inventory.get("plugins") or [])
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            }
            missing = sorted(set(changes_req["crs_plugins_enabled"]) - available)
            if missing:
                raise HTTPException(
                    status_code=422,
                    detail=f"CoreRuleSet plugin is not installed on Kong: {', '.join(missing)}",
                )
        before = {}
        for k, v in changes_req.items():
            if k == "coreruleset_rulesets":
                merged = dict(cfg.get("coreruleset_rulesets") or DEFAULT_RULESETS)
                before[k] = {kk: merged.get(kk) for kk in v}
                merged.update(v)
                cfg[k] = merged
            elif v is None:
                before[k] = cfg.get(k)
                cfg.pop(k, None)
            else:
                before[k] = cfg.get(k)
                cfg[k] = v
        r = await client.patch(f"{_kong_admin_url()}/plugins/{plugin_id}", json={"config": cfg})
        if r.status_code not in (200, 201):
            raise HTTPException(status_code=502, detail=f"Admin API rejected the change: {r.text[:200]}")
        svc_name = await _kong_service_name(client, (plugin.get("service") or {}).get("id"))

    auth.append_change({"actor": sub, "action": "engine_update", "service": svc_name,
                        "plugin_id": plugin_id, "before": _audit_safe_config(before),
                        "after": _audit_safe_config(changes_req)})
    _invalidate_cache()
    _invalidate_kong_inventory()
    return {"ok": True, "updated": _audit_safe_config(changes_req)}


# rule_action_overrides / rule_response_overrides (selector-based virtual patching)
_OVERRIDE_FIELD = {"action": "rule_action_overrides", "response": "rule_response_overrides"}


def _override_entry(kind, payload):
    sel = payload.get("selector")
    if not isinstance(sel, dict):
        raise HTTPException(status_code=422, detail="selector must be an object")
    positive = any(sel.get(k) for k in ("ids", "id_ranges", "tags")) or sel.get("any") is True
    if not positive:
        raise HTTPException(status_code=422, detail="selector needs ids, id_ranges, tags, or any:true")
    if kind == "action":
        act = payload.get("action")
        if not isinstance(act, dict) or act.get("type") not in ("fix", "passthrough", "block"):
            raise HTTPException(status_code=422, detail="action.type must be fix, passthrough, or block")
        return {"selector": sel, "action": act}
    resp = payload.get("response")
    if not isinstance(resp, dict) or not resp:
        raise HTTPException(status_code=422, detail="response must be a non-empty object")
    if "status_code" in resp:
        try:
            resp["status_code"] = int(resp["status_code"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="response.status_code must be an integer")
    return {"selector": sel, "response": resp}


@app.post("/api/plugins/{plugin_id}/overrides/{kind}")
async def add_override(plugin_id: str, kind: str, payload: dict = Body(...), sub: str = Depends(require_auth)):
    if kind not in _OVERRIDE_FIELD:
        raise HTTPException(status_code=422, detail="kind must be 'action' or 'response'")
    entry = _override_entry(kind, payload)
    field = _OVERRIDE_FIELD[kind]
    async with egress.client(timeout=6.0, headers=_kong_headers()) as client:
        plugin = await _kong_get_plugin(client, plugin_id)
        cfg = plugin.get("config", {})
        arr = list(cfg.get(field) or [])
        arr.append(json.dumps(entry, separators=(",", ":")))
        cfg[field] = arr
        await _patch_cfg(client, plugin_id, cfg)
        svc_name = await _kong_service_name(client, (plugin.get("service") or {}).get("id"))
    auth.append_change({"actor": sub, "action": f"{kind}_override_add", "service": svc_name,
                        "plugin_id": plugin_id, "detail": entry})
    _invalidate_cache()
    _invalidate_kong_inventory()
    return {"ok": True, "count": len(arr)}


@app.patch("/api/plugins/{plugin_id}/overrides/{kind}/{index}")
async def edit_override(plugin_id: str, kind: str, index: int, payload: dict = Body(...),
                        expected: str | None = None, sub: str = Depends(require_auth)):
    if kind not in _OVERRIDE_FIELD:
        raise HTTPException(status_code=422, detail="kind must be 'action' or 'response'")
    entry = _override_entry(kind, payload)
    field = _OVERRIDE_FIELD[kind]
    async with egress.client(timeout=6.0, headers=_kong_headers()) as client:
        plugin = await _kong_get_plugin(client, plugin_id)
        cfg = plugin.get("config", {})
        arr = list(cfg.get(field) or [])
        _check_entry(arr, index, expected, "override")
        arr[index] = json.dumps(entry, separators=(",", ":"))
        cfg[field] = arr
        await _patch_cfg(client, plugin_id, cfg)
        svc_name = await _kong_service_name(client, (plugin.get("service") or {}).get("id"))
    auth.append_change({"actor": sub, "action": f"{kind}_override_update", "service": svc_name,
                        "plugin_id": plugin_id, "detail": {"index": index, "entry": entry}})
    _invalidate_cache()
    _invalidate_kong_inventory()
    return {"ok": True}


@app.delete("/api/plugins/{plugin_id}/overrides/{kind}/{index}")
async def delete_override(plugin_id: str, kind: str, index: int, expected: str | None = None,
                          sub: str = Depends(require_auth)):
    if kind not in _OVERRIDE_FIELD:
        raise HTTPException(status_code=422, detail="kind must be 'action' or 'response'")
    field = _OVERRIDE_FIELD[kind]
    async with egress.client(timeout=6.0, headers=_kong_headers()) as client:
        plugin = await _kong_get_plugin(client, plugin_id)
        cfg = plugin.get("config", {})
        arr = list(cfg.get(field) or [])
        _check_entry(arr, index, expected, "override")
        removed = arr.pop(index)
        cfg[field] = arr
        await _patch_cfg(client, plugin_id, cfg)
        svc_name = await _kong_service_name(client, (plugin.get("service") or {}).get("id"))
    auth.append_change({"actor": sub, "action": f"{kind}_override_remove", "service": svc_name,
                        "plugin_id": plugin_id, "detail": {"index": index, "removed": removed}})
    _invalidate_cache()
    _invalidate_kong_inventory()
    return {"ok": True, "count": len(arr)}


def _etag(raw) -> str:
    """Content tag of one stored override / rule entry, as Kong keeps it."""
    return hashlib.sha256(str(raw).encode("utf-8")).hexdigest()[:16]


def _check_entry(arr: list, index: int, expected: str | None, what: str) -> None:
    """Edit and delete address entries by position in a config array; the
    content tag makes sure the entry is still the one the operator saw, so a
    concurrent change cannot make us replace or delete a different one."""
    if index < 0 or index >= len(arr):
        raise HTTPException(status_code=404, detail=f"{what} index out of range")
    if not expected:
        raise HTTPException(status_code=428, detail=f"Missing the {what}'s content tag; reload and try again.")
    if _etag(arr[index]) != expected:
        raise HTTPException(status_code=409, detail=f"This {what} changed since the page loaded; reload and try again.")


def _clip(value, limit: int = 8192) -> str:
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    return text if len(text) <= limit else text[:limit] + "…"


# ---- rules: rules_request (native Karna JSON) + custom_secrules (SecLang) ----
_RULE_FIELD = {"native": "rules_request", "seclang": "custom_secrules"}


def _serialize_rule(kind, rule):
    if kind == "native":
        if not isinstance(rule, dict):
            raise HTTPException(status_code=422, detail="Native rule must be a JSON object.")
        if not rule.get("id"):
            raise HTTPException(status_code=422, detail="Rule needs an id.")
        if not isinstance(rule.get("conditions"), list) or not rule["conditions"]:
            raise HTTPException(status_code=422, detail="Rule needs at least one condition.")
        action = rule.get("action")
        controls = rule.get("rule_control")
        if action is not None and not isinstance(action, dict):
            raise HTTPException(status_code=422, detail="Rule action must be a JSON object.")
        if controls is not None and not isinstance(controls, list):
            raise HTTPException(status_code=422, detail="Rule controls must be a JSON array.")
        if isinstance(controls, list) and any(not isinstance(control, dict) for control in controls):
            raise HTTPException(status_code=422, detail="Every rule control must be a JSON object.")
        if not action and not controls:
            raise HTTPException(status_code=422, detail="Rule needs an action or at least one rule control.")
        return json.dumps(rule, separators=(",", ":"))
    s = (rule if isinstance(rule, str) else "").strip()
    if not s:
        raise HTTPException(status_code=422, detail="SecLang rule is empty.")
    if not s.startswith("Sec"):
        raise HTTPException(status_code=422, detail="SecLang rule must start with a Sec* directive (e.g. SecRule).")
    return s


async def _patch_cfg(client, plugin_id, cfg):
    r = await client.patch(f"{_kong_admin_url()}/plugins/{plugin_id}", json={"config": cfg})
    if r.status_code not in (200, 201):
        raise HTTPException(status_code=502, detail=f"Admin API rejected the change: {r.text[:200]}")


def _rule_label(kind, entry):
    if kind == "native":
        try:
            return str(json.loads(entry).get("id", "?"))
        except ValueError:
            return "?"
    return entry.split('"', 2)[0][:60]


@app.post("/api/plugins/{plugin_id}/rules")
async def add_rule(plugin_id: str, payload: dict = Body(...), sub: str = Depends(require_auth)):
    kind = payload.get("kind")
    if kind not in _RULE_FIELD:
        raise HTTPException(status_code=422, detail="kind must be 'native' or 'seclang'")
    entry = _serialize_rule(kind, payload.get("rule"))
    field = _RULE_FIELD[kind]
    async with egress.client(timeout=6.0, headers=_kong_headers()) as client:
        plugin = await _kong_get_plugin(client, plugin_id)
        cfg = plugin.get("config", {})
        arr = list(cfg.get(field) or [])
        arr.append(entry)
        cfg[field] = arr
        await _patch_cfg(client, plugin_id, cfg)
        svc_name = await _kong_service_name(client, (plugin.get("service") or {}).get("id"))
    auth.append_change({"actor": sub, "action": "rule_add", "service": svc_name, "plugin_id": plugin_id,
                        "detail": {"kind": kind, "id": _rule_label(kind, entry)}})
    _invalidate_cache()
    _invalidate_kong_inventory()
    return {"ok": True, "count": len(arr)}


@app.patch("/api/plugins/{plugin_id}/rules/{kind}/{index}")
async def edit_rule(plugin_id: str, kind: str, index: int, payload: dict = Body(...),
                    expected: str | None = None, sub: str = Depends(require_auth)):
    if kind not in _RULE_FIELD:
        raise HTTPException(status_code=422, detail="kind must be 'native' or 'seclang'")
    entry = _serialize_rule(kind, payload.get("rule"))
    field = _RULE_FIELD[kind]
    async with egress.client(timeout=6.0, headers=_kong_headers()) as client:
        plugin = await _kong_get_plugin(client, plugin_id)
        cfg = plugin.get("config", {})
        arr = list(cfg.get(field) or [])
        _check_entry(arr, index, expected, "rule")
        before = arr[index]
        arr[index] = entry
        cfg[field] = arr
        await _patch_cfg(client, plugin_id, cfg)
        svc_name = await _kong_service_name(client, (plugin.get("service") or {}).get("id"))
    auth.append_change({"actor": sub, "action": "rule_update", "service": svc_name, "plugin_id": plugin_id,
                        "detail": {"kind": kind, "index": index, "id": _rule_label(kind, entry)},
                        "before": _clip(before), "after": _clip(entry)})
    _invalidate_cache()
    _invalidate_kong_inventory()
    return {"ok": True}


@app.delete("/api/plugins/{plugin_id}/rules/{kind}/{index}")
async def delete_rule(plugin_id: str, kind: str, index: int, expected: str | None = None,
                      sub: str = Depends(require_auth)):
    if kind not in _RULE_FIELD:
        raise HTTPException(status_code=422, detail="kind must be 'native' or 'seclang'")
    field = _RULE_FIELD[kind]
    async with egress.client(timeout=6.0, headers=_kong_headers()) as client:
        plugin = await _kong_get_plugin(client, plugin_id)
        cfg = plugin.get("config", {})
        arr = list(cfg.get(field) or [])
        _check_entry(arr, index, expected, "rule")
        removed = arr.pop(index)
        cfg[field] = arr
        await _patch_cfg(client, plugin_id, cfg)
        svc_name = await _kong_service_name(client, (plugin.get("service") or {}).get("id"))
    auth.append_change({"actor": sub, "action": "rule_remove", "service": svc_name, "plugin_id": plugin_id,
                        "detail": {"kind": kind, "index": index, "id": _rule_label(kind, removed)},
                        "before": _clip(removed), "after": None})
    _invalidate_cache()
    _invalidate_kong_inventory()
    return {"ok": True}
