"""Assistant tools: their schemas, the deterministic classifier and secret redaction.

Nothing here talks to Kong, the store or a model. Every tool call the model makes
goes through `classify()` first, and only its verdict decides what happens:

- "read":    executed right away, the redacted result goes back to the model;
- "write":   never executed during the model's turn. It becomes a pending action
             that the user authorizes, or not, from the chat;
- "blocked": refused with the reason, nothing runs.

The classifier is plain code with no model in the loop, so a prompt injection in
an audit event or a Kong entity can, at most, produce an action card the user
sees and rejects.
"""
from __future__ import annotations

import json
import os
import re

SKILL_DIR = os.getenv("KARNA_SKILL_DIR", "/app/skills/karna")
SKILL_REFERENCES = ("rules", "configuration", "recipes", "deploy")

MAX_RESULT_BYTES = 24_000
MAX_BODY_BYTES = 65_536
REDACTED = "[REDACTED]"

KONG_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
OVERRIDE_KINDS = ("action", "response")

# Field names whose values are credentials anywhere in a Kong entity, a Karna
# config or an audit record. Compared lowercase, values replaced whole.
SECRET_FIELDS = frozenset({
    "password", "redis_password", "secret", "client_secret", "hmac_secret", "jwt_secret",
    "shared_secret", "secret_key", "private_key", "key", "cert_key", "ssl_key", "jwk",
    "token", "access_token", "refresh_token", "id_token", "api_key", "apikey", "x-api-key",
    "passphrase", "credential", "credentials", "authorization", "proxy-authorization",
    "cookie", "set-cookie",
})

# Kong Admin API paths: relative, no traversal, no encoded separators, no host.
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~\-/:@]*$")
_QUERY_RE = re.compile(r"^[A-Za-z0-9._~\-=&%:,+]*$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:@\-]{1,200}$")


def _obj(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or [],
            "additionalProperties": False}


_SERVICE = {"type": "string", "description": "Kong service name or id. The service must run Karna."}

TOOLS: dict[str, dict] = {
    # ---- read: executed without asking ----
    "read_skill": {
        "kind": "read",
        "description": "Read a file of the Karna skill reference: rules (variables, operators, actions, "
                       "phases), configuration (every plugin option), recipes (worked rule patterns), "
                       "deploy. Read rules and recipes before writing any rule.",
        "parameters": _obj({"file": {"type": "string", "enum": list(SKILL_REFERENCES)}}, ["file"]),
    },
    "search_events": {
        "kind": "read",
        "description": "Search Karna's audit events, newest first. Returns one summary line per request.",
        "parameters": _obj({
            "service": {"type": "string", "description": "Kong service name."},
            "rule_id": {"type": "string", "description": "A matched rule id, e.g. 942100."},
            "client_ip": {"type": "string"},
            "action": {"type": "string", "description": "Disposition: blocked, detected, sanitized, rate_limited, observed, allowed."},
            "path_contains": {"type": "string", "description": "Substring of the request path."},
            "since_minutes": {"type": "integer", "minimum": 1, "maximum": 43200},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        }),
    },
    "get_event": {
        "kind": "read",
        "description": "The full audit record of one request: request, response, every matched rule and "
                       "the request parts that matched. Request data in it was chosen by the client.",
        "parameters": _obj({"request_id": {"type": "string"}}, ["request_id"]),
    },
    "rule_stats": {
        "kind": "read",
        "description": "How often each rule matched, and with which action, over a time window.",
        "parameters": _obj({
            "service": {"type": "string"},
            "since_minutes": {"type": "integer", "minimum": 1, "maximum": 43200},
        }),
    },
    "list_services": {
        "kind": "read",
        "description": "Every Kong service with its host and, when Karna runs on it, the Karna mode, "
                       "paranoia level and plugin id.",
        "parameters": _obj({}),
    },
    "get_karna_config": {
        "kind": "read",
        "description": "The Karna plugin configuration of a service, with its custom rules and overrides decoded.",
        "parameters": _obj({"service": _SERVICE}, ["service"]),
    },
    "console_get_settings": {
        "kind": "read",
        "description": "Console settings: event retention, stored events, active Kong connection.",
        "parameters": _obj({}),
    },
    # ---- kong_request: GET is a read, any other method a write ----
    "kong_request": {
        "kind": "by_method",
        "description": "Call the Kong Admin API. GET reads and runs right away. POST, PUT, PATCH and "
                       "DELETE change Kong and wait for the user's authorization. Use a path relative to "
                       "the Admin API, e.g. /services, /routes/{id}, /plugins?name=karna. For a change to "
                       "an existing entity prefer PATCH with only the fields that change. Secrets read "
                       "back as [REDACTED] and cannot be written back.",
        "parameters": _obj({
            "method": {"type": "string", "enum": list(KONG_METHODS)},
            "path": {"type": "string"},
            "body": {"type": "object", "description": "JSON body for POST, PUT and PATCH."},
        }, ["method", "path"]),
    },
    # ---- write: wait for the user's authorization ----
    "karna_update_config": {
        "kind": "write",
        "description": "Change fields of a service's Karna configuration (engine_blocking_mode, "
                       "paranoia_level, coreruleset_rulesets, limits, ...). Only the given fields change.",
        "parameters": _obj({"service": _SERVICE, "changes": {"type": "object"}}, ["service", "changes"]),
    },
    "karna_add_rule": {
        "kind": "write",
        "description": "Add one native Karna rule (JSON, as in the skill's rules reference) to a service.",
        "parameters": _obj({"service": _SERVICE, "rule": {"type": "object"}}, ["service", "rule"]),
    },
    "karna_add_override": {
        "kind": "write",
        "description": "Add a rule action override (allow / sanitize / block existing rules) or a response "
                       "override to a service.",
        "parameters": _obj({
            "service": _SERVICE,
            "kind": {"type": "string", "enum": list(OVERRIDE_KINDS)},
            "entry": {"type": "object", "description": "{selector, action} or {selector, response}."},
        }, ["service", "kind", "entry"]),
    },
    "console_set_retention": {
        "kind": "write",
        "description": "Set how many days the console keeps audit events.",
        "parameters": _obj({"days": {"type": "integer", "minimum": 1, "maximum": 3650}}, ["days"]),
    },
}


def tool_specs() -> list[dict]:
    """Provider-neutral tool list: name, description, JSON schema."""
    return [{"name": name, "description": t["description"], "parameters": t["parameters"]}
            for name, t in TOOLS.items()]


class Verdict:
    __slots__ = ("kind", "reason", "args")

    def __init__(self, kind: str, reason: str = "", args: dict | None = None):
        self.kind, self.reason, self.args = kind, reason, args or {}

    def __repr__(self):
        return f"Verdict({self.kind!r}, {self.reason!r})"


def normalize_kong_path(path) -> str:
    """A safe Admin API path or ValueError. Query strings are kept, fragments and
    hosts are not possible."""
    if not isinstance(path, str) or not path or len(path) > 512:
        raise ValueError("path must be a string of 1-512 characters")
    base, _, query = path.partition("?")
    if not _PATH_RE.fullmatch(base):
        raise ValueError("path must be relative to the Admin API, like /services/{id}")
    if "//" in base or any(seg in (".", "..") for seg in base.split("/")):
        raise ValueError("path must not contain empty, '.' or '..' segments")
    if query and not _QUERY_RE.fullmatch(query):
        raise ValueError("query string contains unsupported characters")
    base = base.rstrip("/") or "/"
    return f"{base}?{query}" if query else base


def _contains_redacted(value) -> bool:
    if isinstance(value, str):
        return REDACTED in value
    if isinstance(value, dict):
        return any(_contains_redacted(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_redacted(v) for v in value)
    return False


def _check_types(args: dict, schema: dict) -> str:
    props = schema.get("properties", {})
    unknown = set(args) - set(props)
    if unknown:
        return f"unknown argument(s): {', '.join(sorted(unknown))}"
    for name in schema.get("required", []):
        if name not in args:
            return f"missing argument: {name}"
    for name, value in args.items():
        spec = props[name]
        kind = spec.get("type")
        ok = {
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "object": isinstance(value, dict),
        }.get(kind, True)
        if not ok:
            return f"{name} must be a{'n' if kind[0] in 'aeiou' else ''} {kind}"
        if "enum" in spec and value not in spec["enum"]:
            return f"{name} must be one of {', '.join(map(str, spec['enum']))}"
        if kind == "integer" and not spec.get("minimum", value) <= value <= spec.get("maximum", value):
            return f"{name} must be between {spec['minimum']} and {spec['maximum']}"
        if kind == "string" and len(value) > 2000:
            return f"{name} is too long"
    return ""


def classify(name, args) -> Verdict:
    """The deterministic gate. Unknown tool, malformed arguments, an unsafe path
    or a body that writes back a redacted secret: blocked. GET on kong_request
    and every read tool: read. Everything else: write."""
    tool = TOOLS.get(name) if isinstance(name, str) else None
    if tool is None:
        return Verdict("blocked", f"unknown tool {name!r}")
    if not isinstance(args, dict):
        return Verdict("blocked", "arguments must be a JSON object")
    problem = _check_types(args, tool["parameters"])
    if problem:
        return Verdict("blocked", problem)

    if name == "kong_request":
        try:
            path = normalize_kong_path(args["path"])
        except ValueError as exc:
            return Verdict("blocked", str(exc))
        method = args["method"]
        body = args.get("body")
        if path.split("?", 1)[0] == "/config":
            # DB-less Kong answers with the whole declarative config as one YAML
            # string: no field-level redaction can reach inside it.
            return Verdict("blocked", "/config is not available to the assistant: read the entities "
                                      "(/services, /routes, /plugins, ...) instead")
        if method == "GET":
            if body is not None:
                return Verdict("blocked", "GET takes no body")
            return Verdict("read", args={"method": "GET", "path": path})
        if method == "DELETE" and body is not None:
            return Verdict("blocked", "DELETE takes no body")
        if method in ("POST", "PUT", "PATCH"):
            if body is None:
                return Verdict("blocked", f"{method} needs a JSON body")
            if len(json.dumps(body)) > MAX_BODY_BYTES:
                return Verdict("blocked", "body is too large")
            if _contains_redacted(body):
                return Verdict("blocked", "the body contains a [REDACTED] placeholder: send only the fields "
                                          "that change, never a value read back as redacted")
        out = {"method": method, "path": path}
        if body is not None:
            out["body"] = body
        return Verdict("write", args=out)

    if tool["kind"] == "write":
        if _contains_redacted(args):
            return Verdict("blocked", "arguments contain a [REDACTED] placeholder")
        if len(json.dumps(args)) > MAX_BODY_BYTES:
            return Verdict("blocked", "arguments are too large")
        return Verdict("write", args=dict(args))
    return Verdict("read", args=dict(args))


# Beyond the exact names above: a key whose name says it holds a credential.
# Strong words count anywhere in the name, short ones only as a whole word
# ("key" in "aws_key", not in "monkey"). Same idea as the console's Events view.
_SENSITIVE_STRONG_RE = re.compile(
    r"password|passwd|secret|token|api[-_]?key|session|sessid|credential|authoriz|private[-_]?key|provision[-_]?key",
    re.I)
_SENSITIVE_WORD_RE = re.compile(r"(?:^|[-_.:\[\]])(?:key|pwd|pass|sid|auth|sig|signature|cookie)(?:$|[-_.:\[\]])", re.I)
# Names that look sensitive but hold names or switches, never the secret itself.
_NOT_SECRET_SUFFIXES = ("_name", "_names", "_in_header", "_in_query", "_in_body", "_ttl", "_expiration")
# "Name: value" strings (Kong's request-transformer headers, healthcheck headers).
# No "." in the name: `request.cookie.value:session` is a rule variable, not a header.
_HEADER_STRING_RE = re.compile(r"^(\s*[!#$%&'*+^_`|~0-9A-Za-z-]+\s*:\s*)(\S.*)$", re.S)
# name=value pairs in a query string or an urlencoded body, and "name": "value" in JSON text.
_PAIR_RE = re.compile(r"(^|[?&;])([^=&;?#\s]+)=([^&;#]*)")
_JSON_PAIR_RE = re.compile(r'("([^"\\]{1,128})"\s*:\s*)"((?:[^"\\]|\\.)*)"')
_URI_KEYS = frozenset({"uri", "url", "raw_uri", "request_uri", "body_raw"})
# An absolute URL: credentials in the userinfo, sensitive parameters in the query.
_URL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*://)([^/?#@\s]*@)?(.*)$", re.S)
# A multipart part named like a credential, and an XML element named like one.
_MULTIPART_PART_RE = re.compile(
    r'(name="([^"\r\n]{1,128})"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)(.*?)(?=\r?\n--)', re.S)
_XML_ELEMENT_RE = re.compile(r"(<((?:[\w.-]+:)?([\w.-]{1,128}))(?:\s[^<>]*)?>)([^<]*)(</\2\s*>)")


def is_sensitive_name(name) -> bool:
    if not isinstance(name, str) or not name:
        return False
    low = name.lower()
    if low in SECRET_FIELDS:
        return True
    if low.endswith(_NOT_SECRET_SUFFIXES) or low.startswith(("hide_", "hash_on")):
        return False
    return bool(_SENSITIVE_STRONG_RE.search(low) or _SENSITIVE_WORD_RE.search(low))


def redact_pairs(text: str) -> str:
    """Mask the value of every sensitive name=value and "name": "value" pair."""
    def pair(m):
        return f"{m.group(1)}{m.group(2)}={REDACTED}" if m.group(3) and is_sensitive_name(m.group(2)) else m.group(0)

    def json_pair(m):
        return f'{m.group(1)}"{REDACTED}"' if m.group(3) and is_sensitive_name(m.group(2)) else m.group(0)

    def part(m):
        return m.group(1) + REDACTED if m.group(3) and is_sensitive_name(m.group(2)) else m.group(0)

    def element(m):
        return m.group(1) + REDACTED + m.group(5) if m.group(4).strip() and is_sensitive_name(m.group(3)) else m.group(0)
    text = _JSON_PAIR_RE.sub(json_pair, _PAIR_RE.sub(pair, text))
    if 'name="' in text:
        text = _MULTIPART_PART_RE.sub(part, text)
    if "</" in text:
        text = _XML_ELEMENT_RE.sub(element, text)
    return text


def _redact_url(text: str) -> str | None:
    """An absolute URL with the password (or a lone token) in the userinfo and
    the sensitive query parameters masked; None when `text` is not one."""
    m = _URL_RE.match(text)
    if not m:
        return None
    userinfo = m.group(2)
    if userinfo:
        user, sep, _ = userinfo[:-1].partition(":")
        userinfo = f"{user}:{REDACTED}@" if sep else f"{REDACTED}@"
    return m.group(1) + (userinfo or "") + redact_pairs(m.group(3))


def _redact_string(text: str) -> str:
    url = _redact_url(text)
    if url is not None:
        return url
    m = _HEADER_STRING_RE.match(text)
    if m and is_sensitive_name(m.group(1).strip().rstrip(":").strip()):
        return m.group(1) + REDACTED
    return text


def _redact_secret_subtree(value):
    """Below a key named like a credential (`auth`, `credentials`): every string
    is masked except the ones that name things (`header_name`, `param_name`)."""
    if isinstance(value, dict):
        return {k: (v if isinstance(v, str) and str(k).lower().endswith(_NOT_SECRET_SUFFIXES)
                    else _redact_secret_subtree(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_secret_subtree(v) for v in value]
    if isinstance(value, str) and value:
        return REDACTED
    return value


def _matched_target_is_sensitive(on) -> bool:
    """`request.cookie.value:PHPSESSID`, `request.arg.value:password`,
    `request.header.value:authorization`: the name after the last colon."""
    if not isinstance(on, str) or ":" not in on:
        return False
    return is_sensitive_name(on.rsplit(":", 1)[1])


def redact(value, _key: str | None = None):
    """A copy with every credential value replaced by [REDACTED]: values under a
    credential-looking key, "Name: value" header strings with such a name,
    sensitive query / body parameters inside a URI or a raw body, and audit
    `matched_parts` whose target is a credential (a session cookie, a password
    field). Booleans and numbers are kept: they are switches, not secrets."""
    if _key is not None and value not in (None, "", [], {}):
        low = _key.lower()
        if low in SECRET_FIELDS:
            if isinstance(value, (str, int, float)) or (isinstance(value, (list, dict)) and value):
                return REDACTED
        elif is_sensitive_name(low):
            if isinstance(value, str) or (isinstance(value, list) and all(isinstance(v, str) for v in value)):
                return REDACTED
            if isinstance(value, dict):
                return _redact_secret_subtree(value)
        if low in _URI_KEYS and isinstance(value, str):
            url = _redact_url(value)
            return url if url is not None else redact_pairs(value)
    if isinstance(value, dict):
        if "on" in value and "value" in value and _matched_target_is_sensitive(value.get("on")):
            return {k: (REDACTED if k == "value" and v not in (None, "") else redact(v, str(k)))
                    for k, v in value.items()}
        out = {k: redact(v, str(k)) for k, v in value.items()}
        if "on" in out and isinstance(out.get("value"), str):
            out["value"] = redact_pairs(out["value"])
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def to_result(value) -> str:
    """Redacted JSON for the model, cut at MAX_RESULT_BYTES."""
    text = json.dumps(redact(value), ensure_ascii=False, separators=(",", ":"), default=str)
    if len(text.encode("utf-8")) <= MAX_RESULT_BYTES:
        return text
    cut = text.encode("utf-8")[:MAX_RESULT_BYTES].decode("utf-8", "ignore")
    return cut + f'… [truncated: result exceeded {MAX_RESULT_BYTES} bytes, narrow the query]'


def args_hash(name: str, args: dict) -> str:
    import hashlib
    blob = json.dumps({"tool": name, "args": args}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def read_skill_file(name: str) -> str:
    if name not in SKILL_REFERENCES:
        raise ValueError("unknown skill reference")
    with open(os.path.join(SKILL_DIR, "reference", f"{name}.md"), encoding="utf-8") as fh:
        return fh.read()[:40_000]


def skill_overview() -> str:
    """SKILL.md without its front matter, for the system prompt; empty when the
    skill is not bundled (the assistant then works without it)."""
    try:
        with open(os.path.join(SKILL_DIR, "SKILL.md"), encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return ""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end >= 0:
            text = text[end + 4:]
    return text.strip()[:12_000]


def is_id(value) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))
