#!/usr/bin/env python3
"""
karna-rules, push local rules or action/response overrides onto a Karna plugin.

Reads a JSON file (a top-level array) and writes it to one of the karna
plugin's array config fields on a chosen Kong service, via the Admin API.
The Admin API address is required: pass --admin URL or set KARNA_ADMIN_URL.

Run ./karna-rules.py --help for the options, examples and file format.
"""

import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

# ─────────────────────────────────────────────────────────────────────────────
# Look & feel, Karna brand palette via truecolor ANSI, with graceful no-color.
# ─────────────────────────────────────────────────────────────────────────────
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

GOLD     = (217, 164, 65)
OLIVE    = (112, 148, 42)
INCHWORM = (186, 233, 92)
RED      = (196, 69, 43)
DIM      = (140, 138, 134)
INK      = (230, 226, 222)


def _sgr(rgb=None, bold=False):
    if not _COLOR:
        return ""
    parts = []
    if bold:
        parts.append("1")
    if rgb:
        parts.append("38;2;%d;%d;%d" % rgb)
    return "\033[" + ";".join(parts) + "m" if parts else ""


def c(text, rgb=None, bold=False):
    if not _COLOR:
        return str(text)
    return "%s%s\033[0m" % (_sgr(rgb, bold), text)


def panel(lines, color=GOLD, pad=1):
    """A rounded box around `lines`, drawn in `color`."""
    body = []
    for ln in lines:
        body.extend(ln.split("\n"))
    width = max((_vlen(ln) for ln in body), default=0) + pad * 2
    top = c("╭" + "─" * width + "╮", color)
    bot = c("╰" + "─" * width + "╯", color)
    bar = c("│", color)
    out = [top]
    for ln in body:
        gap = " " * (width - _vlen(ln) - pad)
        out.append("%s%s%s%s%s" % (bar, " " * pad, ln, gap, bar))
    out.append(bot)
    return "\n".join(out)


def _vlen(s):
    """Visible length: strip ANSI escapes so box math stays aligned."""
    out, i = 0, 0
    while i < len(s):
        if s[i] == "\033":
            j = s.find("m", i)
            i = (j + 1) if j != -1 else i + 1
            continue
        out += 1
        i += 1
    return out


def table(headers, rows, color=GOLD):
    cols = len(headers)
    widths = [_vlen(str(h)) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], _vlen(str(r[i])))

    def line(left, mid, right):
        return c(left + mid.join("─" * (w + 2) for w in widths) + right, color)

    def row(cells, head=False):
        bar = c("│", color)
        out = bar
        for i, cell in enumerate(cells):
            s = str(cell)
            pad = widths[i] - _vlen(s)
            txt = c(s, INK, bold=True) if head else s
            out += " " + txt + " " * (pad + 1) + bar
        return out

    res = [line("┌", "┬", "┐"), row(headers, head=True), line("├", "┼", "┤")]
    for r in rows:
        res.append(row(r))
    res.append(line("└", "┴", "┘"))
    return "\n".join(res)


def banner():
    title = "%s  %s   %s" % (
        c("क", GOLD, bold=True),
        c("Karna", INK, bold=True),
        c("rules & overrides", DIM),
    )
    print()
    print(panel([title], color=GOLD))
    print()


def step(ok, msg):
    mark = c("✓", OLIVE, bold=True) if ok else c("✗", RED, bold=True)
    print("  %s %s" % (mark, msg))


def arrow(msg):
    print("  %s %s" % (c("→", GOLD, bold=True), msg))


def info(msg):
    print("  %s %s" % (c("·", DIM), c(msg, DIM)))


def die(msg, code=1):
    print()
    print(panel([c("✗ ", RED, bold=True) + msg], color=RED))
    sys.exit(code)


def ask(prompt):
    try:
        return input("  %s %s " % (c("?", GOLD, bold=True), prompt)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        die("cancelled.")


def confirm(prompt, default=False):
    suffix = "[y/N]" if not default else "[Y/n]"
    ans = ask("%s %s" % (prompt, c(suffix, DIM))).lower()
    if ans == "":
        return default
    return ans in ("y", "yes", "s", "si")


# ─────────────────────────────────────────────────────────────────────────────
# Kong Admin API client (stdlib only)
# ─────────────────────────────────────────────────────────────────────────────
class Admin:
    def __init__(self, base):
        self.base = base.rstrip("/")

    def _req(self, method, path, body=None):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:500]
            raise RuntimeError("%s %s -> HTTP %s\n%s" % (method, path, e.code, detail))
        except urllib.error.URLError as e:
            raise RuntimeError("cannot reach Admin API at %s (%s)" % (url, e.reason))

    def get(self, path):
        return self._req("GET", path)

    def patch(self, path, body):
        return self._req("PATCH", path, body)

    def post(self, path, body):
        return self._req("POST", path, body)

    def list_services(self):
        out, path = [], "/services?size=1000"
        while path:
            page = self.get(path)
            out.extend(page.get("data", []))
            nxt = page.get("next")
            path = nxt if nxt else None
        return out

    def karna_plugin(self, service_id):
        page = self.get("/services/%s/plugins" % service_id)
        for p in page.get("data", []):
            if p.get("name") == "karna":
                return p
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Minimal Redis client (RESP2, stdlib only — no redis-py dependency, in the
# same spirit as using urllib instead of requests). Enough surface for the
# global-rules pack: PING / AUTH / SELECT / HGETALL / HSET / HDEL / MULTI /
# EXEC. TLS via rediss:// (no cert verification — transport privacy only; the
# pack's integrity comes from the HMAC signature, not the channel).
# ─────────────────────────────────────────────────────────────────────────────
class RedisClient:
    def __init__(self, url):
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("redis", "rediss"):
            raise RuntimeError("unsupported Redis URL scheme '%s' "
                               "(want redis:// or rediss://)" % p.scheme)
        if not p.hostname:
            raise RuntimeError("Redis URL has no host")
        self.host = p.hostname
        self.port = p.port or 6379
        self.user = p.username or None
        self.password = p.password or None
        self.use_ssl = p.scheme == "rediss"
        self.db = 0
        path = (p.path or "").strip("/")
        if path:
            if not path.isdigit():
                raise RuntimeError("Redis URL path must be a database number, got '%s'" % path)
            self.db = int(path)
        self.sock = None
        self.buf = b""

    def connect(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=10)
        except OSError as e:
            raise RuntimeError("cannot reach Redis at %s:%d (%s)" % (self.host, self.port, e))
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        self.sock = s
        if self.password:
            if self.user:
                self.cmd("AUTH", self.user, self.password)
            else:
                self.cmd("AUTH", self.password)
        if self.db:
            self.cmd("SELECT", str(self.db))
        self.cmd("PING")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def cmd(self, *args):
        parts = [b"*%d\r\n" % len(args)]
        for a in args:
            b = a if isinstance(a, bytes) else str(a).encode("utf-8")
            parts.append(b"$%d\r\n%s\r\n" % (len(b), b))
        self.sock.sendall(b"".join(parts))
        return self._reply()

    def _line(self):
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("Redis closed the connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _exactly(self, n):
        while len(self.buf) < n + 2:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("Redis closed the connection")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n + 2:]
        return data

    def _reply(self):
        line = self._line()
        t, rest = line[:1], line[1:]
        if t == b"+":
            return rest.decode()
        if t == b"-":
            raise RuntimeError("Redis error: %s" % rest.decode())
        if t == b":":
            return int(rest)
        if t == b"$":
            n = int(rest)
            return None if n == -1 else self._exactly(n)
        if t == b"*":
            n = int(rest)
            return None if n == -1 else [self._reply() for _ in range(n)]
        raise RuntimeError("unexpected Redis reply: %r" % line[:40])

    def hgetall(self, key):
        arr = self.cmd("HGETALL", key) or []
        return {arr[i].decode(): arr[i + 1] for i in range(0, len(arr), 2)}


# ─────────────────────────────────────────────────────────────────────────────
# Global rules pack — Redis layout + signature. MUST stay in lockstep with
# kong/plugins/karna/modules/ka_global_rules.lua (`signing_message`).
# ─────────────────────────────────────────────────────────────────────────────
GLOBAL_KEY = "karna:global_rules"
HMAC_ENV = "KARNA_GLOBAL_RULES_HMAC_KEY"


def _as_bytes(v):
    if v is None:
        return b""
    return v if isinstance(v, bytes) else str(v).encode("utf-8")


def _sign_message(version, json_blob, seclang_blob):
    jh = hashlib.sha256(_as_bytes(json_blob)).hexdigest()
    sh = hashlib.sha256(_as_bytes(seclang_blob)).hexdigest()
    return ("%s\n%s\n%s" % (version, jh, sh)).encode("ascii")


def _sign(key, version, json_blob, seclang_blob):
    msg = _sign_message(version, json_blob, seclang_blob)
    return hmac_mod.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _seclang_ids(text):
    ids = []
    for line in text.splitlines():
        line = line.strip()
        i = line.find("id:")
        if line.startswith("SecRule") and i != -1:
            rid = ""
            for ch in line[i + 3:]:
                if ch.isalnum() or ch == "_":
                    rid += ch
                else:
                    break
            if rid:
                ids.append(rid)
    return ids


def _pack_summary(fields, key):
    """Rows describing the published pack, plus signature status."""
    version = (fields.get("version") or b"").decode("utf-8", "replace")
    json_blob = fields.get("json") or b""
    seclang_blob = fields.get("seclang") or b""
    sig = (fields.get("sig") or b"").decode("ascii", "replace")

    n_json = "?"
    if json_blob:
        try:
            n_json = len(json.loads(json_blob.decode("utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError):
            n_json = c("unparseable!", RED)
    else:
        n_json = 0
    n_sec = len(_seclang_ids(seclang_blob.decode("utf-8", "replace"))) if seclang_blob else 0

    if not sig:
        sig_status = c("absent (unsigned)", RED)
    elif not key:
        sig_status = c("present — set %s to verify" % HMAC_ENV, DIM)
    elif hmac_mod.compare_digest(_sign(key, version, json_blob, seclang_blob), sig.lower()):
        sig_status = c("valid", OLIVE)
    else:
        sig_status = c("INVALID", RED, bold=True)

    return version, n_json, n_sec, sig_status


# ─────────────────────────────────────────────────────────────────────────────
# What we can push. All three are `array of string` config fields on the karna
# plugin: each list element is one JSON-encoded object.
# ─────────────────────────────────────────────────────────────────────────────
TYPES = {
    "rules": {
        "label": "local rules", "noun": "rule",
        "config_key": "rules_request", "enable_key": "local_rules_enabled",
        "hint": "a JSON array of rule objects",
    },
    "action-overrides": {
        "label": "action overrides", "noun": "override",
        "config_key": "rule_action_overrides", "enable_key": None,
        "hint": "a JSON array of {selector, action} objects",
    },
    "response-overrides": {
        "label": "response overrides", "noun": "override",
        "config_key": "rule_response_overrides", "enable_key": None,
        "hint": "a JSON array of {selector, response} objects",
    },
}


def read_entries(path):
    if not os.path.isfile(path):
        die("file not found: %s" % path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        die("invalid JSON in %s: %s" % (path, e))
    if not isinstance(data, list):
        die("file must be a JSON array (got %s)" % type(data).__name__)
    for i, e in enumerate(data):
        if not isinstance(e, dict):
            die("entry #%d is not an object" % (i + 1))
    return data


def validate(entries, typ):
    """Soft validation: return human-readable warnings (does not abort)."""
    issues = []
    for i, e in enumerate(entries):
        n = i + 1
        if typ == "rules":
            if not e.get("id"):
                issues.append("entry %d has no id" % n)
            if not e.get("phase"):
                issues.append("entry %d has no phase" % n)
        elif typ == "action-overrides":
            if not isinstance(e.get("selector"), dict):
                issues.append("entry %d is missing a selector" % n)
            act = e.get("action")
            if not isinstance(act, dict) or act.get("type") not in ("fix", "passthrough", "block"):
                issues.append("entry %d: action.type must be fix, passthrough or block" % n)
        elif typ == "response-overrides":
            if not isinstance(e.get("selector"), dict):
                issues.append("entry %d is missing a selector" % n)
            if not isinstance(e.get("response"), dict):
                issues.append("entry %d is missing a response" % n)
    return issues


def _clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "+"


def rule_action(rule):
    act = rule.get("action")
    if isinstance(act, dict) and act:
        return ", ".join(act.keys())
    if rule.get("rule_control"):
        return "rule_control"
    return c("(none)", DIM)


def selector_summary(sel):
    if not isinstance(sel, dict):
        return c("(invalid)", RED)
    parts = []
    if sel.get("any") is True:
        parts.append("any")
    if sel.get("ids"):
        parts.append("ids=" + _clip(",".join(map(str, sel["ids"])), 26))
    if sel.get("id_ranges"):
        parts.append("ranges=" + _clip(",".join(map(str, sel["id_ranges"])), 26))
    if sel.get("tags"):
        parts.append("tags=" + _clip(",".join(map(str, sel["tags"])), 26))
    if sel.get("except_ids"):
        parts.append("!ids=" + _clip(",".join(map(str, sel["except_ids"])), 16))
    if sel.get("except_tags"):
        parts.append("!tags=" + _clip(",".join(map(str, sel["except_tags"])), 16))
    return ", ".join(parts) if parts else c("(empty)", RED)


def preview(entries, typ):
    if typ == "rules":
        rows = []
        for i, r in enumerate(entries):
            rows.append([i + 1,
                         r.get("id", c("(no id)", RED)),
                         r.get("phase", c("(no phase)", RED)),
                         len(r.get("conditions") or []),
                         rule_action(r)])
        return table(["#", "ID", "PHASE", "COND", "ACTION"], rows)
    if typ == "action-overrides":
        rows = []
        for i, e in enumerate(entries):
            act = e.get("action") or {}
            t = act.get("type") or c("(no type)", RED)
            detail = act.get("remove_chars_pattern", "default") if t == "fix" else ""
            rows.append([i + 1, selector_summary(e.get("selector")), t, detail])
        return table(["#", "SELECTOR", "TYPE", "FIX PATTERN"], rows)
    rows = []
    for i, e in enumerate(entries):
        resp = e.get("response") or {}
        rows.append([i + 1,
                     selector_summary(e.get("selector")),
                     resp.get("status_code", ""),
                     _clip(resp.get("body") or "", 22),
                     _clip(",".join((resp.get("headers") or {}).keys()), 22)])
    return table(["#", "SELECTOR", "STATUS", "BODY", "HEADERS"], rows)


def prompt_type():
    items = [(k, TYPES[k]["label"], TYPES[k]["config_key"])
             for k in ("rules", "action-overrides", "response-overrides")]
    rows = [[i + 1, k, lbl, key] for i, (k, lbl, key) in enumerate(items)]
    print(table(["#", "TYPE", "WHAT", "CONFIG FIELD"], rows))
    print()
    while True:
        sel = ask("what do you want to push %s:" % c("[1-3]", DIM))
        if sel.isdigit() and 1 <= int(sel) <= 3:
            return items[int(sel) - 1][0]
        info("enter 1, 2 or 3")


def service_label(svc):
    name = svc.get("name") or c("(unnamed)", DIM)
    host = svc.get("host", "")
    port = svc.get("port", "")
    proto = svc.get("protocol", "")
    target = "%s://%s:%s" % (proto, host, port) if host else ""
    return name, svc.get("id", "")[:8], target


def pick_service(admin, wanted):
    services = admin.list_services()
    if not services:
        die("no services found on this Kong. Create one first.")

    if wanted:
        for s in services:
            if s.get("name") == wanted or s.get("id") == wanted or s.get("id", "").startswith(wanted):
                return s
        die("service '%s' not found. Available: %s"
            % (wanted, ", ".join(s.get("name") or s.get("id")[:8] for s in services)))

    rows = []
    for i, s in enumerate(services):
        name, sid, target = service_label(s)
        rows.append([i + 1, name, sid, target])
    print(table(["#", "SERVICE", "ID", "UPSTREAM"], rows))
    print()
    while True:
        sel = ask("select a service %s:" % c("[1-%d]" % len(services), DIM))
        if sel.isdigit() and 1 <= int(sel) <= len(services):
            return services[int(sel) - 1]
        info("enter a number between 1 and %d" % len(services))


# ─────────────────────────────────────────────────────────────────────────────
# Global rules: publish / show / pull against Redis (no Admin API involved).
# ─────────────────────────────────────────────────────────────────────────────
def cmd_global_rules(args):
    banner()

    url = args.redis or os.environ.get("KARNA_REDIS_URL")
    if not url:
        die("no Redis address. Pass --redis URL "
            "(e.g. --redis redis://localhost:26379/0) or set KARNA_REDIS_URL.")
    key = os.environ.get(HMAC_ENV) or None

    try:
        red = RedisClient(url)
        red.connect()
    except RuntimeError as e:
        die(str(e))
    step(True, "connected to Redis at %s" % c("%s:%d/%d" % (red.host, red.port, red.db), DIM))

    current = red.hgetall(GLOBAL_KEY)

    # ── show: inspect what is currently published ───────────────────────────
    if args.show:
        if not current:
            info("no global rules pack published (key %s is absent)" % GLOBAL_KEY)
            red.close()
            return
        version, n_json, n_sec, sig_status = _pack_summary(current, key)
        print()
        print(table(["FIELD", "VALUE"], [
            ["version", version],
            ["json rules", n_json],
            ["seclang rules", n_sec],
            ["json sha256", hashlib.sha256(current.get("json") or b"").hexdigest()[:16] + "…"],
            ["seclang sha256", hashlib.sha256(current.get("seclang") or b"").hexdigest()[:16] + "…"],
            ["signature", sig_status],
        ]))
        jb = current.get("json") or b""
        if jb:
            try:
                print()
                print(preview(json.loads(jb.decode("utf-8")), "rules"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        red.close()
        return

    # ── pull: reconstruct local authoring files from the published pack ─────
    if args.pull:
        if not current:
            die("nothing to pull: no global rules pack published.")
        targets = [("json", args.json or "global_rules.json"),
                   ("seclang", args.seclang or "global_rules.conf")]
        for field, path in targets:
            blob = current.get(field) or b""
            if not blob:
                info("field '%s' is empty — skipping %s" % (field, path))
                continue
            if os.path.exists(path) and not args.yes:
                if not confirm("overwrite %s?" % c(path, INK, bold=True)):
                    info("skipped %s" % path)
                    continue
            with open(path, "wb") as f:
                f.write(blob)
            step(True, "wrote %s (%d bytes)" % (c(path, INK, bold=True), len(blob)))
        red.close()
        return

    # ── publish ──────────────────────────────────────────────────────────────
    if not args.json and not args.seclang:
        die("nothing to publish. Pass --json FILE and/or --seclang FILE "
            "(or --show / --pull to inspect).")

    if not key and not args.unsigned:
        die("refusing to publish UNSIGNED global rules: set %s\n"
            "(generate one with: openssl rand -hex 32 — the same key goes on\n"
            "the Kong nodes) or pass --unsigned explicitly." % HMAC_ENV)

    # New payloads from files; an omitted format is PRESERVED from the pack
    # already in Redis so publishing one file never wipes the other.
    json_blob = current.get("json") or b""
    seclang_blob = current.get("seclang") or b""

    if args.json:
        entries = read_entries(args.json)  # dies on unreadable / non-array
        for issue in validate(entries, "rules"):
            print("  %s %s" % (c("!", RED, bold=True), c(issue, RED)))
        with open(args.json, "rb") as f:
            json_blob = f.read()
        step(True, "loaded %s rule(s) from %s" % (c(len(entries), INK, bold=True), c(args.json, DIM)))
        print()
        print(preview(entries, "rules"))
        print()
    elif current.get("json"):
        info("keeping the already-published json rules (no --json given)")

    if args.seclang:
        if not os.path.isfile(args.seclang):
            die("file not found: %s" % args.seclang)
        with open(args.seclang, "rb") as f:
            seclang_blob = f.read()
        ids = _seclang_ids(seclang_blob.decode("utf-8", "replace"))
        if seclang_blob.strip() and not ids:
            print("  %s %s" % (c("!", RED, bold=True),
                               c("no `SecRule ... id:NNN` found — the engine will load nothing from it", RED)))
        step(True, "loaded %s SecLang rule(s) from %s"
             % (c(len(ids), INK, bold=True), c(args.seclang, DIM)))
        if ids:
            info("seclang ids: %s" % _clip(",".join(ids), 60))
    elif current.get("seclang"):
        info("keeping the already-published seclang rules (no --seclang given)")

    old_version = (current.get("version") or b"0").decode("utf-8", "replace")
    try:
        version = str(int(old_version) + 1)
    except ValueError:
        version = "1"
    _, old_json_n, old_sec_n, _ = _pack_summary(current, key) if current else ("0", 0, 0, "")
    arrow("version %s -> %s%s" % (old_version if current else c("(none)", DIM),
                                  c(version, GOLD, bold=True),
                                  "" if key else c("  UNSIGNED", RED, bold=True)))

    if args.dry_run:
        print()
        print(panel([c("dry run", GOLD, bold=True) + ", nothing was published"], color=GOLD))
        red.close()
        return

    print()
    if not args.yes and not confirm("publish global rules pack version %s?" % c(version, INK, bold=True)):
        die("aborted.", code=0)

    try:
        if key:
            sig = _sign(key, version, json_blob, seclang_blob)
            # single HSET = atomic swap of the whole pack
            red.cmd("HSET", GLOBAL_KEY,
                    "json", json_blob, "seclang", seclang_blob,
                    "version", version, "sig", sig)
        else:
            # unsigned: also drop any stale signature so engines in unsigned
            # mode don't carry a field that would fail verification later
            red.cmd("MULTI")
            red.cmd("HSET", GLOBAL_KEY,
                    "json", json_blob, "seclang", seclang_blob, "version", version)
            red.cmd("HDEL", GLOBAL_KEY, "sig")
            red.cmd("EXEC")
    except RuntimeError as e:
        die(str(e))
    red.close()

    print()
    print(panel([
        c("✓ published", OLIVE, bold=True),
        "global rules pack version %s on %s" % (c(version, INK, bold=True), c(GLOBAL_KEY, DIM)),
        c("every Karna worker applies it within its poll interval", DIM),
        c("(KARNA_GLOBAL_RULES_POLL, default 30s) — no Kong reload needed", DIM),
    ], color=OLIVE))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        prog="karna-rules",
        description="""\
Push Karna local rules or action/response overrides onto a Kong service.

Reads a JSON file (a top-level array) and writes it to one of the karna
plugin's array config fields on the chosen service, via the Kong Admin
API. Anything you leave out (--type, --service, --file) is asked
interactively.

What --type pushes where:
  rules               your own detection rules   -> config.rules_request
  action-overrides    change how existing rules  -> config.rule_action_overrides
                      react: fix / passthrough / block, selected
                      by rule id, id range or tag
  response-overrides  custom block response      -> config.rule_response_overrides
  global-rules        one rule pack for EVERY    -> Redis hash karna:global_rules
                      service, published to Redis (--redis, not --admin) and
                      HMAC-signed with $KARNA_GLOBAL_RULES_HMAC_KEY
""",
        epilog="""\
examples:
  # interactive: menus for type, service and file
  ./karna-rules.py --admin http://localhost:8001

  # push the rules in rules.json onto service "api"
  ./karna-rules.py --admin http://localhost:8001 \\
      --type rules --service api --file rules.json

  # preview an override push without changing anything
  ./karna-rules.py --admin http://localhost:8001 \\
      --type action-overrides --service api --file ov.json --dry-run

  # publish signed global rules (applied to ALL services, hot, no reload)
  KARNA_GLOBAL_RULES_HMAC_KEY=... ./karna-rules.py --type global-rules \\
      --redis redis://localhost:26379/0 \\
      --json global_rules.json --seclang global_rules.conf

  # inspect / recover the published global pack
  ./karna-rules.py --type global-rules --redis redis://localhost:26379/0 --show
  ./karna-rules.py --type global-rules --redis redis://localhost:26379/0 --pull

file format: a JSON array; each element becomes one JSON-encoded string
in the target config field. One element, per --type:
  rules:              { "id": "vp_1", "phase": "access",
                        "conditions": [ ... ], "action": { ... } }
  action-overrides:   { "selector": { "tags": ["attack-xss"] },
                        "action": { "type": "fix", "remove_chars_pattern": "[<>'&;]" } }
  response-overrides: { "selector": { "id_ranges": ["942000-942999"] },
                        "response": { "status_code": 429, "body": "slow down" } }
  global-rules:       --json takes the same array as `rules`; --seclang takes
                      a raw SecLang .conf. An omitted file keeps the published
                      payload for that format (publishing one never wipes the
                      other).
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--admin", metavar="URL",
                    default=os.environ.get("KARNA_ADMIN_URL"),
                    help="Kong Admin API base URL, e.g. http://localhost:8001. "
                         "Required unless the KARNA_ADMIN_URL env var is set "
                         "(not used by --type global-rules).")
    ap.add_argument("--type", choices=list(TYPES.keys()) + ["global-rules"], metavar="TYPE",
                    help="what to push: rules | action-overrides | response-overrides "
                         "| global-rules. With --file it defaults to rules, otherwise "
                         "it is asked interactively.")
    ap.add_argument("--redis", metavar="URL",
                    help="[global-rules] Redis address, e.g. redis://localhost:26379/0 "
                         "(rediss:// for TLS). Defaults to the KARNA_REDIS_URL env var.")
    ap.add_argument("--json", metavar="PATH",
                    help="[global-rules] JSON rule array to publish (Karna rule format, "
                         "same as --type rules files)")
    ap.add_argument("--seclang", metavar="PATH",
                    help="[global-rules] SecLang .conf to publish")
    ap.add_argument("--show", action="store_true",
                    help="[global-rules] display the published pack (version, rule "
                         "counts, signature status) and exit")
    ap.add_argument("--pull", action="store_true",
                    help="[global-rules] write the published payloads back to local "
                         "files (recover your authoring files from Redis)")
    ap.add_argument("--unsigned", action="store_true",
                    help="[global-rules] allow publishing without an HMAC signature "
                         "when %s is not set (NOT recommended)" % HMAC_ENV)
    ap.add_argument("--service", metavar="NAME_OR_ID",
                    help="target service, by name or id (id prefix works too); "
                         "omitted: interactive picker")
    ap.add_argument("--file", metavar="PATH",
                    help="the JSON array file to push; omitted: asked interactively")
    ap.add_argument("--append", action="store_true",
                    help="add to the entries already on the plugin instead of "
                         "replacing them")
    ap.add_argument("--no-enable", action="store_true",
                    help="with --type rules: do not set local_rules_enabled=true")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would happen, change nothing")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="skip the confirmation prompt")
    ap.add_argument("--no-color", action="store_true",
                    help="plain output, no ANSI colors")
    args = ap.parse_args()

    global _COLOR
    if args.no_color:
        _COLOR = False

    # global-rules targets Redis, not the Admin API — branch off early.
    if args.type == "global-rules":
        return cmd_global_rules(args)
    for flag, name in ((args.redis, "--redis"), (args.json, "--json"),
                       (args.seclang, "--seclang"), (args.show, "--show"),
                       (args.pull, "--pull"), (args.unsigned, "--unsigned")):
        if flag:
            ap.error("%s only makes sense with --type global-rules" % name)

    if not args.admin:
        ap.error("no Admin API address. Pass --admin URL "
                 "(e.g. --admin http://localhost:8001) or set KARNA_ADMIN_URL.")

    banner()
    admin = Admin(args.admin)

    # 1) connect
    try:
        ver = admin.get("/").get("version", "?")
        step(True, "connected to Kong %s at %s" % (c(ver, INK, bold=True), c(admin.base, DIM)))
    except RuntimeError as e:
        die(str(e))

    # 2) what to push (explicit --type, else default rules in direct mode, else ask)
    typ = args.type or ("rules" if args.file else prompt_type())
    t = TYPES[typ]
    step(True, "target: %s %s" % (c(t["label"], INK, bold=True), c("(config." + t["config_key"] + ")", DIM)))

    # 3) service
    svc = pick_service(admin, args.service)
    name, sid, target = service_label(svc)
    step(True, "service %s %s" % (c(name, INK, bold=True), c("(" + sid + ")", DIM)))

    # 4) the file
    path = args.file or ask("path to the %s file (%s):" % (t["label"], t["hint"]))
    entries = read_entries(path)
    if not entries:
        die("the file is an empty array, nothing to push.")
    step(True, "loaded %s %s(s) from %s" % (c(len(entries), INK, bold=True), t["noun"], c(path, DIM)))
    for issue in validate(entries, typ):
        print("  %s %s" % (c("!", RED, bold=True), c(issue, RED)))
    print()
    print(preview(entries, typ))
    print()

    # 5) current state on the service
    encoded = [json.dumps(e) for e in entries]
    plugin = admin.karna_plugin(svc["id"])
    if plugin:
        cur = plugin.get("config", {}).get(t["config_key"]) or []
        info("current: %d %s(s) in config.%s" % (len(cur), t["noun"], t["config_key"]))
        final = (cur + encoded) if args.append else encoded
        arrow("will %s -> %s %s(s) total"
              % ("append" if args.append else "replace", c(len(final), GOLD, bold=True), t["noun"]))
    else:
        final = encoded
        arrow("no Karna plugin on this service yet, one will be created")

    enable = bool(t["enable_key"]) and not args.no_enable
    if enable:
        info("%s will be set to true" % t["enable_key"])

    # 6) dry-run / confirm
    if args.dry_run:
        print()
        print(panel([c("dry run", GOLD, bold=True) + ", nothing was changed"], color=GOLD))
        return

    print()
    if not args.yes and not confirm("apply to service %s?" % c(name, INK, bold=True)):
        die("aborted.", code=0)

    # 7) apply
    cfg = {t["config_key"]: final}
    if enable:
        cfg[t["enable_key"]] = True
    try:
        if plugin:
            admin.patch("/plugins/%s" % plugin["id"], {"config": cfg})
            verb = "updated"
        else:
            admin.post("/services/%s/plugins" % svc["id"], {"name": "karna", "config": cfg})
            verb = "created"
    except RuntimeError as e:
        die(str(e))

    print()
    print(panel([
        c("✓ done", OLIVE, bold=True),
        "%s %s(s) on service %s" % (c(len(final), INK, bold=True), t["noun"], c(name, INK, bold=True)),
        c("plugin %s · %s" % (verb, admin.base), DIM),
    ], color=OLIVE))
    print()


if __name__ == "__main__":
    main()
