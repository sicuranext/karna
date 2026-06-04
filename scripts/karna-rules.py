#!/usr/bin/env python3
"""
karna-rules, push local rules or action/response overrides onto a Karna plugin.

Reads a JSON file (a top-level ARRAY) and writes it to one of the karna
plugin's array config fields on a chosen Kong service, via the Admin API.
Three things you can push (--type):

  rules               -> config.rules_request          (your own detection rules)
  action-overrides    -> config.rule_action_overrides  (switch EXISTING rules to
                         fix / passthrough / block, by tag / id / id-range)
  response-overrides  -> config.rule_response_overrides (custom block response)

Works two ways:
  Interactive   ./karna-rules.py            (asks for type, service, file)
  Direct        ./karna-rules.py --type action-overrides --service api --file ov.json

Options:
  --admin URL    Kong Admin API base (default: $KARNA_ADMIN_URL or
                 http://localhost:28001)
  --type T       rules | action-overrides | response-overrides
                 (default: rules; asked interactively if neither --type nor
                 --file is given)
  --service S    service name or id (skips the interactive picker)
  --file F       the JSON array file to push
  --append       add to what is already there instead of replacing it
  --no-enable    for --type rules only: do not force local_rules_enabled=true
  --dry-run      show what would happen, change nothing
  --yes, -y      skip the confirmation prompt
  --no-color     plain output

Each array element becomes one JSON string in the target config field. Examples:

  rules:              { "id": "vp_1", "phase": "access",
                        "conditions": [ ... ], "action": { ... } }
  action-overrides:   { "selector": { "tags": ["attack-xss"] },
                        "action": { "type": "fix", "remove_chars_pattern": "[<>'&;]" } }
  response-overrides: { "selector": { "id_ranges": ["942000-942999"] },
                        "response": { "status_code": 429, "body": "slow down" } }
"""

import argparse
import json
import os
import sys
import urllib.error
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
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Push Karna local rules or action/response overrides onto a Kong service.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--admin", default=os.environ.get("KARNA_ADMIN_URL", "http://localhost:28001"))
    ap.add_argument("--type", choices=list(TYPES.keys()),
                    help="what to push (default: rules, or asked interactively)")
    ap.add_argument("--service")
    ap.add_argument("--file")
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--no-enable", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("-y", "--yes", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    global _COLOR
    if args.no_color:
        _COLOR = False

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
