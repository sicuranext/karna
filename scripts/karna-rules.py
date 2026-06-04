#!/usr/bin/env python3
"""
karna-rules, push local rules onto a Karna plugin instance.

Reads a JSON file holding an ARRAY of rule objects and writes them to the
`rules_request` of the Karna plugin attached to a Kong service, through the
Admin API. Works two ways:

  Interactive   ./karna-rules.py
                (pick the service from a list, then point it at a rules file)

  Direct        ./karna-rules.py --service api --file rules.json

Options:
  --admin URL    Kong Admin API base (default: $KARNA_ADMIN_URL or
                 http://localhost:28001)
  --service S    service name or id (skips the interactive picker)
  --file F       JSON file: a top-level array of rule objects
  --append       add to the existing local rules instead of replacing them
  --no-enable    do not force local_rules_enabled=true
  --dry-run      show what would happen, change nothing
  --yes, -y      skip the confirmation prompt
  --no-color     plain output

The rules file is a JSON array; each element becomes one entry in the
plugin's `rules_request` (Karna stores them as JSON strings). Example:

  [
    { "id": "vp_1", "phase": "access",
      "conditions": [ { "op": "isSet", "variables": ["request.arg.value:user"] } ],
      "action": { "fix_matched_parts": { "remove_chars_pattern": "[^a-zA-Z0-9]" } } }
  ]
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
        c("local rules", DIM),
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
# Domain helpers
# ─────────────────────────────────────────────────────────────────────────────
def read_rules(path):
    if not os.path.isfile(path):
        die("rules file not found: %s" % path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        die("invalid JSON in %s: %s" % (path, e))
    if not isinstance(data, list):
        die("rules file must be a JSON array of rule objects (got %s)"
            % type(data).__name__)
    for i, r in enumerate(data):
        if not isinstance(r, dict):
            die("rule #%d is not an object" % (i + 1))
    return data


def rule_action(rule):
    act = rule.get("action")
    if isinstance(act, dict) and act:
        return ", ".join(act.keys())
    if rule.get("rule_control"):
        return "rule_control"
    return c("(none)", DIM)


def rules_table(rules):
    rows = []
    for i, r in enumerate(rules):
        conds = r.get("conditions") or []
        rid = r.get("id", c("(no id)", RED))
        phase = r.get("phase", c("(no phase)", RED))
        rows.append([i + 1, rid, phase, len(conds), rule_action(r)])
    return table(["#", "ID", "PHASE", "COND", "ACTION"], rows)


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
        description="Push Karna local rules onto a Kong service.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--admin", default=os.environ.get("KARNA_ADMIN_URL", "http://localhost:28001"))
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
        status = admin.get("/")
        ver = status.get("version", "?")
        step(True, "connected to Kong %s at %s" % (c(ver, INK, bold=True), c(admin.base, DIM)))
    except RuntimeError as e:
        die(str(e))

    # 2) service
    svc = pick_service(admin, args.service)
    name, sid, target = service_label(svc)
    step(True, "service %s %s" % (c(name, INK, bold=True), c("(" + sid + ")", DIM)))

    # 3) rules file
    path = args.file or ask("path to the rules JSON file:")
    rules = read_rules(path)
    if not rules:
        die("the rules file is an empty array, nothing to push.")
    step(True, "loaded %s rule(s) from %s" % (c(len(rules), INK, bold=True), c(path, DIM)))
    print()
    print(rules_table(rules))
    print()

    # 4) current state on the service
    plugin = admin.karna_plugin(svc["id"])
    if plugin:
        cur = plugin.get("config", {}).get("rules_request") or []
        enabled = plugin.get("config", {}).get("local_rules_enabled")
        info("current Karna plugin: %d local rule(s), local_rules_enabled=%s"
             % (len(cur), enabled))
        final = (cur + [json.dumps(r) for r in rules]) if args.append else [json.dumps(r) for r in rules]
        verb = "append" if args.append else "replace"
        arrow("will %s -> %s local rule(s) total" % (verb, c(len(final), GOLD, bold=True)))
    else:
        cur = []
        final = [json.dumps(r) for r in rules]
        arrow("no Karna plugin on this service yet, one will be created")

    enable = not args.no_enable
    if enable:
        info("local_rules_enabled will be set to true")

    # 5) dry-run / confirm
    if args.dry_run:
        print()
        print(panel([c("dry run", GOLD, bold=True) + ", nothing was changed"], color=GOLD))
        return

    print()
    if not args.yes and not confirm("apply to service %s?" % c(name, INK, bold=True)):
        die("aborted.", code=0)

    # 6) apply
    cfg = {"rules_request": final}
    if enable:
        cfg["local_rules_enabled"] = True
    try:
        if plugin:
            admin.patch("/plugins/%s" % plugin["id"], {"config": cfg})
            action = "updated"
        else:
            admin.post("/services/%s/plugins" % svc["id"], {"name": "karna", "config": cfg})
            action = "created"
    except RuntimeError as e:
        die(str(e))

    print()
    print(panel([
        c("✓ done", OLIVE, bold=True),
        "%s local rule(s) on service %s" % (c(len(final), INK, bold=True), c(name, INK, bold=True)),
        c("plugin %s · %s" % (action, admin.base), DIM),
    ], color=OLIVE))
    print()


if __name__ == "__main__":
    main()
