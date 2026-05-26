#!/usr/bin/env python3
"""
Categorize every PL1 test that the regression suite flags as "failed":
- send the test's request to the dev Karna stack (private_debug on, so the
  blocked response carries the matched rule object as its body);
- capture HTTP status + matched rule id from the response;
- bucket the test into one of:
    PASS_AS_IS        — already passed when re-fetched (suite-flakiness only)
    EQUIV_RULE        — Karna blocked with status 403 but a different rule id
                        than the test expected; semantic equivalent
    GATE_405          — Karna's method gate rejected (405 / not-allowed)
    GATE_KARNA_NATIVE — Karna blocked with a synthetic id (`check_arg_len`,
                        `uri_path_check_violation`, `method_allowed`, …)
    REAL_GAP          — Karna did NOT block (HTTP 2xx upstream reflect)
    NO_EXPECT_FP      — the test was `no_expect_ids` and Karna fired anyway
                        (FP from Karna's side)

CSV output to stdout. Filter post-hoc in pandas/awk.

Usage:
    cd crs-regression-test
    PARANOIA=1 ./configure-kong.sh
    # ensure private_debug is on (configure-kong.sh sets it)
    python3 categorize_fails.py > /tmp/pl1-categorized.csv
"""

import os
import re
import socket
import sys
import yaml
from pathlib import Path

HOST = os.environ.get("KARNA_TEST_HOST", "127.0.0.1")
PORT = int(os.environ.get("KARNA_TEST_PORT", "28000"))

KARNA_NATIVE_IDS = {
    "method_allowed",
    "uri_path_check_violation",
    "check_request_headers_allowed",
    "check_request_content_type_charset",
    "request_body_parser_violation",
    "check_arg_len",
}

ROOT = Path(__file__).parent / "tests"


def stage_request(stage_input):
    method = stage_input.get("method", "GET")
    uri = stage_input.get("uri", "/")
    version = stage_input.get("version", "HTTP/1.1")
    headers = stage_input.get("headers") or {}
    data = stage_input.get("data", "")
    if isinstance(data, list):
        data = "".join(str(d) for d in data)
    if not isinstance(data, str):
        data = str(data)

    hdrs = []
    has_cl = False
    # Force Host to one Kong recognises (configure-kong.sh registers
    # karna-test + integration.local). Tests carry Host: localhost
    # which doesn't match any route → Kong returns 404 instead of
    # forwarding to Karna.
    hdrs.append("Host: karna-test")
    for k, v in headers.items():
        kl = k.lower()
        if kl == "host":
            continue
        hdrs.append(f"{k}: {v}")
        if kl == "content-length":
            has_cl = True
    if data and not has_cl and method in ("POST", "PUT", "PATCH"):
        hdrs.append(f"Content-Length: {len(data.encode('utf-8', errors='replace'))}")
    header_block = "\r\n".join(hdrs)
    raw = f"{method} {uri} {version}\r\n{header_block}\r\n\r\n{data}"
    return raw


def parse_response(resp_bytes):
    try:
        text = resp_bytes.decode(errors="replace")
    except Exception:
        text = ""
    status_m = re.match(r"HTTP/1\.\d\s+(\d+)", text)
    status = int(status_m.group(1)) if status_m else 0
    rule_m = re.search(r'"id":"([^"]+)"', text)
    rule = rule_m.group(1) if rule_m else ""
    return status, rule


def send(stage_input):
    raw = stage_request(stage_input)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST, PORT))
        s.send(raw.encode("utf-8", errors="replace"))
        chunks = []
        try:
            while True:
                b = s.recv(8192)
                if not b:
                    break
                chunks.append(b)
                if len(b) < 8192:
                    break
        except socket.timeout:
            pass
        return parse_response(b"".join(chunks))
    except Exception as e:
        return 0, f"ERR:{e}"
    finally:
        s.close()


# CRS rule families share the same first 3 digits. Same prefix ≈
# same attack class (911=method, 920=protocol, 921=protocol-attack,
# 922=multipart, 930=LFI, 931=RFI, 932=RCE, 933=PHP, 934=generic,
# 941=XSS, 942=SQLi, 943=session, 944=Java, …).
def same_family(a, b):
    a, b = str(a), str(b)
    if not a.isdigit() or not b.isdigit():
        return a == b
    return a[:3] == b[:3]


def categorize_expect(expect_ids, status, rule):
    expect_ids = [str(x) for x in expect_ids]
    if rule in expect_ids:
        return "PASS_AS_IS"
    if status == 405:
        return "GATE_405"
    if status == 403:
        if rule in KARNA_NATIVE_IDS:
            return "GATE_KARNA_NATIVE"
        if not rule:
            return "EQUIV_RULE_UNKNOWN"
        if any(same_family(rule, eid) for eid in expect_ids):
            return "EQUIV_SAME_FAMILY"
        return "EQUIV_DIFFERENT_FAMILY"
    if status == 200:
        return "REAL_GAP"
    return f"UNKNOWN_{status}"


def categorize_no_expect(no_expect_ids, status, rule):
    no_expect_ids = [str(x) for x in no_expect_ids]
    if rule in no_expect_ids:
        return "NO_EXPECT_FP"
    return "PASS_AS_IS"


def iter_tests():
    for yaml_path in sorted(ROOT.rglob("*.yaml")):
        with open(yaml_path) as f:
            try:
                doc = yaml.safe_load(f)
            except Exception:
                continue
        if not doc or "tests" not in doc:
            continue
        for t in doc["tests"]:
            test_id = t.get("test_id")
            for stage in t.get("stages", []):
                stage_input = stage.get("input", {})
                stage_output = stage.get("output", {})
                log = stage_output.get("log") or {}
                expect_ids = log.get("expect_ids") or []
                no_expect_ids = log.get("no_expect_ids") or []
                yield yaml_path.name, test_id, stage_input, expect_ids, no_expect_ids
                break  # only first stage


def main():
    print("yaml,test_id,kind,expected,karna_status,karna_rule,category")
    for yaml_name, test_id, stage_input, expect_ids, no_expect_ids in iter_tests():
        if not expect_ids and not no_expect_ids:
            continue  # nothing to assert
        status, rule = send(stage_input)
        if expect_ids:
            cat = categorize_expect(expect_ids, status, rule)
            ids_str = "|".join(str(x) for x in expect_ids)
            print(f"{yaml_name},{test_id},expect,{ids_str},{status},{rule},{cat}")
        if no_expect_ids:
            cat = categorize_no_expect(no_expect_ids, status, rule)
            ids_str = "|".join(str(x) for x in no_expect_ids)
            print(f"{yaml_name},{test_id},no_expect,{ids_str},{status},{rule},{cat}")


if __name__ == "__main__":
    main()
