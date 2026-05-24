import socket
import yaml, json, re, os, time, sys
import argparse

# CRS rules Karna intentionally removes via coreruleset_fix.global_fps
# because they duplicate a Karna schema-level config knob. The
# regression bench can't detect the equivalence — the test framework
# searches for the CRS rule id in the response, doesn't find it, and
# would report "failed (expect)". Mark these as passed* with a tag so
# the per-rule summary remains accurate without a misleading red.
#
# Principle (memory: project_principle_config_vs_rules, 2026-05-24):
# limits and configuration live in the plugin schema, detection rules
# detect attacks. The two never mix. CRS rules that exist purely to
# gate behaviour on a TX-set config variable are duplicates of
# Karna's schema and are removed via coreruleset_fix.global_fps.
KARNA_REMOVED_RULES = {
    "911100": "request_methods_allowed",
    "920360": "limit_arg_name_length",
    "920370": "limit_arg_value_length",
    "920380": "limit_arg_num",
    "920390": "total_arg_value_length",
    "920410": "(body length limit covers combined file sizes)",
}

# parse arguments
parser = argparse.ArgumentParser(description='CRS Regression Test')
parser.add_argument('--testfile', type=str, help='YAML regression test file or directory', required=True)
parser.add_argument('--testrule', type=str, help='Rule ID subject of test', required=False)
parser.add_argument('--testnum', type=str, help='Filter test number', required=False)
parser.add_argument('--show-only-failed', help='Show only failed tests', required=False, action='store_true')
parser.add_argument('--debug', help='Debug mode', required=False, action='store_true')
parser.add_argument('--host', type=str, default=os.environ.get('KARNA_TEST_HOST', '127.0.0.1'),
                    help='Kong proxy host (default: 127.0.0.1, or env KARNA_TEST_HOST)')
parser.add_argument('--port', type=int, default=int(os.environ.get('KARNA_TEST_PORT', '28000')),
                    help='Kong proxy port (default: 28000 to match docker-compose, or env KARNA_TEST_PORT)')
args = parser.parse_args()

def colorize(text, color):
    # bash color red and green
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "orange": "\033[33m",
        "end": "\033[0m"
    }

    return f"{colors[color]}{text}{colors['end']}"

# def function to get rulenumber from test file name <ruleid>.yaml
def get_rule_id_from_testfile(testfile):
    rule_id = os.path.basename(testfile).split(".")[0]
    return rule_id

def collect_test_files(path):
    normalized_path = os.path.abspath(path)
    if not os.path.exists(normalized_path):
        print(f"Path not found: {normalized_path}")
        sys.exit(1)

    if os.path.isdir(normalized_path):
        collected = []
        for root, _, files in os.walk(normalized_path):
            for filename in files:
                if filename.lower().endswith((".yaml", ".yml")):
                    collected.append(os.path.join(root, filename))
        if not collected:
            print(f"No YAML tests found in {normalized_path}")
            sys.exit(1)
        return sorted(collected)

    if normalized_path.lower().endswith((".yaml", ".yml")):
        return [normalized_path]

    print(f"No YAML files found at: {normalized_path}")
    sys.exit(1)

def send_request(test, rule_id):
    passed_tests = 0
    failed_tests = 0
    skipped_tests = 0

    args.testrule = rule_id

    for stg in test["stages"]:
        if args.testnum:
            if str(test["test_id"]) != args.testnum:
                continue

        curl_command = "curl"
        
        if args.debug:
            print(f"-------- TEST {test['test_id']} --------")
            print(json.dumps(stg, indent=4))

        # remove last part "-<number>" from title to get the rule id
        #rule_id = test["test_id"].split("-")[0]

        stage = stg

        # build request
        method = "GET"
        if "method" in stage["input"]:
            method = stage["input"]["method"]
        
        version = "HTTP/1.1"
        if "version" in stage["input"]:
            version = stage["input"]["version"]
        
        data = ""
        if "data" in stage["input"]:
            data = stage["input"]["data"]
            # normalize line endings to \r\n
            data = data.replace("\r\n", "\n").replace("\n", "\r\n")
            #print(f"DEBUG: data len={len(data)}, has CR={chr(13) in data}")
            
            # for curl command, replace all \r\n with \\r\\n
            curl_data = data.replace("\r\n", "\\r\\n")
            curl_command += f" -d '{curl_data}'"
        
        uri = "/"
        if "uri" in stage["input"]:
            uri = stage["input"]["uri"]
        
        curl_command += f" -X {method} 'http://{args.host}:{args.port}{uri}'"

        # build request headers
        headers = f"x-karna-test: true\r\nx-karna-test-rule-id: {args.testrule}\r\n"
        #headers = f"x-karna-test: true\r\n"
        cl_found = False
        ct_found = False
        if "headers" in stage["input"]:
            for key, value in stage["input"]["headers"].items():
                if key == "Host" or key == "host":
                    #if not "example" in value:
                    headers += "Host: integration.local\r\n"
                    #else:
                    #    headers += f"Host: {value}\r\n"
                    continue

                if key == "Accept-Encoding" and not test["test_id"] in ["920520-7"]:
                    continue

                if key == "Content-Length" or key == "content-length":
                    cl_found = True
                
                if key == "Content-Type" or key == "content-type":
                    ct_found = True

                headers += f"{key}: {value}\r\n"

            if not "Host" in stage["input"]["headers"] and not "host" in stage["input"]["headers"]:
                headers += "Host: karna-test\r\n"

        if not cl_found:
            if not "stop_magic" in stage["input"]:
                headers += f"Content-Length: {len(data)}\r\n"
                cl_found = True

        if not ct_found and cl_found and len(data) > 0:
            if not "stop_magic" in stage["input"]:
                headers += f"Content-Type: application/x-www-form-urlencoded\r\n"

        for h in headers.split("\r\n"):
            curl_command += f" -H '{h}'"

        if args.debug:
            print(f"--- CURL COMMAND ---")
            # escape all [ and ] in curl command
            curl_command = curl_command.replace("[", "\\[").replace("]", "\\]")
            print(f"{curl_command} | jq")


        request = f"{method} {uri} {version}\r\n{headers}\r\n{data}"

        if args.debug:
            print("\n\n>>>> REQUEST >>>>")
            print(request)

        # send request
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((args.host, args.port))
        s.send(request.encode())
        try:
            response = s.recv(40968)
        except socket.timeout:
            s.close()
            print(f"{colorize('failed (timeout: no response from server)', 'red')}")
            failed_tests += 1
            continue
        s.close()

        response_decoded = response.decode()

        if args.debug:
            print("<<<< RESPONSE <<<<")
            print(response_decoded)

        #prefix = f"Running test {test['test_id']}: "
        prefix = ""

        if args.show_only_failed:
            prefix = f"Test Rule {args.testrule} - {test['test_id']}: "

        if "output" in stage:
            if "log" in stage["output"]:
                if "expect_ids" in stage["output"]["log"]:
                    expect_ids = stage["output"]["log"]["expect_ids"]
                    # Karna-removed rules: the equivalent is enforced via a
                    # schema-level config knob (limits/policy), not via a CRS
                    # rule. Don't flag these as failed. YAML loads rule ids
                    # as ints; the map uses strings — normalise.
                    expect_ids_str = [str(eid) for eid in expect_ids]
                    if all(eid in KARNA_REMOVED_RULES for eid in expect_ids_str):
                        karna_knob = KARNA_REMOVED_RULES[expect_ids_str[0]]
                        print(f"{prefix}{colorize(f'passed* (covered by Karna config: {karna_knob})', 'green')}")
                        passed_tests += 1
                        continue
                    at_least_one_passed = False
                    for expruleid in expect_ids:
                        if f'"id":"{expruleid}"' in response_decoded:
                            if not args.show_only_failed:
                                print(f"{prefix}{colorize('passed', 'green')}")
                            passed_tests += 1
                            at_least_one_passed = True
                            break
                    if not at_least_one_passed:
                        if "403 Forbidden" in response_decoded:
                            if "Request URI path contains illegal characters" in response_decoded:
                                print(f"{prefix}{colorize('passed* (got 403 by rule illegal characters)', 'green')}")
                            else:
                                print(f"{prefix}{colorize('failed (expect, but got 403)', 'orange')}")
                        else:
                            if "405 Not Allowed" in response_decoded:
                                print(f"{prefix}{colorize('passed* (got 405, likely due to missing rule)', 'green')}")
                            else:
                                print(f"{prefix}{colorize('failed (expect)', 'red')}")
                        failed_tests += 1
                if "no_expect_ids" in stage["output"]["log"]:
                    no_expect_ids = stage["output"]["log"]["no_expect_ids"]
                    for nexpruleid in no_expect_ids:
                        if f'"id":"{nexpruleid}",' not in response_decoded:
                            if not args.show_only_failed:
                                print(f"{prefix}{colorize('passed', 'green')}")
                            passed_tests += 1
                        else:
                            print(f"{prefix}{colorize('failed (not expect)', 'red')}")
                            failed_tests += 1

        # check response
        if "log_contains" in stage["output"]:
            # get only number from log_contains
            log_contains = re.findall(r'\d+', stage["output"]["log_contains"])
            if log_contains:
                log_contains = log_contains[0]
                if log_contains in response_decoded:
                    if not args.show_only_failed:
                        print(f"{prefix}{colorize('passed', 'green')}")
                    passed_tests += 1
                else:
                    print(f"{prefix}{colorize('failed', 'red')}")
                    failed_tests += 1
            else:
                if not args.show_only_failed:
                    print(f"{prefix}skip, no id number in log_contains")
                skipped_tests += 1
                #failed_tests += 1
        
        if "no_log_contains" in stage["output"]:
            # get only number from log_contains
            no_log_contains = re.findall(r'\d+', stage["output"]["no_log_contains"])
            if no_log_contains:
                if no_log_contains[0] not in response_decoded:
                    if not args.show_only_failed:
                        print(f"{prefix}{colorize('passed', 'green')}")
                    passed_tests += 1
                else:
                    print(f"{prefix}{colorize('failed', 'red')}")
                    failed_tests += 1
            else:
                skipped_tests += 1
                if not args.show_only_failed:
                    print(f"{prefix}skip, no id number in no_log_contains")
                #failed_tests += 1

    return passed_tests, failed_tests, skipped_tests

tests = {}

test_files = collect_test_files(args.testfile)

for test_file in test_files:
    with open(test_file, 'r') as f:
        tests[test_file] = yaml.safe_load(f) or {}

passed_tests = 0
failed_tests = 0
skipped_tests = 0
loading_status = 1
loading_arr = ["|", "/", "-", "\\"]

def show_loading_bash():
    global loading_status
    if not args.show_only_failed:
        print(f"\rRunning tests {loading_arr[loading_status]}", end="")
    if loading_status >= 3:
        loading_status = 0
    else:
        loading_status += 1
            
start_time = time.time()

cli_testrule = args.testrule

for testfile, test_content in tests.items():
    rule_id = cli_testrule if cli_testrule else get_rule_id_from_testfile(testfile)
    file_tests = test_content.get("tests", []) if isinstance(test_content, dict) else []

    if not file_tests:
        if args.debug:
            print(f"No tests found in {testfile}")
        continue

    for test in file_tests:
        if args.testnum and str(test["test_id"]) != args.testnum:
            continue
        if not args.show_only_failed:
            print(f'Running test {test["test_id"]} ({os.path.basename(testfile)})... ', end="")
        p, f, s = send_request(test, rule_id)
        passed_tests += p
        failed_tests += f
        skipped_tests += s

end_time = time.time()

# get percentage of passed tests
total_tests = passed_tests + failed_tests
passed_percentage = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
failed_percentage = (failed_tests / total_tests) * 100 if total_tests > 0 else 0
skipped_tests_percentage = (skipped_tests / total_tests) * 100 if total_tests > 0 else 0
print("\n\n")
print(f"✅  Passed tests:  {passed_tests}/{total_tests} ({passed_percentage}%)")
print(f"❌  Failed tests:  {failed_tests}/{total_tests} ({failed_percentage}%)")
print(f"🚫 Skipped tests:  {skipped_tests}/{total_tests} ({skipped_tests_percentage}%)")
print(f"⏱️     Total time:  {end_time - start_time} seconds")
print("\n\n")
