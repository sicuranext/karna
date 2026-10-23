/* ============================================================
   Sample data — shaped EXACTLY like Karna's real surfaces so the
   phase-2 swap to live data is a source change only:
     - events[]   : real audit log v2 objects (ka_utils.get_auditlog_v2)
     - services[] : a Kong Service + its karna plugin config (schema.lua)
     - overrides  : rule_action_overrides / rule_response_overrides
     - crs/local  : coreruleset_rulesets, local rules, custom_secrules
   IPs use TEST-NET ranges (RFC 5737); hosts use example.com (RFC 2606).
   ============================================================ */

export const ENGINE = {
  name: "karna",
  version: "1.7.3",
  commit: "unknown",
  commit_short: "unknown",
  built_at: "unknown",
  crs_version: "4.26.0", // sample; live = read from the loaded CRS pack
};

export const KONG_CONNECTION = {
  id: "sample-primary",
  name: "Production",
  protocol: "https",
  host: "kong.example.internal",
  port: 8444,
  url: "https://kong.example.internal:8444",
  active: true,
  metadata: { version: "3.9.2", hostname: "kong-prod-01", services_count: 18, karna_plugins_count: 12 },
};

// 24h observed traffic (hourly). Live: aggregated server-side from audit files.
const reqShape = [
  3.1, 2.4, 1.9, 1.6, 1.4, 1.7, 2.6, 4.2, 6.8, 8.9, 9.6, 9.1,
  8.4, 8.8, 9.3, 9.7, 9.2, 8.1, 7.0, 6.2, 5.4, 4.6, 3.9, 3.3,
];
const blkShape = [
  41, 33, 28, 22, 19, 24, 38, 61, 96, 142, 168, 151,
  133, 147, 188, 214, 176, 129, 104, 88, 71, 60, 52, 44,
];
export const TRAFFIC = reqShape.map((r, i) => ({
  h: i,
  label: String(i).padStart(2, "0") + ":00",
  requests: Math.round(r * 1000),
  blocked: blkShape[i],
  allowed: Math.round(r * 1000) - blkShape[i],
}));

// 24h totals per attack category (derived server-side in live mode).
export const CATEGORY_COUNTS = [
  { id: "sqli",    count: 842 },
  { id: "xss",     count: 613 },
  { id: "rce",     count: 388 },
  { id: "lfi",     count: 271 },
  { id: "scanner", count: 196 },
  { id: "proto",   count: 124 },
  { id: "mcp",     count: 73 },
];

// Most-fired rules (24h). rule_id + message come straight from the audit log.
export const TOP_RULES = [
  { rule_id: "942100", message: "SQL Injection Attack Detected via libinjection", hits: 612, action: "block" },
  { rule_id: "941100", message: "XSS Attack Detected via libinjection",           hits: 487, action: "block" },
  { rule_id: "932160", message: "Remote Command Execution: Unix Shell Code",       hits: 301, action: "block" },
  { rule_id: "930120", message: "OS File Access Attempt",                          hits: 244, action: "block" },
  { rule_id: "913100", message: "Found User-Agent associated with security scanner", hits: 188, action: "detect" },
  { rule_id: "922100", message: "Multipart content-type charset mismatch",          hits: 121, action: "block" },
  { rule_id: "mcp_method_not_allowed", message: "MCP method not in allow-list",      hits: 64,  action: "block" },
  { rule_id: "942190", message: "Detects MSSQL/Oracle SQLi probes",                  hits: 58,  action: "detect" },
];

// Last-24h activity of the rules that matched most (live: RULE_ACTIVITY from the
// backend). Each shape is a recognisable pattern: daytime noise, a burst, a
// steady background, a one-hour scan.
const ruleShape = {
  daytime: [1, 1, 0, 0, 0, 1, 2, 4, 6, 8, 9, 8, 7, 8, 9, 10, 9, 7, 5, 4, 3, 2, 2, 1],
  burst:   [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 3, 18, 22, 6, 1, 0, 0, 0, 0, 0],
  steady:  [5, 5, 4, 5, 5, 4, 5, 5, 5, 6, 5, 5, 5, 4, 5, 5, 6, 5, 5, 4, 5, 5, 5, 5],
  scan:    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 2, 0, 0],
  night:   [6, 8, 9, 7, 5, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 5],
};
const spread = (total, shape) => {
  const sum = shape.reduce((a, b) => a + b, 0);
  const out = shape.map((v) => Math.floor((v / sum) * total));
  out[shape.indexOf(Math.max(...shape))] += total - out.reduce((a, b) => a + b, 0);
  return out;
};
export const RULE_ACTIVITY = [
  { rule_id: "942100", shape: "daytime", ips: 41, services: 3, top_service: "public-api", blocked_pct: 100 },
  { rule_id: "941100", shape: "burst", ips: 3, services: 1, top_service: "legacy-portal", blocked_pct: 100 },
  { rule_id: "932160", shape: "night", ips: 7, services: 2, top_service: "public-api", blocked_pct: 100 },
  { rule_id: "930120", shape: "scan", ips: 1, services: 1, top_service: "public-api", blocked_pct: 100 },
  { rule_id: "913100", shape: "steady", ips: 18, services: 4, top_service: "checkout", blocked_pct: 0 },
  { rule_id: "922100", shape: "steady", ips: 96, services: 1, top_service: "checkout", blocked_pct: 100 },
  { rule_id: "mcp_method_not_allowed", shape: "daytime", ips: 2, services: 1, top_service: "model-gateway", blocked_pct: 100 },
  { rule_id: "942190", shape: "burst", ips: 5, services: 2, top_service: "partner-api", blocked_pct: 0 },
].map(({ shape, ...a }) => {
  const r = TOP_RULES.find((x) => x.rule_id === a.rule_id);
  return { ...a, message: r.message, action: r.action, hits: r.hits, hourly: spread(r.hits, ruleShape[shape]) };
});

// Services = Kong Services that carry a karna plugin. `config` mirrors schema.lua;
// `observed` is computed from the audit logs (live mode).
export const SERVICES = [
  {
    id: "a1f0c2d4-0001-4a1b-9c00-000000000001", name: "public-api", host: "api.example.com", routes: 14,
    config: {
      engine_blocking_mode: true, engine_fast_path: true, engine_re2_scan: true, engine_ac_pm: true, engine_re2_match: true, paranoia_level: 2, coreruleset_enabled: true,
      coreruleset_rulesets: { method_enforcement: true, scanner_detection: true, protocol_enforcement: false, protocol_attack: true, multipart_attack: true, lfi: true, rfi: true, rce: true, php: true, generic: true, xss: true, sqli: true, session_fixation: true, java: true },
      local_rules_enabled: true, rules_request_count: 4, custom_secrules_count: 0,
      crs_plugins_path: "/opt/coreruleset-plugins/",
      crs_plugins_enabled: ["wordpress-rule-exclusions-plugin"],
      crs_plugins_available: [{ name: "wordpress-rule-exclusions-plugin", config_file_count: 2,
        config_files: ["wordpress-rule-exclusions-before.conf", "wordpress-rule-exclusions-config.conf"] }],
      mcp_enabled: false, redis_inspect_enabled: true, auditlog_format: "v2",
    },
    observed: { reqs_24h: 38420, block_rate: 1.7, latency_p95_ms: 1.9, status: "healthy" },
  },
  {
    id: "a1f0c2d4-0002-4a1b-9c00-000000000002", name: "checkout", host: "pay.example.com", routes: 6,
    config: {
      engine_blocking_mode: true, engine_fast_path: true, engine_re2_scan: true, engine_ac_pm: true, engine_re2_match: true, paranoia_level: 3, coreruleset_enabled: true,
      coreruleset_rulesets: { method_enforcement: true, scanner_detection: true, protocol_enforcement: false, protocol_attack: true, multipart_attack: true, lfi: true, rfi: true, rce: true, php: true, generic: true, xss: true, sqli: true, session_fixation: true, java: true },
      local_rules_enabled: true, rules_request_count: 2, custom_secrules_count: 1,
      mcp_enabled: false, redis_inspect_enabled: true, auditlog_format: "v2",
    },
    observed: { reqs_24h: 12880, block_rate: 0.9, latency_p95_ms: 2.4, status: "healthy" },
  },
  {
    id: "a1f0c2d4-0003-4a1b-9c00-000000000003", name: "model-gateway", host: "mcp.example.com", routes: 4,
    config: {
      engine_blocking_mode: true, engine_fast_path: true, engine_re2_scan: true, engine_ac_pm: true, engine_re2_match: true, paranoia_level: 2, coreruleset_enabled: true,
      coreruleset_rulesets: { method_enforcement: true, scanner_detection: true, protocol_enforcement: false, protocol_attack: true, multipart_attack: true, lfi: true, rfi: true, rce: true, php: true, generic: true, xss: true, sqli: true, session_fixation: true, java: true },
      local_rules_enabled: true, rules_request_count: 3, custom_secrules_count: 0,
      mcp_enabled: true, redis_inspect_enabled: false, auditlog_format: "v2",
    },
    observed: { reqs_24h: 9210, block_rate: 0.8, latency_p95_ms: 3.1, status: "healthy" },
  },
  {
    id: "a1f0c2d4-0004-4a1b-9c00-000000000004", name: "partner-api", host: "partners.example.com", routes: 9,
    config: {
      engine_blocking_mode: false, engine_fast_path: true, engine_re2_scan: true, engine_ac_pm: true, engine_re2_match: true, paranoia_level: 1, coreruleset_enabled: true,
      coreruleset_rulesets: { method_enforcement: true, scanner_detection: true, protocol_enforcement: false, protocol_attack: true, multipart_attack: true, lfi: true, rfi: true, rce: true, php: true, generic: true, xss: true, sqli: true, session_fixation: true, java: true },
      local_rules_enabled: true, rules_request_count: 1, custom_secrules_count: 0,
      mcp_enabled: false, redis_inspect_enabled: false, auditlog_format: "v2",
    },
    observed: { reqs_24h: 6740, block_rate: 3.2, latency_p95_ms: 1.6, status: "tuning" },
  },
  {
    id: "a1f0c2d4-0005-4a1b-9c00-000000000005", name: "legacy-portal", host: "portal.example.com", routes: 11,
    config: {
      engine_blocking_mode: false, engine_fast_path: true, engine_re2_scan: false, engine_ac_pm: true, engine_re2_match: true, paranoia_level: 1, coreruleset_enabled: true,
      coreruleset_rulesets: { method_enforcement: true, scanner_detection: true, protocol_enforcement: false, protocol_attack: true, multipart_attack: true, lfi: true, rfi: true, rce: true, php: true, generic: true, xss: true, sqli: true, session_fixation: true, java: true },
      local_rules_enabled: false, rules_request_count: 0, custom_secrules_count: 0,
      mcp_enabled: false, redis_inspect_enabled: false, auditlog_format: "v2",
    },
    observed: { reqs_24h: 4120, block_rate: 5.8, latency_p95_ms: 2.0, status: "tuning" },
  },
  {
    id: "a1f0c2d4-0006-4a1b-9c00-000000000006", name: "webhooks-ingress", host: "hooks.example.com", routes: 3,
    config: {
      engine_blocking_mode: true, engine_fast_path: true, engine_re2_scan: true, engine_ac_pm: true, engine_re2_match: true, paranoia_level: 2, coreruleset_enabled: false,
      coreruleset_rulesets: { method_enforcement: true, scanner_detection: true, protocol_enforcement: false, protocol_attack: true, multipart_attack: true, lfi: true, rfi: true, rce: true, php: true, generic: true, xss: true, sqli: true, session_fixation: true, java: true },
      local_rules_enabled: true, rules_request_count: 2, custom_secrules_count: 0,
      mcp_enabled: false, redis_inspect_enabled: false, auditlog_format: "v2",
    },
    observed: { reqs_24h: 2980, block_rate: 0.4, latency_p95_ms: 1.2, status: "healthy" },
  },
];

// Real audit log v2 objects (newest first). Shape = ka_utils.get_auditlog_v2 +
// the `latencies` block of audit log v2.
export const EVENTS = [
  {
    version: "2.0", timestamp: "2026-06-16T14:32:00.412Z", request_id: "8f21a4c0-1e2b-4d11-9a01-aa0000000001",
    service: { id: "a1f0c2d4-0001-4a1b-9c00-000000000001", name: "public-api" },
    client: { ip: "203.0.113.47", port: 54012 }, server: { ip: "10.0.0.10", port: 8000 },
    request: { method: "POST", uri: "/v2/orders/search", http_version: "1.1",
      headers: { host: "api.example.com", "user-agent": "python-requests/2.31", "content-type": "application/json" } },
    response: { status: 403, headers: { "content-type": "application/json" }, latency_ms: 0.0,
      latencies: { kong: 1.8, upstream: 0.0, total: 1.8 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "blocking", paranoia_level: 2 },
    matches: [
      { rule_id: "942100", message: "SQL Injection Attack Detected via libinjection", tags: ["OWASP_CRS", "attack-sqli", "paranoia-level/1"],
        matched_parts: [{ on: "request.body.json.filter", value: "1' OR '1'='1' --" }], action: "block" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "RU", country_name: "Russian Federation", continent_code: "EU", continent_name: "Europe" }, asn: { id: "12389", org: "Rostelecom" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:31:19.880Z", request_id: "8f1ee210-77aa-4c20-8b02-aa0000000002",
    service: { id: "a1f0c2d4-0003-4a1b-9c00-000000000003", name: "model-gateway" },
    client: { ip: "198.51.100.9", port: 41122 }, server: { ip: "10.0.0.12", port: 8000 },
    request: { method: "POST", uri: "/mcp/v1/messages", http_version: "2",
      headers: { host: "mcp.example.com", "user-agent": "mcp-client/0.4", "content-type": "application/json", authorization: "[REDACTED]" } },
    response: { status: 403, headers: { "content-type": "application/json" }, latency_ms: 0.0,
      latencies: { kong: 2.9, upstream: 0.0, total: 2.9 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "blocking", paranoia_level: 2 },
    matches: [
      { rule_id: "mcp_method_not_allowed", message: "MCP method/tool not in allow-list", tags: ["mcp", "jsonrpc"],
        matched_parts: [{ on: "mcp.params.name", value: "shell_exec" }], action: "block" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "US", country_name: "United States", continent_code: "NA", continent_name: "North America" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:30:52.140Z", request_id: "8f0a9933-22cc-4a01-9d03-aa0000000003",
    service: { id: "a1f0c2d4-0001-4a1b-9c00-000000000001", name: "public-api" },
    client: { ip: "192.0.2.211", port: 33980 }, server: { ip: "10.0.0.10", port: 8000 },
    request: { method: "GET", uri: "/static/%2e%2e/%2e%2e/etc/passwd", http_version: "1.1",
      headers: { host: "api.example.com", "user-agent": "curl/8.4.0" } },
    response: { status: 403, headers: { "content-type": "application/json" }, latency_ms: 0.0,
      latencies: { kong: 1.1, upstream: 0.0, total: 1.1 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "blocking", paranoia_level: 2 },
    matches: [
      { rule_id: "930120", message: "OS File Access Attempt", tags: ["OWASP_CRS", "attack-lfi"],
        matched_parts: [{ on: "request.uri.path", value: "../../etc/passwd" }], action: "block" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "CN", country_name: "China", continent_code: "AS", continent_name: "Asia" }, asn: { id: "4134", org: "Chinanet" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:28:57.330Z", request_id: "8ef21044-aa11-4bb0-8e04-aa0000000004",
    service: { id: "a1f0c2d4-0005-4a1b-9c00-000000000005", name: "legacy-portal" },
    client: { ip: "203.0.113.88", port: 50991 }, server: { ip: "10.0.0.14", port: 8000 },
    request: { method: "GET", uri: "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", http_version: "1.1",
      headers: { host: "portal.example.com", "user-agent": "Mozilla/5.0" } },
    response: { status: 200, headers: { "content-type": "text/html" }, latency_ms: 14.2,
      latencies: { kong: 1.4, upstream: 14.2, total: 15.6 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "detection", paranoia_level: 1 },
    matches: [
      { rule_id: "941100", message: "XSS Attack Detected via libinjection", tags: ["OWASP_CRS", "attack-xss"],
        matched_parts: [{ on: "request.args.q", value: "<script>alert(1)</script>" }], action: "detect" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "BR", country_name: "Brazil", continent_code: "SA", continent_name: "South America" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:27:21.000Z", request_id: "8ee07755-bb22-4cc0-9f05-aa0000000005",
    service: { id: "a1f0c2d4-0002-4a1b-9c00-000000000002", name: "checkout" },
    client: { ip: "198.51.100.74", port: 47210 }, server: { ip: "10.0.0.11", port: 8000 },
    request: { method: "POST", uri: "/charge", http_version: "1.1",
      headers: { host: "pay.example.com", "user-agent": "Go-http-client/2.0", "content-type": "application/json" } },
    response: { status: 403, headers: { "content-type": "application/json" }, latency_ms: 0.0,
      latencies: { kong: 2.2, upstream: 0.0, total: 2.2 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "blocking", paranoia_level: 3 },
    matches: [
      { rule_id: "932160", message: "Remote Command Execution: Unix Shell Code Found", tags: ["OWASP_CRS", "attack-rce"],
        matched_parts: [{ on: "request.body.json.note", value: ";cat /etc/shadow" }], action: "block" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "DE", country_name: "Germany", continent_code: "EU", continent_name: "Europe" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:25:43.610Z", request_id: "8ed46622-cc33-4dd0-8006-aa0000000006",
    service: { id: "a1f0c2d4-0004-4a1b-9c00-000000000004", name: "partner-api" },
    client: { ip: "203.0.113.5", port: 38844 }, server: { ip: "10.0.0.13", port: 8000 },
    request: { method: "GET", uri: "/v1/users", http_version: "1.1",
      headers: { host: "partners.example.com", "user-agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)" } },
    response: { status: 200, headers: { "content-type": "application/json" }, latency_ms: 9.1,
      latencies: { kong: 1.6, upstream: 9.1, total: 10.7 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "detection", paranoia_level: 1 },
    matches: [
      { rule_id: "913100", message: "Found User-Agent associated with security scanner", tags: ["OWASP_CRS", "attack-scanner"],
        matched_parts: [{ on: "request.headers.user-agent", value: "Nuclei" }], action: "detect" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "IN", country_name: "India", continent_code: "AS", continent_name: "Asia" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:24:08.220Z", request_id: "8ec19911-dd44-4ee0-9107-aa0000000007",
    service: { id: "a1f0c2d4-0002-4a1b-9c00-000000000002", name: "checkout" },
    client: { ip: "198.51.100.220", port: 52001 }, server: { ip: "10.0.0.11", port: 8000 },
    request: { method: "POST", uri: "/charge", http_version: "1.1",
      headers: { host: "pay.example.com", "user-agent": "Mozilla/5.0", "content-type": "application/json" } },
    response: { status: 200, headers: { "content-type": "application/json" }, latency_ms: 11.3,
      latencies: { kong: 2.1, upstream: 11.3, total: 13.4 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "blocking", paranoia_level: 3 },
    matches: [
      { rule_id: "941310", message: "US-ASCII Malformed Encoding XSS Filter Evasion", tags: ["OWASP_CRS", "attack-xss"],
        matched_parts: [{ on: "request.body.json.description", value: "<img src=x onerror=fetch('//x')>" }], action: "sanitized" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "GB", country_name: "United Kingdom", continent_code: "EU", continent_name: "Europe" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:22:40.700Z", request_id: "8eb38800-ee55-4ff0-8208-aa0000000008",
    service: { id: "a1f0c2d4-0001-4a1b-9c00-000000000001", name: "public-api" },
    client: { ip: "203.0.113.201", port: 44120 }, server: { ip: "10.0.0.10", port: 8000 },
    request: { method: "POST", uri: "/v2/auth/login", http_version: "1.1",
      headers: { host: "api.example.com", "user-agent": "python-requests/2.31", "content-type": "application/json" } },
    response: { status: 429, headers: { "content-type": "application/json", "retry-after": "60" }, latency_ms: 0.0,
      latencies: { kong: 1.7, upstream: 0.0, total: 1.7 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "blocking", paranoia_level: 2 },
    matches: [
      { rule_id: "local_login_bruteforce", message: "Login attempts over threshold (rate limit)", tags: ["local", "rate-limit"],
        matched_parts: [{ on: "request.body.json.email", value: "admin@example.com" }], action: "rate_limited" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "RU", country_name: "Russian Federation", continent_code: "EU", continent_name: "Europe" }, asn: { id: "12389", org: "Rostelecom" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:20:11.500Z", request_id: "8e907733-ff66-4001-9309-aa0000000009",
    service: { id: "a1f0c2d4-0003-4a1b-9c00-000000000003", name: "model-gateway" },
    client: { ip: "198.51.100.31", port: 39550 }, server: { ip: "10.0.0.12", port: 8000 },
    request: { method: "POST", uri: "/mcp/v1/messages", http_version: "2",
      headers: { host: "mcp.example.com", "user-agent": "claude-mcp/1.2", "content-type": "application/json", "mcp-session-id": "9f3a***", authorization: "[REDACTED]" } },
    response: { status: 200, headers: { "content-type": "text/event-stream" }, latency_ms: 22.7,
      latencies: { kong: 3.4, upstream: 22.7, total: 26.1 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "detection", paranoia_level: 2 },
    matches: [
      { rule_id: "mcp_method_observed", message: "MCP method observed (allow-listed)", tags: ["mcp", "jsonrpc"],
        matched_parts: [{ on: "mcp.method", value: "resources/read" }], action: "log" },
    ],
    external_matches: [
      { source: "geoip-asn-plugin", rule_id: "ENRICH-asn", message: "ASN tagged as cloud provider", tags: ["enrichment"], metadata: { asn: 16509 } },
    ],
    enrichment: { geoip: { country_code: "US", country_name: "United States", continent_code: "NA", continent_name: "North America" }, asn: { id: "16509", org: "Amazon.com" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:17:55.010Z", request_id: "8e7c6644-0077-4112-840a-aa000000000a",
    service: { id: "a1f0c2d4-0005-4a1b-9c00-000000000005", name: "legacy-portal" },
    client: { ip: "203.0.113.150", port: 60110 }, server: { ip: "10.0.0.14", port: 8000 },
    request: { method: "GET", uri: "/index.php?page=php://filter/convert.base64-encode/resource=config", http_version: "1.1",
      headers: { host: "portal.example.com", "user-agent": "Mozilla/5.0" } },
    response: { status: 200, headers: { "content-type": "text/html" }, latency_ms: 7.8,
      latencies: { kong: 1.3, upstream: 7.8, total: 9.1 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "detection", paranoia_level: 1 },
    matches: [
      { rule_id: "933200", message: "PHP Injection Attack: Wrapper scheme detected", tags: ["OWASP_CRS", "attack-php"],
        matched_parts: [{ on: "request.args.page", value: "php://filter" }], action: "detect" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "TR", country_name: "Türkiye", continent_code: "AS", continent_name: "Asia" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:15:02.330Z", request_id: "8e615533-1188-4223-950b-aa000000000b",
    service: { id: "a1f0c2d4-0006-4a1b-9c00-000000000006", name: "webhooks-ingress" },
    client: { ip: "198.51.100.12", port: 51223 }, server: { ip: "10.0.0.15", port: 8000 },
    request: { method: "PUT", uri: "/hooks/github", http_version: "1.1",
      headers: { host: "hooks.example.com", "user-agent": "GitHub-Hookshot/a1b2c3", "content-type": "application/xml" } },
    response: { status: 403, headers: { "content-type": "application/json" }, latency_ms: 0.0,
      latencies: { kong: 1.0, upstream: 0.0, total: 1.0 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "blocking", paranoia_level: 2 },
    matches: [
      { rule_id: "content_type_not_allowed", message: "Request Content-Type not in allow-list (gate)", tags: ["gate", "protocol"],
        matched_parts: [{ on: "request.headers.content-type", value: "application/xml" }], action: "block" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "FR", country_name: "France", continent_code: "EU", continent_name: "Europe" } },
  },
  {
    version: "2.0", timestamp: "2026-06-16T14:12:44.900Z", request_id: "8e443322-2299-4334-960c-aa000000000c",
    service: { id: "a1f0c2d4-0001-4a1b-9c00-000000000001", name: "public-api" },
    client: { ip: "192.0.2.43", port: 35567 }, server: { ip: "10.0.0.10", port: 8000 },
    request: { method: "POST", uri: "/v2/orders/search", http_version: "1.1",
      headers: { host: "api.example.com", "user-agent": "okhttp/4.12", "content-type": "application/json" } },
    response: { status: 200, headers: { "content-type": "application/json" }, latency_ms: 8.4,
      latencies: { kong: 1.9, upstream: 8.4, total: 10.3 } },
    engine: { name: "karna", version: "1.7.3", commit: "unknown", mode: "detection", paranoia_level: 1 },
    matches: [
      { rule_id: "942190", message: "Detects MSSQL/Oracle SQLi probes (time-based)", tags: ["OWASP_CRS", "attack-sqli"],
        matched_parts: [{ on: "request.body.json.sort", value: "id; WAITFOR DELAY '0:0:5'" }], action: "detect" },
    ],
    external_matches: [],
    enrichment: { geoip: { country_code: "NL", country_name: "Netherlands", continent_code: "EU", continent_name: "Europe" } },
  },
];

// rule_action_overrides — the real "virtual patching" (selector + action).
export const RULE_ACTION_OVERRIDES = [
  { service: "partner-api", selector: { ids: ["942440"] }, action: { type: "passthrough" },
    note: "SQL comment sequence in legitimate partner payloads", by: "you@example.com", hits: 128 },
  { service: "public-api", selector: { ids: ["941310"] }, action: { type: "fix", remove_chars_pattern: "[<>\"'&]" },
    note: "Sanitise instead of block on user-content field", by: "you@example.com", hits: 64 },
  { service: "all", selector: { tags: ["attack-scanner"] }, action: { type: "block" },
    note: "Force-block all scanner detections fleet-wide", by: "you@example.com", hits: 412 },
];

// rule_response_overrides — custom block response for matched rules.
export const RULE_RESPONSE_OVERRIDES = [
  { service: "public-api", selector: { id_ranges: ["942000-942999"] },
    response: { status_code: 403, body: "Request rejected · ref %{request.path}", headers: { "x-blocked-by": "karna" } },
    by: "you@example.com" },
];

// Global CRS category toggles (coreruleset_rulesets defaults from schema.lua).
export const CRS_RULESETS = {
  method_enforcement: true, scanner_detection: true, protocol_enforcement: false,
  protocol_attack: true, multipart_attack: true, lfi: true, rfi: true, rce: true,
  php: true, generic: true, xss: true, sqli: true, session_fixation: true, java: true,
};

// Local rules (rules_request) across services — id/phase/message/action kind.
export const LOCAL_RULES = [
  { id: "local_login_bruteforce", service: "public-api", phase: "access", message: "Login rate limit", action_kind: "rate_limit", hits: 36 },
  { id: "local_block_admin_cidr", service: "all", phase: "access", message: "Deny /admin from public CIDRs", action_kind: "fixed_response", hits: 412 },
  { id: "local_autoban_sqli", service: "public-api", phase: "access", message: "Auto-ban repeat SQLi sources", action_kind: "redis_sadd", hits: 9 },
  { id: "local_trusted_internal", service: "checkout", phase: "access", message: "Flag trusted internal caller", action_kind: "set_variable", hits: 0 },
];

export const CUSTOM_SECRULES = [
  { id: "990001", service: "checkout", text: 'SecRule REQUEST_HEADERS:X-Tenant "@rx ^[a-z0-9-]{1,32}$" "id:990001,phase:1,pass,t:none"' },
];

// CRS exclusion plugins available on disk (crs_plugins_enabled).
export const CRS_PLUGINS = [
  { name: "wordpress-rule-exclusions-plugin", installed: true, config_file_count: 2, services: ["public-api"] },
  { name: "drupal-rule-exclusions-plugin", installed: true, config_file_count: 2, services: [] },
];

// Impact of the always-on coreruleset_fix.lua layer (pruned / bridged rules).
export const CRS_FIX_IMPACT = {
  pruned: 95, bridged: 6,
  buckets: [
    { name: "Protocol well-formedness (Kong/nginx already enforce)", count: 38 },
    { name: "Host / Connection semantics (Kong owns routing)", count: 22 },
    { name: "Browser-nicety, FP-prone on API clients", count: 18 },
    { name: "Config-as-rule (schema gates are authoritative)", count: 17 },
  ],
};

export const REDIS = {
  host: "redis.internal", port: 6379, database: 0, inspect_enabled: true,
  on_error: "skip", timeout_ms: 50, keepalive_pool_size: 64, connected: true,
};

export const LOG_SOURCES = [
  { id: "files", name: "Audit log files", detail: "/usr/local/openresty/nginx/logs", format: "audit v2 · JSON", on: true },
  { id: "loki", name: "Grafana Loki", detail: "loki.internal:3100", format: "audit v2 · JSON", on: false },
  { id: "opensearch", name: "OpenSearch", detail: "os.internal · index karna-*", format: "audit v2 · JSON", on: false },
];

// p50/p95/p99 of Kong (WAF) latency — from the latencies block of audit log v2.
export const LATENCY = { p50: 0.9, p95: 2.1, p99: 4.8, max: 18.2 };

const CHANGE_NOW = Math.floor(Date.now() / 1000);
export const CHANGES = [
  { ts: CHANGE_NOW - 1100, actor: "admin@example.com", action: "engine_update", service: "checkout", plugin_id: "plugin-checkout",
    before: { engine_blocking_mode: false, paranoia_level: 2 }, after: { engine_blocking_mode: true, paranoia_level: 3 } },
  { ts: CHANGE_NOW - 4200, actor: "admin@example.com", action: "action_override_add", service: "public-api", plugin_id: "plugin-public-api",
    detail: { selector: { ids: ["941310"] }, action: { type: "fix", remove_chars_pattern: "[<>\\\"'&]" } } },
  { ts: CHANGE_NOW - 8900, actor: "admin@example.com", action: "rule_update", service: "model-gateway", plugin_id: "plugin-model-gateway",
    detail: { kind: "native", index: 2, id: "mcp_method_not_allowed" } },
  { ts: CHANGE_NOW - 17200, actor: "admin@example.com", action: "kong_connection_update", service: "—",
    before: { url: "http://kong:8001" }, after: { url: "https://kong-admin.internal:8444" } },
  { ts: CHANGE_NOW - 86400, actor: "admin@example.com", action: "logs_ttl_update", service: "—",
    before: { ttl_days: 30 }, after: { ttl_days: 90 }, detail: { pruned: 0 } },
  { ts: CHANGE_NOW - 172800, actor: "admin@example.com", action: "response_override_remove", service: "partner-api", plugin_id: "plugin-partner-api",
    detail: { index: 1, removed: { selector: { tags: ["attack-scanner"] }, response: { status_code: 403 } } } },
];
