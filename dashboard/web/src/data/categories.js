/* Attack-category derivation from a match.
 *
 * Karna does NOT label categories in the audit log — every match carries a
 * `rule_id` (CRS numeric id, an MCP rule, or a local-rule id) and `tags[]`.
 * The dashboard derives a category from the CRS rule-id range, mirroring the
 * OWASP CRS family numbering. The phase-2 backend will mirror this exact map
 * so sample and live data classify identically.
 */

export const CATEGORIES = [
  { id: "sqli",    name: "SQL Injection",        color: "var(--cat-1)" },
  { id: "xss",     name: "Cross-Site Scripting",  color: "var(--cat-1)" },
  { id: "rce",     name: "RCE / Command Inj.",    color: "var(--cat-1)" },
  { id: "lfi",     name: "Path Traversal / LFI",  color: "var(--cat-2)" },
  { id: "rfi",     name: "Remote File Inclusion", color: "var(--cat-2)" },
  { id: "php",     name: "PHP Injection",         color: "var(--cat-2)" },
  { id: "java",    name: "Java Attacks",          color: "var(--cat-2)" },
  { id: "generic", name: "Generic / SSRF",        color: "var(--cat-3)" },
  { id: "scanner", name: "Scanner / Recon",       color: "var(--cat-3)" },
  { id: "proto",   name: "Protocol Anomaly",      color: "var(--cat-3)" },
  { id: "session", name: "Session Fixation",      color: "var(--cat-3)" },
  { id: "mcp",     name: "MCP / JSON-RPC",         color: "var(--cat-2)" },
  { id: "gate",    name: "Validation Gate",       color: "var(--cat-4)" },
  { id: "other",   name: "Other",                 color: "var(--fg-3)" },
];

const GATE_IDS = new Set([
  "method_allowed", "uri_path_check_violation", "check_request_headers_allowed",
  "check_request_content_type_charset", "check_request_content_type_enforce",
  "request_body_parser_violation", "limit_arg_num", "check_arg_len",
]);

const BY_ID = Object.fromEntries(CATEGORIES.map(c => [c.id, c]));

// CRS family prefix (3 digits) -> category id.
const PREFIX = {
  "913": "scanner",
  "920": "proto",
  "921": "proto",
  "922": "proto",
  "930": "lfi",
  "931": "rfi",
  "932": "rce",
  "933": "php",
  "934": "generic",
  "941": "xss",
  "942": "sqli",
  "943": "session",
  "944": "java",
};

export function categoryForRule(ruleId, tags) {
  const id = String(ruleId || "");
  if (id.startsWith("mcp")) return "mcp";
  // Karna's always-on gates emit synthetic ids (ka_engine.lua), mirrored in api/app.py.
  if (GATE_IDS.has(id) || /^(ka_|gate_|method|content_type|path|arg)/.test(id)) return "gate";
  const fam = PREFIX[id.slice(0, 3)];
  if (fam) return fam;
  // Fall back to tags if the id isn't a CRS family we know. `tags` can arrive
  // as an empty object `{}` (Karna's audit log serialises an empty Lua tags
  // table as `{}`, not `[]`) — `{} || []` is truthy, so guard on Array.isArray.
  const t = (Array.isArray(tags) ? tags : []).map(x => String(x).toLowerCase());
  if (t.some(x => x.includes("sqli") || x.includes("sql_injection"))) return "sqli";
  if (t.some(x => x.includes("xss"))) return "xss";
  if (t.some(x => x.includes("rce") || x.includes("command"))) return "rce";
  if (t.some(x => x.includes("lfi"))) return "lfi";
  if (t.some(x => x.includes("scanner"))) return "scanner";
  return "other";
}

export function categoryMeta(catId) {
  return BY_ID[catId] || BY_ID.other;
}
