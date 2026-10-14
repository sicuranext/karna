import React from "react";
import { Icon } from "./icons.jsx";

export const SERVICE_CONFIG_DEFAULTS = {
  set_karna_headers: false,
  local_rules_enabled: true,
  mcp_enabled: false,
  mcp_routes: [],
  mcp_detection_heuristic: false,
  mcp_protocol_versions_allowed: ["2025-11-25", "2025-06-18", "2025-03-26"],
  mcp_block_legacy_sse_transport: false,
  mcp_origin_check_enabled: true,
  mcp_origins_allowed: [],
  mcp_max_event_size_bytes: 1048576,
  mcp_max_stream_buffer_bytes: 8388608,
  mcp_redact_session_id_in_audit: true,
  mcp_redact_authorization_in_audit: true,
  ignore_from_local_ips: false,
  check_invalid_chars_in_path: false,
  limit_invalid_chars_in_path: 1,
  check_special_chars_in_path: true,
  limit_special_chars_in_path: 3,
  request_methods_allowed: ["GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS", "PATCH", "PROPFIND"],
  request_headers_denied: ["content-encoding", "proxy", "lock-token", "content-range", "if"],
  total_arg_value_length: 64000,
  restricted_extensions: [],
  request_content_type_charset_allowed: ["utf-8", "iso-8859-1", "iso-8859-15", "windows-1252"],
  request_content_type_allowed: [
    "application/x-www-form-urlencoded", "multipart/form-data", "multipart/related",
    "text/xml", "application/xml", "application/soap+xml", "application/json",
    "application/cloudevents+json", "application/cloudevents-batch+json",
  ],
  request_content_type_enforce: true,
  limit_arg_name_length: 100,
  limit_arg_value_length: 400,
  limit_arg_num: 255,
  inspection_table_convert: [],
  validate_utf8_encoding: true,
  try_bas64decode_if_possible: false,
  crs_plugins_path: "/opt/coreruleset-plugins/",
  default_block_response_body: "",
  default_block_response_headers: {},
  default_ratelimit_response_body: "",
  default_ratelimit_response_headers: {},
  default_50x_response_body: "",
  default_50x_response_headers: {},
  auditlog_enabled: true,
  auditlog_path: "/usr/local/openresty/nginx/logs",
  auditlog_format: "v2",
  auditlog_only_on_match: false,
  auditlog_modsec: false,
  auditlog_error_log_on_match: false,
  redis_host: "localhost",
  redis_port: 6379,
  redis_inspect_enabled: false,
  redis_database: 0,
  redis_timeout_ms: 50,
  redis_keepalive_pool_size: 64,
  redis_keepalive_idle_ms: 60000,
  redis_on_error: "skip",
  private_debug: false,
};

const OPTIONAL_BODY_FIELDS = new Set([
  "default_block_response_body", "default_ratelimit_response_body", "default_50x_response_body",
]);

export function createServiceConfig(config = {}) {
  const out = { ...SERVICE_CONFIG_DEFAULTS, ...config };
  for (const [key, fallback] of Object.entries(SERVICE_CONFIG_DEFAULTS)) {
    if (Array.isArray(fallback)) out[key] = [...(config[key] ?? fallback)];
    else if (fallback && typeof fallback === "object") out[key] = { ...(config[key] ?? fallback) };
    else if (OPTIONAL_BODY_FIELDS.has(key)) out[key] = config[key] ?? "";
  }
  return out;
}

export function diffServiceConfig(before, after) {
  const changes = {};
  for (const key of Object.keys(SERVICE_CONFIG_DEFAULTS)) {
    if (JSON.stringify(before[key]) === JSON.stringify(after[key])) continue;
    changes[key] = OPTIONAL_BODY_FIELDS.has(key) && after[key] === "" ? null : after[key];
  }
  return changes;
}

function Section({ icon, title, description, children }) {
  return (
    <section className="service-config-section">
      <div className="service-config-section-head">
        <span className="service-config-section-icon"><Icon name={icon} size={15} /></span>
        <div><h3>{title}</h3><p>{description}</p></div>
      </div>
      <div className="service-config-section-body">{children}</div>
    </section>
  );
}

function Toggle({ label, description, value, onChange, disabled }) {
  return (
    <div className="service-config-toggle">
      <div><strong>{label}</strong><span>{description}</span></div>
      <button type="button" className={`switch${value ? " on" : ""}`} disabled={disabled}
        aria-label={`${label}: ${value ? "enabled" : "disabled"}`} aria-pressed={value}
        onClick={() => onChange(!value)} />
    </div>
  );
}

function Field({ label, description, children, wide = false }) {
  return (
    <label className={`service-config-field${wide ? " wide" : ""}`}>
      <span>{label}</span>
      {description && <small>{description}</small>}
      {children}
    </label>
  );
}

function TextInput({ value, onChange, disabled, type = "text", placeholder, min, max }) {
  return <input className="input" type={type} value={value ?? ""} disabled={disabled}
    min={min} max={max} placeholder={placeholder} onChange={(event) =>
      onChange(type === "number" && event.target.value !== "" ? Number(event.target.value) : event.target.value)} />;
}

function ListInput({ value = [], onChange, disabled, placeholder }) {
  return <textarea className="input service-list-input" value={value.join("\n")} disabled={disabled}
    placeholder={placeholder} onChange={(event) =>
      onChange(event.target.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))} />;
}

function HeaderMapInput({ value = {}, onChange, disabled }) {
  const serialize = React.useCallback((map) =>
    Object.entries(map || {}).map(([name, headerValue]) => `${name}: ${headerValue}`).join("\n"), []);
  const [text, setText] = React.useState(() => serialize(value));
  React.useEffect(() => setText(serialize(value)), [value, serialize]);
  const commit = () => {
    const headers = {};
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const separator = line.indexOf(":");
      if (separator <= 0) continue;
      headers[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
    }
    onChange(headers);
  };
  return <textarea className="input service-list-input" value={text} disabled={disabled}
    placeholder={"content-type: text/plain\ncache-control: no-store"}
    onChange={(event) => setText(event.target.value)} onBlur={commit} />;
}

export function RequestValidationSettings({ value, onChange, disabled }) {
  const set = (key, next) => onChange({ ...value, [key]: next });
  return (
    <div className="service-config-panels">
      <Section icon="shield" title="Inspection boundaries" description="Hard limits evaluated before local and managed rules.">
        <div className="service-config-toggle-grid">
          <Toggle label="Enforce inspectable Content-Type" value={value.request_content_type_enforce} disabled={disabled}
            description="Reject request bodies Karna cannot structurally inspect." onChange={(v) => set("request_content_type_enforce", v)} />
          <Toggle label="Validate UTF-8 encoding" value={value.validate_utf8_encoding} disabled={disabled}
            description="Populate the CRS UTF-8 validation control." onChange={(v) => set("validate_utf8_encoding", v)} />
          <Toggle label="Check special path characters" value={value.check_special_chars_in_path} disabled={disabled}
            description="Apply the special-character threshold to request paths." onChange={(v) => set("check_special_chars_in_path", v)} />
          <Toggle label="Check invalid path characters" value={value.check_invalid_chars_in_path} disabled={disabled}
            description="Apply the invalid-character threshold to request paths." onChange={(v) => set("check_invalid_chars_in_path", v)} />
          <Toggle label="Ignore local IPs" value={value.ignore_from_local_ips} disabled={disabled}
            description="Bypass rule evaluation for locally sourced requests." onChange={(v) => set("ignore_from_local_ips", v)} />
          <Toggle label="Try Base64 decoding" value={value.try_bas64decode_if_possible} disabled={disabled}
            description="Attempt Base64 decoding while parsing request values." onChange={(v) => set("try_bas64decode_if_possible", v)} />
        </div>
        <div className="service-config-grid">
          <Field label="Special characters limit"><TextInput type="number" min={0} value={value.limit_special_chars_in_path} disabled={disabled} onChange={(v) => set("limit_special_chars_in_path", v)} /></Field>
          <Field label="Invalid characters limit"><TextInput type="number" min={0} value={value.limit_invalid_chars_in_path} disabled={disabled} onChange={(v) => set("limit_invalid_chars_in_path", v)} /></Field>
          <Field label="Argument name length"><TextInput type="number" min={0} value={value.limit_arg_name_length} disabled={disabled} onChange={(v) => set("limit_arg_name_length", v)} /></Field>
          <Field label="Argument value length"><TextInput type="number" min={0} value={value.limit_arg_value_length} disabled={disabled} onChange={(v) => set("limit_arg_value_length", v)} /></Field>
          <Field label="Argument count"><TextInput type="number" min={0} value={value.limit_arg_num} disabled={disabled} onChange={(v) => set("limit_arg_num", v)} /></Field>
          <Field label="Total argument value length"><TextInput type="number" min={0} value={value.total_arg_value_length} disabled={disabled} onChange={(v) => set("total_arg_value_length", v)} /></Field>
        </div>
      </Section>

      <Section icon="filter" title="Allow-lists and deny-lists" description="One value per line. Values are stored directly in this service's Karna plugin.">
        <div className="service-config-grid">
          <Field label="Allowed HTTP methods"><ListInput value={value.request_methods_allowed} disabled={disabled} onChange={(v) => set("request_methods_allowed", v)} /></Field>
          <Field label="Denied request headers"><ListInput value={value.request_headers_denied} disabled={disabled} onChange={(v) => set("request_headers_denied", v)} /></Field>
          <Field label="Allowed content types"><ListInput value={value.request_content_type_allowed} disabled={disabled} onChange={(v) => set("request_content_type_allowed", v)} /></Field>
          <Field label="Allowed charsets"><ListInput value={value.request_content_type_charset_allowed} disabled={disabled} onChange={(v) => set("request_content_type_charset_allowed", v)} /></Field>
          <Field label="Restricted extensions" description="Extensions without the leading dot."><ListInput value={value.restricted_extensions} disabled={disabled} onChange={(v) => set("restricted_extensions", v)} /></Field>
          <Field label="Inspection table conversion" description="Optional variable namespaces converted before inspection."><ListInput value={value.inspection_table_convert} disabled={disabled} onChange={(v) => set("inspection_table_convert", v)} /></Field>
        </div>
      </Section>
    </div>
  );
}

export function McpSettings({ value, onChange, disabled }) {
  const set = (key, next) => onChange({ ...value, [key]: next });
  return (
    <div className="service-config-panels">
      <Section icon="globe" title="Model Context Protocol" description="Enable MCP envelope detection only on services that expose MCP traffic.">
        <div className="service-config-toggle-grid">
          <Toggle label="MCP inspection" value={value.mcp_enabled} disabled={disabled} description="Parse JSON-RPC envelopes and expose mcp.* variables." onChange={(v) => set("mcp_enabled", v)} />
          <Toggle label="Heuristic detection" value={value.mcp_detection_heuristic} disabled={disabled} description="Detect MCP beyond explicitly configured routes." onChange={(v) => set("mcp_detection_heuristic", v)} />
          <Toggle label="Block legacy SSE transport" value={value.mcp_block_legacy_sse_transport} disabled={disabled} description="Reject the deprecated standalone SSE transport." onChange={(v) => set("mcp_block_legacy_sse_transport", v)} />
          <Toggle label="Origin checks" value={value.mcp_origin_check_enabled} disabled={disabled} description="Validate browser Origin against the allow-list." onChange={(v) => set("mcp_origin_check_enabled", v)} />
          <Toggle label="Redact session ID" value={value.mcp_redact_session_id_in_audit} disabled={disabled} description="Do not persist MCP session identifiers in audit logs." onChange={(v) => set("mcp_redact_session_id_in_audit", v)} />
          <Toggle label="Redact Authorization" value={value.mcp_redact_authorization_in_audit} disabled={disabled} description="Do not persist authorization values in audit logs." onChange={(v) => set("mcp_redact_authorization_in_audit", v)} />
        </div>
        <div className="service-config-grid">
          <Field label="MCP routes" description="One route path per line."><ListInput value={value.mcp_routes} disabled={disabled} placeholder="/mcp" onChange={(v) => set("mcp_routes", v)} /></Field>
          <Field label="Allowed protocol versions"><ListInput value={value.mcp_protocol_versions_allowed} disabled={disabled} onChange={(v) => set("mcp_protocol_versions_allowed", v)} /></Field>
          <Field label="Allowed origins"><ListInput value={value.mcp_origins_allowed} disabled={disabled} placeholder="https://client.example" onChange={(v) => set("mcp_origins_allowed", v)} /></Field>
          <Field label="Maximum event size (bytes)"><TextInput type="number" min={1} value={value.mcp_max_event_size_bytes} disabled={disabled} onChange={(v) => set("mcp_max_event_size_bytes", v)} /></Field>
          <Field label="Maximum stream buffer (bytes)"><TextInput type="number" min={1} value={value.mcp_max_stream_buffer_bytes} disabled={disabled} onChange={(v) => set("mcp_max_stream_buffer_bytes", v)} /></Field>
        </div>
      </Section>
    </div>
  );
}

function ResponseEditor({ title, bodyKey, headersKey, value, set, disabled, description }) {
  return (
    <div className="service-response-editor">
      <div><strong>{title}</strong><span>{description}</span></div>
      <div className="service-config-grid">
        <Field label="Response body"><textarea className="input service-body-input" value={value[bodyKey] || ""} disabled={disabled} placeholder="Use Karna's built-in response"
          onChange={(event) => set(bodyKey, event.target.value)} /></Field>
        <Field label="Response headers" description="One “Header: value” per line."><HeaderMapInput value={value[headersKey]} disabled={disabled} onChange={(v) => set(headersKey, v)} /></Field>
      </div>
    </div>
  );
}

export function ResponsesAndLogsSettings({ value, onChange, disabled }) {
  const set = (key, next) => onChange({ ...value, [key]: next });
  return (
    <div className="service-config-panels">
      <Section icon="doc" title="Default responses" description="Service-wide fallback bodies are static and never interpolate request data.">
        <ResponseEditor title="Blocked request" description="Used by CRS, local rules, and validation gates." bodyKey="default_block_response_body" headersKey="default_block_response_headers" value={value} set={set} disabled={disabled} />
        <ResponseEditor title="Rate limited request" description="Used for 429 responses, with block defaults as fallback." bodyKey="default_ratelimit_response_body" headersKey="default_ratelimit_response_headers" value={value} set={set} disabled={disabled} />
        <ResponseEditor title="Upstream 50x" description="Setting a body enables replacement of upstream 500–599 pages." bodyKey="default_50x_response_body" headersKey="default_50x_response_headers" value={value} set={set} disabled={disabled} />
      </Section>
      <Section icon="pulse" title="Audit logging" description="Control which events Karna writes and where Kong workers persist them.">
        <div className="service-config-toggle-grid">
          <Toggle label="Audit log" value={value.auditlog_enabled} disabled={disabled} description="Write Karna audit events for this service." onChange={(v) => set("auditlog_enabled", v)} />
          <Toggle label="Only on match" value={value.auditlog_only_on_match} disabled={disabled} description="Skip audit entries when no rule or external match exists." onChange={(v) => set("auditlog_only_on_match", v)} />
          <Toggle label="ModSecurity output" value={value.auditlog_modsec} disabled={disabled} description="Also emit the ModSecurity-compatible representation." onChange={(v) => set("auditlog_modsec", v)} />
          <Toggle label="Mirror matches to error log" value={value.auditlog_error_log_on_match} disabled={disabled} description="Send match summaries to the Kong error log." onChange={(v) => set("auditlog_error_log_on_match", v)} />
          <Toggle label="Karna response headers" value={value.set_karna_headers} disabled={disabled} description="Expose Karna diagnostic headers in responses." onChange={(v) => set("set_karna_headers", v)} />
          <Toggle label="Private debug" value={value.private_debug} disabled={disabled} description="Enable verbose private engine diagnostics." onChange={(v) => set("private_debug", v)} />
        </div>
        <div className="service-config-grid">
          <Field label="Audit log path"><TextInput value={value.auditlog_path} disabled={disabled} onChange={(v) => set("auditlog_path", v)} /></Field>
          <Field label="Audit format"><select className="input" value={value.auditlog_format} disabled={disabled} onChange={(event) => set("auditlog_format", event.target.value)}><option value="v2">v2 · structured</option><option value="v1">v1 · legacy</option></select></Field>
        </div>
      </Section>
    </div>
  );
}

export function RedisSettings({ value, onChange, disabled, password, onPasswordChange, clearPassword, onClearPasswordChange }) {
  const set = (key, next) => onChange({ ...value, [key]: next });
  return (
    <Section icon="server" title="Redis" description="Counters and optional shared-state inspection. The password is write-only and never returned by the dashboard API.">
      <div className="service-config-toggle-grid">
        <Toggle label="Redis inspection" value={value.redis_inspect_enabled} disabled={disabled} description="Allow redis.* variables and Redis membership operators." onChange={(v) => set("redis_inspect_enabled", v)} />
      </div>
      <div className="service-config-grid">
        <Field label="Host"><TextInput value={value.redis_host} disabled={disabled} onChange={(v) => set("redis_host", v)} /></Field>
        <Field label="Port"><TextInput type="number" min={1} max={65535} value={value.redis_port} disabled={disabled} onChange={(v) => set("redis_port", v)} /></Field>
        <Field label="Database"><TextInput type="number" min={0} value={value.redis_database} disabled={disabled} onChange={(v) => set("redis_database", v)} /></Field>
        <Field label="Read timeout (ms)"><TextInput type="number" min={1} value={value.redis_timeout_ms} disabled={disabled} onChange={(v) => set("redis_timeout_ms", v)} /></Field>
        <Field label="Keepalive pool size"><TextInput type="number" min={1} value={value.redis_keepalive_pool_size} disabled={disabled} onChange={(v) => set("redis_keepalive_pool_size", v)} /></Field>
        <Field label="Keepalive idle (ms)"><TextInput type="number" min={0} value={value.redis_keepalive_idle_ms} disabled={disabled} onChange={(v) => set("redis_keepalive_idle_ms", v)} /></Field>
        <Field label="On read error"><select className="input" value={value.redis_on_error} disabled={disabled} onChange={(event) => set("redis_on_error", event.target.value)}><option value="skip">skip</option><option value="fail_open">fail open</option><option value="fail_closed">fail closed</option></select></Field>
        <Field label="Password" description={value.redis_password_configured ? "A password is configured. Leave blank to keep it." : "Optional. Stored only in Kong."}>
          <TextInput type="password" value={password} disabled={disabled || clearPassword} placeholder={value.redis_password_configured ? "Configured" : "Not configured"} onChange={onPasswordChange} />
          {value.redis_password_configured && !disabled && <label className="service-config-check"><input type="checkbox" checked={clearPassword} onChange={(event) => onClearPasswordChange(event.target.checked)} />Clear stored password</label>}
        </Field>
      </div>
    </Section>
  );
}

export function RulesBoundary({ value, disabled, onToggle }) {
  return (
    <section className="service-rules-boundary">
      <Icon name="doc" size={17} />
      <div>
        <strong>Rules have a dedicated workspace</strong>
        <span>Custom JSON, SecLang rules, exclusions, and response/action overrides remain in Rules so this modal only manages service policy.</span>
      </div>
      <div className="service-rules-counts">
        <span><b>{value.rules_request_count || 0}</b> native</span>
        <span><b>{value.custom_secrules_count || 0}</b> SecLang</span>
        {disabled ? (
          <span className={`tag dot ${value.local_rules_enabled ? "success" : ""}`}>{value.local_rules_enabled ? "enabled" : "off"}</span>
        ) : (
          <button type="button" className={`switch${value.local_rules_enabled ? " on" : ""}`}
            aria-label="Enable local rules" aria-pressed={value.local_rules_enabled}
            onClick={onToggle} />
        )}
      </div>
    </section>
  );
}
