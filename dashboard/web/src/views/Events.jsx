import React from "react";
import { Icon } from "../components/icons.jsx";
import { TrafficScene } from "../components/TrafficScene.jsx";
import { Modal } from "../components/modal.jsx";
import { ActionTag, CatTag, Flag, CopyBtn } from "../components/ui.jsx";
import { EmptyRow } from "../components/states.jsx";
import { clockOf, whenOf, dateOf, primaryMatch, eventCategory, eventDisposition } from "../data/index.js";
import { categoryMeta } from "../data/categories.js";
import { api } from "../data/api.js";
import { useMutation } from "../data/hooks.js";
import { eventExclusionDraft } from "../data/exclusions.js";

const ENFORCED = new Set(["blocked", "rate_limited", "sanitized"]);
const MATCH_ACTION_CLS = { block: "danger", rate_limited: "danger", sanitized: "accent", detect: "warning", log: "info" };
const PAGE_SIZE = 50;
const SENSITIVE_NAME_RE = /(?:^|[-_.:[\]])(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|secret|token|api[-_]?key|session|credential)(?:$|[-_.:[\]])/i;
const HEADER_PRIORITY = ["host", "content-type", "content-length", "user-agent", "origin", "referer", "accept", "accept-language"];

// Karna's audit log serialises an empty Lua array (tags / matched_parts /
// external_matches with no entries) as JSON `{}`, not `[]`. `{} || []` is
// truthy, so the old `(x || [])` guard let an object through and `.map` /
// `.find` on it threw, blanking the whole view. Coerce to a real array.
const asArray = (v) => (Array.isArray(v) ? v : []);

function isSensitiveName(name) {
  return SENSITIVE_NAME_RE.test(String(name || ""));
}

function redactUri(uri) {
  if (!uri || !uri.includes("?")) return uri || "—";
  try {
    const parsed = new URL(uri, "http://karna.local");
    for (const key of [...parsed.searchParams.keys()]) {
      if (isSensitiveName(key)) parsed.searchParams.set(key, "[REDACTED]");
    }
    return parsed.pathname + (parsed.search ? parsed.search : "");
  } catch {
    return uri;
  }
}

function redactHeaders(headers = {}) {
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [
    name,
    isSensitiveName(name) ? "[REDACTED]" : value,
  ]));
}

function redactObject(value, key = "") {
  if (isSensitiveName(key)) return "[REDACTED]";
  if (Array.isArray(value)) return value.map((item) => redactObject(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [
      childKey,
      redactObject(childValue, childKey),
    ]));
  }
  return value;
}

function redactMatchedPart(part = {}) {
  return { ...part, value: isSensitiveName(part.on) ? "[REDACTED]" : part.value };
}

function redactEvent(ev) {
  const safe = redactObject(ev);
  return {
    ...safe,
    request: {
      ...(safe.request || {}),
      uri: redactUri(safe.request?.uri),
      headers: redactHeaders(safe.request?.headers),
    },
    response: {
      ...(safe.response || {}),
      headers: redactHeaders(safe.response?.headers),
    },
    matches: (safe.matches || []).map((match) => ({
      ...match,
      matched_parts: asArray(match.matched_parts).map(redactMatchedPart),
    })),
  };
}

function requestPath(uri) {
  return String(uri || "—").split("?", 1)[0] || "/";
}

function queryParams(uri) {
  if (!uri || !uri.includes("?")) return [];
  try {
    const parsed = new URL(uri, "http://karna.local");
    return [...parsed.searchParams.entries()].map(([name, value]) => ({
      name,
      value: isSensitiveName(name) ? "[REDACTED]" : value,
    }));
  } catch {
    return [];
  }
}

function friendlyTarget(target = "") {
  const suffix = target.includes(":") ? target.slice(target.lastIndexOf(":") + 1) : "";
  if (target.startsWith("request.body.urlencode")) return { area: "Form body", name: suffix || "body field" };
  if (target.startsWith("request.body.json")) return { area: "JSON body", name: suffix || "JSON value" };
  if (target.startsWith("request.body.multipart")) return { area: "Multipart body", name: suffix || "part" };
  if (target.startsWith("request.query") || target.startsWith("request.arg")) return { area: "Query / argument", name: suffix || "parameter" };
  if (target.startsWith("request.header")) return { area: "Request header", name: suffix || "header" };
  if (target.includes("uri") || target.includes("path")) return { area: "Request path", name: "URI" };
  if (target.startsWith("mcp.")) return { area: "MCP payload", name: target.slice(4) };
  return { area: "Request input", name: target || "matched value" };
}

function ruleParanoia(match, fallback) {
  const tag = asArray(match.tags).find((item) => /^paranoia-level\/\d+$/.test(item));
  return tag ? `PL${tag.split("/")[1]}` : `PL${fallback || 1}`;
}

function actionExplanation(match, ev) {
  if (match.action === "block") {
    const upstream = ev.response?.latencies?.upstream ?? ev.response?.latency_ms;
    return upstream === 0
      ? `Karna stopped the request at the gateway and returned HTTP ${ev.response.status}; the upstream was not contacted.`
      : `Karna returned HTTP ${ev.response.status} after this rule matched.`;
  }
  if (match.action === "sanitized") return "Karna removed the matched characters, then forwarded the modified request upstream.";
  if (match.action === "rate_limited") return `Karna applied the rate limit and returned HTTP ${ev.response.status}.`;
  if (match.action === "detect") return "Karna recorded the match in detection mode and allowed the request to continue.";
  return "Karna recorded the match without terminating the request.";
}

const blockIpRule = (ip) => ({
  id: `local_block_${ip.replace(/[.:]/g, "_")}`,
  phase: "access",
  message: `Block ${ip} (added from the console)`,
  conditions: [{ op: "ipMatch", variables: ["request.remote_addr"], value: ip }],
  action: { fixed_response: { status_code: 403 } },
});

/* Copy-paste snippets for read-only mode (same actions, manual application). */
function buildSnippet(kind, ev) {
  const m = primaryMatch(ev) || {};
  if (kind === "allow") {
    return { title: `Add to config.rule_action_overrides for "${ev.service.name}"`,
      json: { selector: { ids: [String(m.rule_id)] }, action: { type: "passthrough" } } };
  }
  if (kind === "sanitize") {
    return { title: `Add to config.rule_action_overrides for "${ev.service.name}"`,
      json: { selector: { ids: [String(m.rule_id)] }, action: { type: "fix", remove_chars_pattern: "[<>\"'&;|`$()]" } } };
  }
  return { title: `Add to config.rules_request for "${ev.service.name}"`, json: blockIpRule(ev.client.ip) };
}

function exportNdjson(rows) {
  const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
  const blob = new Blob(rows.map((e) => JSON.stringify(redactEvent(e)) + "\n"), { type: "application/x-ndjson" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `karna-events-${stamp}.ndjson`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Events({ data, param, nav, navReplace, writable, refresh, openRuleDraft }) {
  // Local audit files may belong to a different Kong than the connected one,
  // or use the legacy format. Neither is a usable event for this view.
  const serviceIds = new Set(asArray(data.services).map((service) => service.id));
  const events = asArray(data.events).filter((event) =>
    event && serviceIds.has(event.service?.id) &&
    typeof event.request_id === "string" &&
    typeof event.service?.name === "string" &&
    typeof event.request?.uri === "string" &&
    event.client && event.server && event.response && event.engine &&
    Array.isArray(event.matches)
  );
  const [q, setQ] = React.useState("");
  const [svcF, setSvcF] = React.useState("all");
  const [catF, setCatF] = React.useState("all");
  const [actF, setActF] = React.useState("all");
  const [page, setPage] = React.useState(0);

  const openId = param || null;
  const openEvent = (id) => nav("events", id);
  const closeEvent = () => navReplace("events");

  // Facet options derived from the data actually present.
  const svcOptions = [...new Set(events.map((e) => e.service.name))].sort();
  const catOptions = [...new Set(events.map((e) => eventCategory(e)))].sort();

  const rows = events.filter((e) => {
    const disp = eventDisposition(e);
    if (actF === "enforced" && !ENFORCED.has(disp)) return false;
    if (actF === "detected" && !(disp === "detected" || disp === "observed")) return false;
    if (svcF !== "all" && e.service.name !== svcF) return false;
    if (catF !== "all" && eventCategory(e) !== catF) return false;
    if (q) {
      const m = primaryMatch(e);
      const hay = (e.client.ip + " " + e.request.uri + " " + (m?.rule_id || "") + " " + e.service.name).toLowerCase();
      if (!hay.includes(q.toLowerCase())) return false;
    }
    return true;
  });

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const pageClamped = Math.min(page, pages - 1);
  const visible = rows.slice(pageClamped * PAGE_SIZE, (pageClamped + 1) * PAGE_SIZE);
  const filtersActive = q || svcF !== "all" || catF !== "all" || actF !== "all";

  const setFilter = (fn) => { fn(); setPage(0); };
  const clearFilters = () => { setQ(""); setSvcF("all"); setCatF("all"); setActF("all"); setPage(0); };
  // Pivot from the event modal: focus the list on one IP or one rule.
  const pivot = (needle) => { clearFilters(); setQ(needle); closeEvent(); };

  const ev = events.find((e) => e.request_id === openId) || null;
  const pluginId = ev ? (data.services.find((s) => s.id === ev.service.id) || {}).plugin_id : null;

  return (
    <div className="view-inner">
      <div className="page-head">
        <div className="ph-top">
          <div>
            <span className="eyebrow">Operations · audit trail</span>
            <h1>Events</h1>
            <p className="lead">Every request Karna inspected: who sent it, which rules matched, and the action taken. One audit entry per request.</p>
          </div>
          <div className="row">
            <span className="hint mono">updated {events[0] ? clockOf(events[0].timestamp) : "—"}</span>
            {writable && <button className="btn" onClick={refresh}><Icon name="refresh" size={15} />Refresh</button>}
            <button className="btn" onClick={() => exportNdjson(rows)} disabled={rows.length === 0}
              title="Download the filtered events as NDJSON (audit log v2)">
              <Icon name="dl" size={15} />Export NDJSON
            </button>
          </div>
        </div>
      </div>

      <div style={{ marginBottom: "var(--gap)" }}>
        {events.length > 0 && <TrafficScene data={data} compact />}
      </div>

      <div className="card filter-bar" style={{ marginBottom: "var(--gap)" }}>
        <div className="search" style={{ width: 250 }}>
          <Icon name="search" size={15} />
          <input placeholder="IP, path, rule id…" value={q} aria-label="Filter events"
            onChange={(e) => setFilter(() => setQ(e.target.value))} />
        </div>
        <select className="input sel" value={svcF} aria-label="Filter by service"
          onChange={(e) => setFilter(() => setSvcF(e.target.value))}>
          <option value="all">All services</option>
          {svcOptions.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input sel" value={catF} aria-label="Filter by category"
          onChange={(e) => setFilter(() => setCatF(e.target.value))}>
          <option value="all">All categories</option>
          {catOptions.map((c) => <option key={c} value={c}>{categoryMeta(c).name}</option>)}
        </select>
        <div className="seg" title="Enforced = blocked, sanitized, or rate-limited">
          {[["all", "All"], ["enforced", "Enforced"], ["detected", "Detected"]].map(([v, l]) => (
            <button key={v} className={actF === v ? "on" : ""} onClick={() => setFilter(() => setActF(v))}>{l}</button>
          ))}
        </div>
        {filtersActive && (
          <button className="btn ghost sm" onClick={clearFilters}><Icon name="x" size={13} />Clear</button>
        )}
        <span className="spacer" style={{ flex: 1 }} />
        <span className="hint mono">{rows.length} {rows.length === 1 ? "event" : "events"}</span>
      </div>

      <div className="card flush">
        <table className="tbl">
          <thead><tr><th>Time</th><th>Service</th><th>Source</th><th>Request</th><th>Rule</th><th>Category</th><th className="right">Action</th></tr></thead>
          <tbody>
            {visible.length === 0 && (
              <EmptyRow colSpan={7} label={filtersActive ? "No events match the filters" : "No events available"} />
            )}
            {visible.map((e) => {
              const m = primaryMatch(e);
              const cc = e.enrichment?.geoip?.country_code;
              return (
                <tr key={e.request_id} className="clickable" tabIndex={0} onClick={() => openEvent(e.request_id)}
                  onKeyDown={(ke) => { if (ke.key === "Enter" || ke.key === " ") { ke.preventDefault(); openEvent(e.request_id); } }}>
                  <td className="mono" style={{ color: "var(--fg-3)", whiteSpace: "nowrap" }}>{whenOf(e.timestamp)}</td>
                  <td style={{ whiteSpace: "nowrap" }}>{e.service.name}</td>
                  <td><span className="row" style={{ gap: 6 }}><Flag cc={cc} /><span className="mono" style={{ fontSize: 11.5 }}>{e.client.ip}</span></span></td>
                  <td><span className="mono" style={{ color: "var(--fg-2)", fontSize: 11.5 }} title={`${e.request.method} ${e.request.uri}`}>
                    {e.request.method} {e.request.uri.length > 48 ? e.request.uri.slice(0, 48) + "…" : e.request.uri}</span></td>
                  <td className="mono" style={{ color: "var(--accent)" }}>{m?.rule_id}</td>
                  <td><CatTag cat={eventCategory(e)} /></td>
                  <td className="right"><ActionTag disposition={eventDisposition(e)} /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {pages > 1 && (
          <div className="pager">
            <button className="btn ghost sm" disabled={pageClamped === 0} onClick={() => setPage(pageClamped - 1)}>← Prev</button>
            <span className="hint mono">
              {pageClamped * PAGE_SIZE + 1}–{Math.min(rows.length, (pageClamped + 1) * PAGE_SIZE)} of {rows.length}
            </span>
            <button className="btn ghost sm" disabled={pageClamped >= pages - 1} onClick={() => setPage(pageClamped + 1)}>Next →</button>
          </div>
        )}
      </div>

      <EventModal ev={ev} pluginId={pluginId} writable={writable} refresh={refresh}
        onClose={closeEvent} onPivot={pivot}
        onCreateExclusion={(match) => openRuleDraft(eventExclusionDraft(ev, match, pluginId))} />
    </div>
  );
}

function DetailsTab({ ev, onPivot }) {
  const safe = redactEvent(ev);
  const h = safe.request.headers || {};
  const geo = safe.enrichment?.geoip;
  const asn = safe.enrichment?.asn;
  const lat = safe.response.latencies || {};
  const disposition = eventDisposition(safe);
  const firstMatch = primaryMatch(safe);
  const firstPart = firstMatch?.matched_parts?.[0];
  const firstTarget = friendlyTarget(firstPart?.on);
  const params = queryParams(safe.request.uri);
  const headerEntries = Object.entries(h).sort(([a], [b]) => {
    const ai = HEADER_PRIORITY.indexOf(a.toLowerCase());
    const bi = HEADER_PRIORITY.indexOf(b.toLowerCase());
    if (ai >= 0 || bi >= 0) return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi);
    return a.localeCompare(b);
  });
  const requestCopy = `${safe.request.method} ${safe.request.uri} HTTP/${safe.request.http_version}`;
  const blockedBeforeUpstream = disposition === "blocked"
    && (lat.upstream ?? safe.response.latency_ms) === 0;

  return (
    <div className="event-dossier">
      <section className={`event-verdict event-verdict-${disposition}`}>
        <div className="event-verdict-mark"><Icon name={disposition === "blocked" ? "shield" : "pulse"} size={24} /></div>
        <div className="event-verdict-copy">
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <ActionTag disposition={disposition} />
            <span className="event-verdict-stage">{blockedBeforeUpstream ? "stopped before upstream" : "request inspected"}</span>
          </div>
          <h2><span className="mono">{safe.request.method}</span> {requestPath(safe.request.uri)}</h2>
          <p>
            {firstMatch
              ? <>Karna returned HTTP {safe.response.status} because rule <strong className="mono">{firstMatch.rule_id}</strong> matched <strong>{firstTarget.name}</strong> in the {firstTarget.area.toLowerCase()}.</>
              : <>Karna recorded this request without a rule match.</>}
          </p>
        </div>
        <div className="event-status-code"><span>HTTP</span><strong>{safe.response.status}</strong></div>
      </section>

      <section className="event-facts" aria-label="Event summary">
        <div><span>Service</span><strong>{safe.service.name}</strong></div>
        <div><span>Source</span><strong className="mono">{safe.client.ip}{safe.client.port ? `:${safe.client.port}` : ""}</strong></div>
        <div><span>Gateway</span><strong className="mono">{safe.server.ip}:{safe.server.port}</strong></div>
        <div><span>Observed</span><strong>{dateOf(safe.timestamp).toLocaleString("en-US")}</strong></div>
        <div><span>Total latency</span><strong className="mono">{lat.total ?? "—"} ms</strong></div>
        <div><span>Engine</span><strong className="mono">{safe.engine.name} {safe.engine.version} · PL{safe.engine.paranoia_level}</strong></div>
      </section>

      <section className="event-section event-request-envelope">
        <div className="event-section-head">
          <div><span className="eyebrow">Full request context</span><h3>Request envelope</h3></div>
          <CopyBtn text={requestCopy} label="Copy request line" />
        </div>

        <div className="event-request-line">
          <span className="event-method">{safe.request.method}</span>
          <code>{safe.request.uri}</code>
          <span className="mono">HTTP/{safe.request.http_version}</span>
        </div>

        <div className="event-request-grid">
          <div><span>Host</span><strong className="mono">{h.host || "—"}</strong></div>
          <div><span>Content type</span><strong className="mono">{h["content-type"] || "—"}</strong></div>
          <div><span>Content length</span><strong className="mono">{h["content-length"] ? `${h["content-length"]} bytes` : "—"}</strong></div>
          <div><span>User agent</span><strong className="mono" title={h["user-agent"]}>{h["user-agent"] || "—"}</strong></div>
        </div>

        {params.length > 0 && (
          <div className="event-request-subsection">
            <h4>Query parameters <span>{params.length}</span></h4>
            <div className="event-param-list">
              {params.map((param, index) => (
                <div key={`${param.name}-${index}`}><code>{param.name}</code><span className="mono">{param.value}</span></div>
              ))}
            </div>
          </div>
        )}

        <div className="event-request-subsection">
          <h4>Request headers <span>{headerEntries.length}</span></h4>
          <div className="event-header-table">
            {headerEntries.map(([name, value]) => (
              <div key={name}><code>{name}</code><span className="mono">{String(value)}</span></div>
            ))}
            {headerEntries.length === 0 && <div className="event-inline-empty">No request headers were recorded.</div>}
          </div>
        </div>

        <div className="event-body-notice">
          <Icon name="shield" size={16} />
          <div><strong>Request body is not retained</strong><span>The audit log stores only matched values, capped by Karna, so passwords and application payloads are not archived in full.</span></div>
        </div>
      </section>

      <section className="event-section">
        <div className="event-section-head">
          <div><span className="eyebrow">Why · where · how</span><h3>Decision path</h3></div>
          <span className="tag">{safe.matches.length} matched {safe.matches.length === 1 ? "rule" : "rules"}</span>
        </div>

        {safe.matches.length === 0 && <div className="event-inline-empty">No rule matched. This request was retained as part of the audit trail.</div>}
        <div className="event-rule-list">
          {safe.matches.map((match, index) => (
            <article className="event-rule-card" key={`${match.rule_id}-${index}`}>
              <div className="event-rule-head">
                <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                  <strong className="mono">Rule {match.rule_id}</strong>
                  <span className={"tag " + (MATCH_ACTION_CLS[match.action] || "")}>{match.action}</span>
                  <CatTag cat={eventCategory({ matches: [match] })} />
                  <span className="tag plain mono">{ruleParanoia(match, safe.engine.paranoia_level)}</span>
                </div>
                <button className="btn ghost sm" onClick={() => onPivot(String(match.rule_id))} title="Show all events matching this rule">
                  <Icon name="filter" size={12} />Same rule
                </button>
              </div>

              <div className="event-decision-trace">
                <div className="event-decision-step">
                  <span className="event-step-number">1</span>
                  <div><span>Observed input</span>
                    {asArray(match.matched_parts).length > 0
                      ? asArray(match.matched_parts).map((part, partIndex) => {
                          const target = friendlyTarget(part.on);
                          return <div className="event-observed-part" key={partIndex}>
                            <strong>{target.area} · {target.name}</strong>
                            <code title={part.on}>{part.value || "—"}</code>
                          </div>;
                        })
                      : <p>No matched value was included in this audit entry.</p>}
                  </div>
                </div>
                <div className="event-decision-step">
                  <span className="event-step-number">2</span>
                  <div><span>Rule matched</span><strong>{match.message || "Rule condition matched the request."}</strong>
                    <details><summary>Rule metadata · {asArray(match.tags).length} tags</summary>
                      <div className="event-rule-tags">{asArray(match.tags).map((tag) => <span className="tag plain" key={tag}>{tag}</span>)}</div>
                    </details>
                  </div>
                </div>
                <div className="event-decision-step outcome">
                  <span className="event-step-number">3</span>
                  <div><span>Action applied</span><strong>{actionExplanation(match, safe)}</strong></div>
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="event-section">
        <div className="event-section-head"><div><span className="eyebrow">Network & runtime</span><h3>Technical context</h3></div></div>
        <div className="event-context-grid">
          <div className="event-context-card">
            <h4>Client</h4>
            <dl>
              <dt>Source IP</dt><dd className="mono">{safe.client.ip}:{safe.client.port}</dd>
              {geo && <><dt>Location</dt><dd><Flag cc={geo.country_code} /> {geo.country_name}{geo.continent_name ? ` · ${geo.continent_name}` : ""}</dd></>}
              {asn && <><dt>Network</dt><dd className="mono">AS{asn.id} · {asn.org}</dd></>}
            </dl>
            <div className="row" style={{ gap: 7, marginTop: 12 }}>
              <CopyBtn text={safe.client.ip} label="Copy source IP" />
              <button className="btn ghost sm" onClick={() => onPivot(safe.client.ip)}><Icon name="filter" size={12} />Same IP</button>
            </div>
          </div>
          <div className="event-context-card">
            <h4>Response & latency</h4>
            <dl>
              <dt>Status</dt><dd className="mono">HTTP {safe.response.status}</dd>
              <dt>Kong</dt><dd className="mono">{lat.kong ?? "—"} ms</dd>
              <dt>Upstream</dt><dd className="mono">{lat.upstream ?? safe.response.latency_ms ?? "—"} ms</dd>
              <dt>Total</dt><dd className="mono">{lat.total ?? "—"} ms</dd>
            </dl>
          </div>
          <div className="event-context-card">
            <h4>Engine & trace</h4>
            <dl>
              <dt>Engine</dt><dd className="mono">{safe.engine.name} {safe.engine.version}</dd>
              <dt>Mode</dt><dd>{safe.engine.mode}</dd>
              <dt>Paranoia</dt><dd className="mono">PL{safe.engine.paranoia_level}</dd>
              <dt>Request ID</dt><dd className="mono event-truncate" title={safe.request_id}>{safe.request_id}</dd>
            </dl>
            <div style={{ marginTop: 12 }}><CopyBtn text={safe.request_id} label="Copy request ID" /></div>
          </div>
        </div>
      </section>

      {safe.external_matches && safe.external_matches.length > 0 && (
        <section>
          <div className="sec-h">From sibling plugins</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {safe.external_matches.map((x, i) => (
              <div key={i} className="mono" style={{ fontSize: 11.5, color: "var(--fg-2)", background: "var(--inset)", border: "1px solid var(--border-1)", borderRadius: "var(--r-sm)", padding: "8px 10px" }}>
                <span style={{ color: "var(--info)" }}>{x.source}</span> · {x.rule_id} — {x.message}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function EventModal({ ev, pluginId, writable, refresh, onClose, onPivot, onCreateExclusion }) {
  const [tab, setTab] = React.useState("details");
  const [snippet, setSnippet] = React.useState(null);
  const { run, pending, error } = useMutation(refresh);
  React.useEffect(() => { setTab("details"); setSnippet(null); }, [ev?.request_id]);

  if (!ev) return null;
  const m = primaryMatch(ev);
  const canApply = writable && pluginId;
  const svc = ev.service.name;
  const show = (kind) => setSnippet(snippet?.kind === kind ? null : { kind, ...buildSnippet(kind, ev) });

  const applyOverride = (type) => {
    const action = type === "fix" ? { type: "fix", remove_chars_pattern: "[<>\"'&;|`$()]" } : { type: "passthrough" };
    const copy = type === "fix"
      ? {
          title: `Sanitize instead of blocking?`,
          message: `Rule ${m.rule_id} on "${svc}" will stop blocking requests. Matched characters are stripped and the request continues to the upstream.\n\nApplies immediately. You can remove the override in Rules → Overrides.`,
          confirmLabel: "Add sanitize override",
        }
      : {
          title: `Allow rule ${m.rule_id}?`,
          message: `Rule ${m.rule_id} will no longer act on "${svc}" — requests it matches go through. Matches are still written to the audit trail.\n\nThis weakens protection for this service. Applies immediately; remove it in Rules → Overrides.`,
          danger: true,
          confirmLabel: "Allow rule",
        };
    run(() => api.addOverride(pluginId, "action", { selector: { ids: [String(m.rule_id)] }, action }), copy);
  };

  const applyBlockIp = () => {
    run(() => api.addRule(pluginId, { kind: "native", rule: blockIpRule(ev.client.ip) }), {
      title: `Block ${ev.client.ip}?`,
      message: `Adds a local rule to "${svc}" that returns 403 to every request from ${ev.client.ip}.\n\nApplies immediately. Remove it in Rules → Custom rules.`,
      danger: true,
      confirmLabel: "Block this IP",
    });
  };

  const title = (
    <div className="row" style={{ gap: 10 }}>
      <span className="mono" style={{ color: "var(--accent)", fontWeight: 600 }}>{ev.request_id.slice(0, 8)}</span>
      <ActionTag disposition={eventDisposition(ev)} />
      <span className="cs">{dateOf(ev.timestamp).toLocaleString("en-US")}</span>
    </div>
  );
  const head = (
    <div className="tabs">
      <button className={tab === "details" ? "on" : ""} onClick={() => setTab("details")}>Details</button>
      <button className={tab === "raw" ? "on" : ""} onClick={() => setTab("raw")}>Raw JSON</button>
    </div>
  );
  const foot = (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <span className="hint" style={{ marginRight: 4 }}>Tune from this event:</span>
        {canApply && m ? (
          <React.Fragment>
            <button className="btn primary sm" disabled={pending} onClick={() => onCreateExclusion(m)}
              title={`Create a scoped exclusion for rule ${m.rule_id} from this event`}>Create exclusion…</button>
            <button className="btn sm" disabled={pending} onClick={() => applyOverride("passthrough")}
              title={`Stop rule ${m.rule_id} from acting on ${svc} (it still logs)`}>Allow this rule…</button>
            <button className="btn sm" disabled={pending} onClick={() => applyOverride("fix")}
              title="Strip the matched characters instead of blocking">Sanitize instead…</button>
            <button className="btn sm" disabled={pending} style={{ color: "var(--danger)" }} onClick={applyBlockIp}>Block source IP…</button>
          </React.Fragment>
        ) : (
          <React.Fragment>
            {m && <button className="btn sm" onClick={() => show("allow")}>Allow this rule</button>}
            {m && <button className="btn sm" onClick={() => show("sanitize")}>Sanitize instead</button>}
            <button className="btn sm" onClick={() => show("block")}>Block source IP</button>
          </React.Fragment>
        )}
        {error && <span className="tag danger" style={{ fontSize: 10.5 }}>{error}</span>}
      </div>
      {snippet && (
        <div>
          <div className="hint" style={{ marginBottom: 6 }}>{snippet.title} <span style={{ color: "var(--fg-4)" }}>(read-only console — apply it via the plugin config)</span></div>
          <pre className="json" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0 }}>{JSON.stringify(snippet.json, null, 2)}</pre>
          <button className="btn ghost sm" style={{ marginTop: 8 }} onClick={() => navigator.clipboard?.writeText(JSON.stringify(snippet.json))}><Icon name="copy" size={13} />Copy JSON</button>
        </div>
      )}
    </div>
  );

  return (
    <Modal open={!!ev} onClose={onClose} title={title} head={head} foot={foot} className="event-detail-modal">
      {tab === "details"
        ? <DetailsTab ev={ev} onPivot={onPivot} />
        : <pre className="json" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0 }}>{JSON.stringify(redactEvent(ev), null, 2)}</pre>}
    </Modal>
  );
}
