import React from "react";
import { Icon } from "../components/icons.jsx";
import { Modal } from "../components/modal.jsx";
import { EmptyRow } from "../components/states.jsx";
import { MODE } from "../data/index.js";
import { api } from "../data/api.js";

const ACTION_LABEL = {
  sessions_revoked: "Signed out everywhere",
  password_changed: "Password changed",
  engine_update: "Engine update",
  action_override_add: "Action override added",
  action_override_update: "Action override updated",
  action_override_remove: "Action override removed",
  response_override_add: "Response override added",
  response_override_update: "Response override updated",
  response_override_remove: "Response override removed",
  service_create: "Service created",
  service_update: "Service updated",
  service_delete: "Service deleted",
  rule_add: "Rule added",
  rule_update: "Rule updated",
  rule_remove: "Rule removed",
  logs_ttl_update: "Log TTL changed",
  logs_purge: "Logs purged",
  kong_connection_save: "Kong connection saved",
  kong_connection_activate: "Kong connection activated",
  kong_connection_remove: "Kong connection removed",
  kong_connection_update: "Kong connection changed",
  setup_completed: "Setup completed",
  assistant_action_execute: "Assistant change authorized",
  assistant_action_reject: "Assistant change rejected",
  assistant_kong_request: "Kong changed by the assistant",
  setup_skipped: "Setup skipped",
};

const SORT_VALUE = {
  time: (change) => Number(change.ts || 0),
  actor: (change) => change.actor || "",
  action: (change) => ACTION_LABEL[change.action] || change.action || "",
  service: (change) => change.service || "",
};
const DEFAULT_SORT = { time: "desc", actor: "asc", action: "asc", service: "asc" };

function labelOf(action) {
  return ACTION_LABEL[action] || String(action || "Unknown change").replaceAll("_", " ");
}

function fmtWhen(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function shortValue(value) {
  if (value == null) return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function changeSummary(change) {
  if (change.before || change.after) {
    const keys = [...new Set([...Object.keys(change.before || {}), ...Object.keys(change.after || {})])];
    if (keys.length === 1) {
      const key = keys[0];
      return `${key}: ${shortValue(change.before?.[key])} → ${shortValue(change.after?.[key])}`;
    }
    if (keys.length) return `${keys.length} fields · ${keys.slice(0, 3).join(", ")}${keys.length > 3 ? "…" : ""}`;
  }
  if (change.detail?.selector) return `selector ${JSON.stringify(change.detail.selector)}`;
  if (change.detail?.id) return `${change.detail.kind || "rule"} · ${change.detail.id}`;
  if (change.detail?.index != null) return `entry index ${change.detail.index}`;
  if (change.detail) return JSON.stringify(change.detail);
  return "No additional context";
}

function SortHeader({ id, label, sort, onSort }) {
  const active = sort.key === id;
  return (
    <th aria-sort={active ? (sort.direction === "asc" ? "ascending" : "descending") : "none"}>
      <button className={`sort-head${active ? " active" : ""}`} onClick={() => onSort(id)}>
        {label}<Icon name={active ? (sort.direction === "asc" ? "up" : "down") : "chevd"} size={11} />
      </button>
    </th>
  );
}

function JsonBlock({ value, empty }) {
  if (value == null || (typeof value === "object" && Object.keys(value).length === 0)) {
    return <div className="audit-json-empty">{empty}</div>;
  }
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

function ChangeDetail({ change, onClose }) {
  if (!change) return null;
  const before = change.before || null;
  const after = change.after || null;
  const diffKeys = [...new Set([...Object.keys(before || {}), ...Object.keys(after || {})])];
  return (
    <Modal open={!!change} onClose={onClose}
      title={<div><div className="ct" style={{ fontSize: 16 }}>{labelOf(change.action)}</div><div className="cs" style={{ marginTop: 3 }}>Recorded configuration change</div></div>}
      foot={<button className="btn" onClick={onClose}>Close</button>}>
      <div className="audit-detail">
        <div className="audit-detail-meta">
          <div><span>Time</span><strong className="mono">{fmtWhen(change.ts)}</strong></div>
          <div><span>Actor</span><strong>{change.actor || "—"}</strong></div>
          <div><span>Service</span><strong>{change.service || "—"}</strong></div>
          <div><span>Plugin</span><strong className="mono">{change.plugin_id || "—"}</strong></div>
        </div>

        {diffKeys.length > 0 && (
          <section>
            <div className="sec-h">Field changes</div>
            <div className="audit-field-diff">
              {diffKeys.map((key) => (
                <div key={key} className="audit-field-row">
                  <span className="mono">{key}</span><code>{shortValue(before?.[key])}</code>
                  <Icon name="arrowr" size={14} /><code>{shortValue(after?.[key])}</code>
                </div>
              ))}
            </div>
          </section>
        )}

        <section>
          <div className="sec-h">Before → after</div>
          <div className="audit-json-diff">
            <div><div className="audit-json-label before">Before</div><JsonBlock value={before} empty="No previous snapshot" /></div>
            <div className="audit-diff-arrow"><Icon name="arrowr" size={16} /></div>
            <div><div className="audit-json-label after">After</div><JsonBlock value={after} empty="No resulting snapshot" /></div>
          </div>
        </section>

        <section>
          <div className="sec-h">Context</div>
          <div className="audit-context"><JsonBlock value={change.detail} empty="No additional context recorded" /></div>
        </section>
      </div>
    </Modal>
  );
}

export default function Audit({ data }) {
  const [changes, setChanges] = React.useState(data.changes || []);
  const [loading, setLoading] = React.useState(MODE === "live");
  const [error, setError] = React.useState("");
  const [selected, setSelected] = React.useState(null);
  const [query, setQuery] = React.useState("");
  const [action, setAction] = React.useState("all");
  const [service, setService] = React.useState("all");
  const [actor, setActor] = React.useState("all");
  const [period, setPeriod] = React.useState("all");
  const [sort, setSort] = React.useState({ key: "time", direction: "desc" });

  const load = React.useCallback(async () => {
    if (MODE !== "live") return;
    setLoading(true); setError("");
    try {
      const response = await api.changes();
      setChanges(response.changes || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const actions = React.useMemo(() => [...new Set(changes.map((c) => c.action).filter(Boolean))].sort((a, b) => labelOf(a).localeCompare(labelOf(b))), [changes]);
  const services = React.useMemo(() => [...new Set(changes.map((c) => c.service).filter((v) => v && v !== "—"))].sort(), [changes]);
  const actors = React.useMemo(() => [...new Set(changes.map((c) => c.actor).filter(Boolean))].sort(), [changes]);

  const visible = React.useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    const cutoff = period === "all" ? 0 : Math.floor(Date.now() / 1000) - Number(period) * 86400;
    const filtered = changes.filter((change) => {
      if (action !== "all" && change.action !== action) return false;
      if (service !== "all" && change.service !== service) return false;
      if (actor !== "all" && change.actor !== actor) return false;
      if (cutoff && Number(change.ts || 0) < cutoff) return false;
      if (!needle) return true;
      return [labelOf(change.action), change.action, change.actor, change.service, change.plugin_id,
        changeSummary(change), JSON.stringify(change.detail || {}), JSON.stringify(change.before || {}), JSON.stringify(change.after || {})]
        .filter(Boolean).join(" ").toLocaleLowerCase().includes(needle);
    });
    const valueOf = SORT_VALUE[sort.key] || SORT_VALUE.time;
    return [...filtered].sort((a, b) => {
      const av = valueOf(a), bv = valueOf(b);
      const compared = typeof av === "number" && typeof bv === "number"
        ? av - bv
        : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: "base" });
      return sort.direction === "asc" ? compared : -compared;
    });
  }, [changes, query, action, service, actor, period, sort]);

  const filtersActive = query.trim() || action !== "all" || service !== "all" || actor !== "all" || period !== "all";
  const clearFilters = () => { setQuery(""); setAction("all"); setService("all"); setActor("all"); setPeriod("all"); };
  const changeSort = (key) => setSort((current) => current.key === key
    ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
    : { key, direction: DEFAULT_SORT[key] || "asc" });

  return (
    <div className="view-inner">
      <div className="page-head audit-page-head">
        <div className="ph-top">
          <div>
            <span className="eyebrow">Governance · configuration history</span>
            <h1>Audit</h1>
            <p className="lead">Inspect every configuration change made from this console, who made it, and the exact values before and after.</p>
          </div>
          <button className="btn sm" disabled={loading || MODE !== "live"} onClick={load}><Icon name="refresh" size={13} />{loading ? "Refreshing…" : "Refresh"}</button>
        </div>
      </div>

      <div className="audit-ledger-strip">
        <div><span className="audit-ledger-count mono">{changes.length}</span><span>recorded changes</span></div>
        <div><Icon name="shield" size={14} /><span>Authenticated console actions</span></div>
        <div><Icon name="clock" size={14} /><span>Newest entries first</span></div>
      </div>

      <div className="card flush audit-table-card">
        <div className="filter-bar audit-filter-bar">
          <label className="service-search audit-search" htmlFor="audit-search">
            <Icon name="search" size={15} />
            <input id="audit-search" value={query} onChange={(e) => setQuery(e.target.value)}
              placeholder="Search actor, service, action or changed value…" autoComplete="off" />
          </label>
          <select className="input sel" value={action} onChange={(e) => setAction(e.target.value)} aria-label="Filter by action">
            <option value="all">All actions</option>
            {actions.map((value) => <option key={value} value={value}>{labelOf(value)}</option>)}
          </select>
          <select className="input sel" value={service} onChange={(e) => setService(e.target.value)} aria-label="Filter by service">
            <option value="all">All services</option>
            {services.map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <select className="input sel" value={actor} onChange={(e) => setActor(e.target.value)} aria-label="Filter by actor">
            <option value="all">All actors</option>
            {actors.map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <select className="input sel" value={period} onChange={(e) => setPeriod(e.target.value)} aria-label="Filter by time period">
            <option value="all">Any time</option><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option>
          </select>
          {filtersActive && <button className="btn ghost sm" onClick={clearFilters}><Icon name="x" size={12} />Clear</button>}
          <span className="service-result-count mono">{visible.length} of {changes.length}</span>
        </div>

        {error && <div className="audit-error"><span>{error}</span><button className="btn sm" onClick={load}>Retry</button></div>}
        <div className="audit-table-scroll">
          <table className="tbl audit-table">
            <thead><tr>
              <SortHeader id="time" label="Time" sort={sort} onSort={changeSort} />
              <SortHeader id="actor" label="Actor" sort={sort} onSort={changeSort} />
              <SortHeader id="action" label="Action" sort={sort} onSort={changeSort} />
              <SortHeader id="service" label="Service" sort={sort} onSort={changeSort} />
              <th>Change summary</th><th><span className="sr-only">Inspect</span></th>
            </tr></thead>
            <tbody>
              {!loading && visible.length === 0 && <EmptyRow colSpan={6} label={changes.length ? "No changes match the current filters" : "No configuration changes recorded yet"} />}
              {loading && changes.length === 0 && <EmptyRow colSpan={6} label="Loading audit history…" />}
              {visible.map((change, index) => (
                <tr key={`${change.ts || 0}-${change.action || "change"}-${index}`} className="clickable" onClick={() => setSelected(change)}>
                  <td className="mono audit-time">{fmtWhen(change.ts)}</td>
                  <td className="audit-actor" title={change.actor}>{change.actor || "—"}</td>
                  <td><span className="tag accent">{labelOf(change.action)}</span></td>
                  <td><span className={change.service && change.service !== "—" ? "" : "hint"}>{change.service || "—"}</span></td>
                  <td><div className="audit-summary" title={changeSummary(change)}>{changeSummary(change)}</div></td>
                  <td className="right"><button className="btn sm" onClick={(event) => { event.stopPropagation(); setSelected(change); }}><Icon name="doc" size={13} />Inspect</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <ChangeDetail change={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
