import React from "react";
import { Icon } from "../components/icons.jsx";
import { Modal } from "../components/modal.jsx";
import { MODE } from "../data/index.js";
import { api } from "../data/api.js";
import { AIProfilesSettings } from "../components/AIProfilesSettings.jsx";
import { useAuth } from "../auth/AuthProvider.jsx";

function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"]; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}
const fmtWhen = (iso) => (iso ? new Date(iso).toLocaleString("en-US") : "—");

/* The single admin account: change the password (revokes every other session)
 * or sign out everywhere. Sample mode has no backend, so only the text shows. */
function AccountCard() {
  const { email, changePassword, logout } = useAuth();
  const [current, setCurrent] = React.useState("");
  const [next, setNext] = React.useState("");
  const [state, setState] = React.useState({ pending: false, error: null, done: false });
  const live = MODE === "live";
  const canSave = live && current && next.length >= 10 && !state.pending;

  const save = async (e) => {
    e.preventDefault();
    if (!canSave) return;
    setState({ pending: true, error: null, done: false });
    try {
      await changePassword(current, next);
      setCurrent(""); setNext("");
      setState({ pending: false, error: null, done: true });
    } catch (err) {
      setState({ pending: false, error: err.message || "Could not change the password", done: false });
    }
  };

  return (
    <div className="card">
      <div className="row" style={{ gap: 10, marginBottom: 14 }}>
        <Icon name="key" size={16} />
        <div>
          <div style={{ fontWeight: 500, fontSize: 13.5 }}>Account</div>
          <div className="hint" style={{ marginTop: 3 }}>
            One administrator{email ? <> (<span className="mono">{email}</span>)</> : null}, created on first run; registration is then closed.
            Every configuration change is recorded on the Audit page.
          </div>
        </div>
      </div>
      {live && (
        <form onSubmit={save} className="row" style={{ gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
          <div className="field" style={{ minWidth: 220, marginBottom: 0 }}>
            <label>Current password</label>
            <input className="input" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
          </div>
          <div className="field" style={{ minWidth: 220, marginBottom: 0 }}>
            <label>New password</label>
            <input className="input" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} placeholder="at least 10 characters" />
          </div>
          <button type="submit" className="btn primary" disabled={!canSave} style={{ opacity: canSave ? 1 : 0.55 }}>
            {state.pending ? "…" : "Change password"}
          </button>
          <button type="button" className="btn" onClick={logout} title="Every session, in every browser, has to sign in again">
            Sign out everywhere
          </button>
        </form>
      )}
      {state.error && <div className="hint" style={{ color: "var(--danger)", marginTop: 10 }}>{state.error}</div>}
      {state.done && <div className="hint" style={{ color: "var(--success)", marginTop: 10 }}>Password changed. Other sessions have been signed out.</div>}
    </div>
  );
}

function LogRetentionCard() {
  const [cfg, setCfg] = React.useState(null);
  const [ttl, setTtl] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [note, setNote] = React.useState("");
  const [confirm, setConfirm] = React.useState(false);

  const load = React.useCallback(() => {
    api.logConfig().then((c) => { setCfg(c); setTtl(String(c.ttl_days)); }).catch((e) => setErr(e.message));
  }, []);
  React.useEffect(() => { if (MODE === "live") load(); }, [load]);
  if (MODE !== "live") return null;

  const dirty = cfg && String(cfg.ttl_days) !== String(ttl).trim();
  const ttlOk = /^\d+$/.test(String(ttl).trim()) && +ttl >= 1 && +ttl <= 3650;

  const saveTtl = async () => {
    setBusy(true); setErr(""); setNote("");
    try {
      const r = await api.setLogTtl(parseInt(ttl, 10));
      setNote(r.pruned ? `Saved · pruned ${r.pruned} expired ${r.pruned === 1 ? "event" : "events"}` : "Saved");
      load();
    } catch (e) { setErr(e.message); } finally { setBusy(false); }
  };
  const doPurge = async () => {
    setBusy(true); setErr(""); setNote("");
    try {
      const r = await api.purgeLogs();
      setConfirm(false);
      setNote(`Purged ${r.events} ${r.events === 1 ? "event" : "events"}${r.files ? ` + ${r.files} file(s)` : ""}`);
      load();
    } catch (e) { setErr(e.message); } finally { setBusy(false); }
  };

  return (
    <div className="card" style={{ marginBottom: "var(--gap)" }}>
      <div className="card-head">
        <div><div className="ct">Log retention</div><div className="cs" style={{ marginTop: 3 }}>audit files are ingested into a local store, then pruned by age</div></div>
        <span className="tag dot success">SQLite</span>
      </div>
      <div className="grid g-4" style={{ gap: 14, marginBottom: 16 }}>
        <div>
          <div className="eyebrow">Stored events</div>
          <div className="mono tnum" style={{ fontSize: 20, fontWeight: 600 }}>{cfg ? cfg.count.toLocaleString("en-US") : "…"}</div>
          {cfg?.max_events && (
            <div className="hint" style={{ fontSize: 11, color: cfg.count >= cfg.max_events * 0.9 ? "var(--warning)" : undefined }}>
              of {cfg.max_events.toLocaleString("en-US")} max · oldest dropped first
            </div>
          )}
        </div>
        <div><div className="eyebrow">Store size</div><div className="mono tnum" style={{ fontSize: 20, fontWeight: 600 }}>{cfg ? fmtBytes(cfg.db_bytes) : "…"}</div></div>
        <div><div className="eyebrow">Oldest</div><div className="mono" style={{ fontSize: 12.5, marginTop: 6 }}>{cfg ? fmtWhen(cfg.oldest) : "…"}</div></div>
        <div><div className="eyebrow">Newest</div><div className="mono" style={{ fontSize: 12.5, marginTop: 6 }}>{cfg ? fmtWhen(cfg.newest) : "…"}</div></div>
      </div>
      <div className="row" style={{ gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
        <div className="field" style={{ marginBottom: 0, maxWidth: 200 }}>
          <label>Retention (days)</label>
          <input className="input mono" type="number" min={1} max={3650} value={ttl} onChange={(e) => setTtl(e.target.value)} />
        </div>
        <button className="btn primary sm" disabled={busy || !dirty || !ttlOk} onClick={saveTtl}>{busy ? "Saving…" : "Save TTL"}</button>
        <button className="btn sm" style={{ color: "var(--danger)", borderColor: "var(--danger)" }} disabled={busy} onClick={() => { setErr(""); setNote(""); setConfirm(true); }}><Icon name="x" size={13} />Purge all logs</button>
        {note && <span className="tag success" style={{ fontSize: 10.5 }}>{note}</span>}
        {err && <span className="tag danger" style={{ fontSize: 10.5 }}>{err}</span>}
      </div>
      <p className="hint" style={{ marginTop: 12 }}>Events older than the retention window are removed automatically. Changing the TTL prunes anything already past it. Karna keeps writing audit files; this console consumes and deletes them as they are stored.</p>

      <Modal open={confirm} onClose={() => setConfirm(false)}
        title={<div className="ct" style={{ fontSize: 16, fontWeight: 600 }}>Purge all logs?</div>}
        foot={
          <div className="row" style={{ gap: 8 }}>
            <button className="btn primary" style={{ background: "var(--danger)", borderColor: "var(--danger)" }} disabled={busy} onClick={doPurge}>{busy ? "Purging…" : "Purge everything"}</button>
            <button className="btn" onClick={() => setConfirm(false)}>Cancel</button>
            {err && <span className="tag danger" style={{ fontSize: 10.5 }}>{err}</span>}
          </div>
        }>
        <p style={{ fontSize: 13.5, lineHeight: 1.6 }}>This permanently deletes <b>all {cfg ? cfg.count.toLocaleString("en-US") : ""} stored events</b> from the console's store and removes any not-yet-ingested audit files. It cannot be undone. New events keep flowing in afterwards.</p>
      </Modal>
    </div>
  );
}

const EMPTY_KONG = { id: null, name: "", protocol: "http", host: "", port: "8001" };
const SAMPLE_KONGS = [
  { id: "sample-primary", name: "Production", protocol: "https", host: "kong.example.internal", port: 8444, url: "https://kong.example.internal:8444", active: true,
    metadata: { version: "3.9.2", hostname: "kong-prod-01", services_count: 18, karna_plugins_count: 12 }, last_tested_at: Math.floor(Date.now() / 1000) - 180 },
  { id: "sample-staging", name: "Staging", protocol: "http", host: "kong-staging.internal", port: 8001, url: "http://kong-staging.internal:8001", active: false,
    metadata: { version: "3.9.2", hostname: "kong-stg-01", services_count: 7, karna_plugins_count: 5 }, last_tested_at: Math.floor(Date.now() / 1000) - 3600 },
];

const fmtTested = (ts) => {
  if (!ts) return { date: "Never verified", time: "—" };
  const value = new Date(ts * 1000);
  return {
    date: value.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" }),
    time: value.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
  };
};

function KongConnectionsCard({ connected, refresh }) {
  const [connections, setConnections] = React.useState(MODE === "live" ? [] : SAMPLE_KONGS);
  const [tokenConfigured, setTokenConfigured] = React.useState(false);
  const [form, setForm] = React.useState(MODE === "live" ? EMPTY_KONG : {
    id: SAMPLE_KONGS[0].id, name: SAMPLE_KONGS[0].name, protocol: SAMPLE_KONGS[0].protocol,
    host: SAMPLE_KONGS[0].host, port: String(SAMPLE_KONGS[0].port),
  });
  const [busy, setBusy] = React.useState("");
  const [error, setError] = React.useState("");
  const [note, setNote] = React.useState("");
  const [removeTarget, setRemoveTarget] = React.useState(null);

  // the form sits below the list: bring it into view when editing or adding
  const formRef = React.useRef(null);
  const focusForm = React.useCallback(() => {
    window.requestAnimationFrame(() => {
      formRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
      formRef.current?.querySelector("#kong-name")?.focus({ preventScroll: true });
    });
  }, []);
  const edit = React.useCallback((connection) => {
    setForm({ id: connection.id, name: connection.name, protocol: connection.protocol, host: connection.host, port: String(connection.port) });
    setError(""); setNote("");
    focusForm();
  }, [focusForm]);

  const load = React.useCallback(async (selectActive = false) => {
    if (MODE !== "live") return;
    const response = await api.kongConnections();
    setConnections(response.connections || []);
    setTokenConfigured(Boolean(response.token_configured));
    if (selectActive) {
      const active = (response.connections || []).find((connection) => connection.active);
      if (active) edit(active);
    }
  }, [edit]);

  React.useEffect(() => {
    load(true).catch((err) => setError(err.message));
  }, [load]);

  const name = form.name.trim();
  const host = form.host.trim();
  const port = Number(form.port);
  const nameValid = name.length > 0 && name.length <= 64;
  const hostValid = host.length > 0 && host.length <= 253 && !/[\s/@?#]/.test(host);
  const portValid = /^\d+$/.test(String(form.port)) && port >= 1 && port <= 65535;
  const valid = nameValid && (form.protocol === "http" || form.protocol === "https") && hostValid && portValid;
  const previewHost = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  const endpoint = `${form.protocol}://${previewHost || "host"}:${form.port || "port"}`;
  const payload = () => ({ ...(form.id ? { id: form.id } : {}), name, protocol: form.protocol, host, port });
  const change = (key) => (event) => {
    setForm((current) => ({ ...current, [key]: event.target.value }));
    setError(""); setNote("");
  };

  const saveOnly = async () => {
    if (!valid || MODE !== "live") return;
    setBusy("save"); setError(""); setNote("");
    try {
      const response = await api.saveKongConnection(payload());
      await load();
      if (response.connection) edit(response.connection);
      setNote(`${name} saved without changing the active connection`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const testAndActivate = async (event) => {
    event.preventDefault();
    if (!valid || MODE !== "live") return;
    setBusy("test"); setError(""); setNote("");
    try {
      const response = await api.testKongConnection(payload());
      if (!response.connected || !response.activated) {
        setError(response.detail || "Kong is unreachable");
        return;
      }
      await load(true);
      refresh();
      setNote(`${response.name} connected and active`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const activate = async (connection) => {
    if (MODE !== "live") return;
    setBusy(`activate:${connection.id}`); setError(""); setNote("");
    try {
      const response = await api.activateKongConnection(connection.id);
      if (!response.connected || !response.activated) {
        setError(`${connection.name}: ${response.detail || "unreachable"}`);
        return;
      }
      await load(true);
      refresh();
      setNote(`${connection.name} connected and active`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const remove = async () => {
    if (!removeTarget || MODE !== "live") return;
    setBusy(`remove:${removeTarget.id}`); setError(""); setNote("");
    try {
      await api.deleteKongConnection(removeTarget.id);
      setNote(`${removeTarget.name} removed`);
      if (form.id === removeTarget.id) setForm(EMPTY_KONG);
      setRemoveTarget(null);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const active = connections.find((connection) => connection.active);
  return (
    <div className="card flush kong-targets-card" style={{ marginBottom: "var(--gap)" }}>
      <div className="kong-target-head">
        <div className="card-head">
          <div><div className="ct">Kong connections</div><div className="cs" style={{ marginTop: 3 }}>saved control-plane targets · one active at a time</div></div>
          <button type="button" className="btn sm" onClick={() => { setForm(EMPTY_KONG); setError(""); setNote(""); focusForm(); }}><Icon name="plus" size={13} />Add Kong</button>
        </div>

        <div className="active-kong-strip">
          <span className="endpoint-preview-label">Active target</span>
          <strong>{active?.name || "No active Kong"}</strong>
          <span className="mono">{active?.url || "—"}</span>
          <span className={`tag dot ${connected ? "success" : "danger"}`}>{connected ? "connected" : "unreachable"}</span>
        </div>
      </div>

      <div className="kong-target-table-scroll">
        <table className="tbl kong-target-table">
          <thead><tr><th>Target</th><th>Endpoint</th><th>Kong</th><th>Inventory</th><th>Verified</th><th className="right">Actions</th></tr></thead>
          <tbody>
            {connections.map((connection) => {
              const metadata = connection.metadata || {};
              const activating = busy === `activate:${connection.id}`;
              const tested = fmtTested(connection.last_tested_at);
              return (
                <tr key={connection.id}>
                  <td>
                    <div className="kong-target-identity">
                      <strong>{connection.name}</strong>
                      {connection.active
                        ? <span className={`tag dot ${connected ? "success" : "danger"}`}>{connected ? "active" : "active · down"}</span>
                        : <span className="tag">saved</span>}
                    </div>
                  </td>
                  <td><span className="kong-endpoint mono" title={connection.url}>{connection.url}</span></td>
                  <td><div className="kong-node"><span>Kong {metadata.version || "—"}</span><span className="mono" title={metadata.hostname || "Node unknown"}>{metadata.hostname || "Node unknown"}</span></div></td>
                  <td><div className="kong-inventory"><span><strong>{metadata.services_count ?? "—"}</strong> services</span><span><strong>{metadata.karna_plugins_count ?? "—"}</strong> Karna plugins</span></div></td>
                  <td><div className="kong-verified"><span>{tested.date}</span><span className="mono">{tested.time}</span></div></td>
                  <td className="right"><div className="kong-row-actions">
                    <button className="btn sm" disabled={Boolean(busy) || MODE !== "live"} onClick={() => activate(connection)}><Icon name="refresh" size={12} />{activating ? "Testing…" : connection.active ? "Retest" : "Activate"}</button>
                    <button className="btn sm" disabled={Boolean(busy) || MODE !== "live"} onClick={() => edit(connection)}>Edit</button>
                    {!connection.active && <button className="icon-btn" title={`Remove ${connection.name}`} aria-label={`Remove ${connection.name}`} disabled={Boolean(busy) || MODE !== "live"} onClick={() => setRemoveTarget(connection)}><Icon name="x" size={13} /></button>}
                  </div></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <form className="kong-target-editor kong-target-form" onSubmit={testAndActivate} ref={formRef}>
        <div className="sec-h">{form.id ? `Edit ${form.name || "connection"}` : "New connection"}</div>
        <div className="kong-target-fields">
          <div className="field"><label htmlFor="kong-name">Name</label><input id="kong-name" className="input" value={form.name} onChange={change("name")} placeholder="Production" autoComplete="off" aria-invalid={form.name.length > 0 && !nameValid} /></div>
          <div className="field"><label htmlFor="kong-protocol">Protocol</label><select id="kong-protocol" className="input sel mono" value={form.protocol} onChange={change("protocol")}><option value="http">http</option><option value="https">https</option></select></div>
          <div className="field"><label htmlFor="kong-host">Host</label><input id="kong-host" className="input mono" value={form.host} onChange={change("host")} placeholder="kong.example.internal" autoComplete="off" spellCheck={false} aria-invalid={form.host.length > 0 && !hostValid} /></div>
          <div className="field"><label htmlFor="kong-port">Port</label><input id="kong-port" className="input mono" type="number" min={1} max={65535} value={form.port} onChange={change("port")} aria-invalid={form.port !== "" && !portValid} /></div>
        </div>

        <div className="endpoint-preview kong-target-preview" aria-label={`Kong endpoint preview: ${endpoint}`}>
          <span className="endpoint-preview-label">{form.id ? "Editing target" : "New target"}</span><span className="mono">{endpoint}</span>
        </div>
        <div className="kong-target-actions">
          <button type="submit" className="btn primary sm" disabled={!valid || Boolean(busy) || MODE !== "live"}><Icon name="refresh" size={13} />{busy === "test" ? "Testing…" : "Test & activate"}</button>
          <button type="button" className="btn sm" disabled={!valid || Boolean(busy) || MODE !== "live"} onClick={saveOnly}>{busy === "save" ? "Saving…" : "Save only"}</button>
          <span className="hint">A successful test switches the dashboard immediately.</span>
          <span className="connection-feedback" aria-live="polite">{note && <span className="tag success">{note}</span>}{error && <span className="tag danger">{error}</span>}</span>
        </div>
        <div className="connection-meta">
          <div className="connection-meta-copy">
            <span>Admin API authentication</span>
            <span>Credentials are read from the backend environment.</span>
          </div>
          <span className={`tag dot ${tokenConfigured ? "success" : ""}`}>
            {tokenConfigured ? "Token configured" : "No token configured"}
          </span>
        </div>
      </form>


      <Modal open={!!removeTarget} onClose={() => setRemoveTarget(null)} size="sm"
        title={<div className="ct" style={{ fontSize: 16 }}>Remove {removeTarget?.name}?</div>}
        foot={<div className="row" style={{ gap: 8 }}><button className="btn danger" disabled={Boolean(busy)} onClick={remove}>Remove connection</button><button className="btn" onClick={() => setRemoveTarget(null)}>Cancel</button></div>}>
        <p className="hint" style={{ lineHeight: 1.6 }}>This removes the saved target from the dashboard. It does not change or delete anything in Kong.</p>
      </Modal>
    </div>
  );
}

export default function Settings({ data, refresh }) {
  const r = data.redis;
  return (
    <div className="view-inner">
      <div className="page-head">
        <div className="ph-top">
          <div>
            <span className="eyebrow">Account · console</span>
            <h1>Settings</h1>
            <p className="lead">Kong Admin API connections, AI profiles, audit storage, Redis backend, and console access.</p>
          </div>
          {MODE === "live" && <a className="btn sm" href="#/setup">Run setup again</a>}
        </div>
      </div>

      <KongConnectionsCard connected={data.kongConnected} refresh={refresh} />

      <AIProfilesSettings />

      <LogRetentionCard />

      <div className="card" style={{ marginBottom: "var(--gap)" }}>
        <div className="card-head"><div className="ct">Redis backend</div><span className={"tag dot " + (r.inspect_enabled ? "success" : "")}>{r.inspect_enabled ? "inspection on" : "not in use"}</span></div>
        <div className="dlist">
          <div className="between"><span className="hint">Host</span><span className="mono" style={{ fontSize: 12.5 }}>{r.host}:{r.port}</span></div>
          <div className="between"><span className="hint">Database</span><span className="mono tnum">{r.database}</span></div>
          <div className="between"><span className="hint">redis_inspect_enabled</span><span className="tag">{r.inspect_enabled ? "on" : "off"}</span></div>
          <div className="between"><span className="hint">redis_on_error</span><span className="mono">{r.on_error}</span></div>
          <div className="between"><span className="hint">Timeout / pool</span><span className="mono tnum">{r.timeout_ms}ms · {r.keepalive_pool_size}</span></div>
        </div>
        <p className="hint" style={{ marginTop: 14 }}>Counters and rate limits persist in Redis — no per-worker drift, no shared-dict eviction surprises. The console reports the configured backend; live connectivity is owned by the Kong workers (per-worker pools), not measured here.</p>
      </div>

      <div className="card flush" style={{ marginBottom: "var(--gap)" }}>
        <div className="card-head" style={{ padding: "var(--card-pad) var(--card-pad) 14px" }}>
          <div><div className="ct">Audit log store</div><div className="cs" style={{ marginTop: 3 }}>files ingested into the local store · audit v2</div></div>
        </div>
        <table className="tbl">
          <thead><tr><th>Source</th><th>Detail</th><th>Format</th><th className="right">Status</th></tr></thead>
          <tbody>
            {data.logSources.map((s) => (
              <tr key={s.id}>
                <td className="row" style={{ gap: 10 }}><Icon name="server" size={15} /><span style={{ fontWeight: 500 }}>{s.name}</span></td>
                <td className="mono hint">{s.detail}</td>
                <td className="hint">{s.format}</td>
                <td className="right"><span className={"tag dot " + (s.on ? "success" : "")}>{s.on ? "active" : "off"}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <AccountCard />
    </div>
  );
}
