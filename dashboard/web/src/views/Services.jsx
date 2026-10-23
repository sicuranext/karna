import React from "react";
import { Icon } from "../components/icons.jsx";
import { Modal } from "../components/modal.jsx";
import { KpiCard } from "../components/ui.jsx";
import { Scene3D } from "../components/Scene3D.jsx";
import { EmptyRow } from "../components/states.jsx";
import {
  createServiceConfig, diffServiceConfig, McpSettings, RedisSettings,
  RequestValidationSettings, ResponsesAndLogsSettings, RulesBoundary,
} from "../components/ServiceAdvancedSettings.jsx";
import { fmt, MODE } from "../data/index.js";
import { api } from "../data/api.js";
import { useMutation } from "../data/hooks.js";

// Fleet map (3D) vs table; remembered per browser, map by default.
const loadFleet = () => import("../components/scene3d/fleet.js").then((m) => m.fleetScene);
const VIEW_KEY = "karna.services.view";
function readView() {
  try { return window.localStorage.getItem(VIEW_KEY) === "table" ? "table" : "map"; } catch { return "map"; }
}

function ServicesMap({ services, writable, onOpen }) {
  const sceneData = React.useMemo(() => ({
    services: services.map((s) => ({
      id: s.id, name: s.name, host: s.host, routes: s.routes,
      blocking: !!s.config.engine_blocking_mode, pl: s.config.paranoia_level,
      crs: !!s.config.coreruleset_enabled, mcp: !!s.config.mcp_enabled, redis: !!s.config.redis_inspect_enabled,
      localRules: (s.config.rules_request_count || 0) + (s.config.custom_secrules_count || 0),
      reqs: s.observed.reqs_24h || 0, matchRate: s.observed.block_rate || 0, p95: s.observed.latency_p95_ms,
      writable,
    })),
  }), [services, writable]);
  const blocking = sceneData.services.filter((s) => s.blocking).length;
  const tuning = sceneData.services.filter((s) => !s.blocking && s.matchRate > 4).length;
  const ready = sceneData.services.length - blocking - tuning;
  if (services.length === 0) return <div className="k3d-empty">No services match the current search and filters</div>;
  return (
    <div className="k3d k3d-flat">
      <Scene3D load={loadFleet} data={sceneData} onPick={(id) => onOpen(services.find((s) => s.id === id))}
        fallback={<div className="k3d-empty">3D view unavailable in this browser: switch to the table.</div>}>
        <div className="k3d-telemetry" aria-hidden="true">
          <span className="hot">{services.length} services · {blocking} blocking · {services.length - blocking} detection</span>
          <span>height = requests 24h · <span className="k3d-red">red</span> = blocked · <span className="k3d-tune">amber</span> = matched, not blocked</span>
          {ready > 0 && <span className="k3d-ready">{ready} ready to block (blue ring)</span>}
          {tuning > 0 && <span className="k3d-tune">{tuning} to review before blocking (amber ring)</span>}
        </div>
      </Scene3D>
      <div className="k3d-controls">
        <span className="k3d-note">click a service to {writable ? "manage" : "view"} it · drag to rotate</span>
      </div>
    </div>
  );
}

function ModePill({ blocking }) {
  return blocking
    ? <span className="tag danger dot">blocking</span>
    : <span className="tag warning dot">detection</span>;
}
function StatusDot({ status }) {
  const c = status === "healthy" ? "var(--success)" : "var(--warning)";
  return <span style={{ width: 8, height: 8, borderRadius: 2, background: c, display: "inline-block" }} title={status} />;
}

/* Honest tuning hint for detection-mode services: a label, not a fake meter.
 * Based on the observed match rate over the last 24h. */
function TuningHint({ svc }) {
  if (svc.config.engine_blocking_mode) return null;
  const high = svc.observed.block_rate > 4;
  return high
    ? <span className="tag warning" title={`${svc.observed.block_rate}% of requests matched a rule in the last 24h — review the events and tune before enabling blocking`}>review matches before blocking</span>
    : <span className="tag info" title={`Only ${svc.observed.block_rate}% of requests matched a rule in the last 24h — likely safe to enable blocking`}>low match rate — ready to block</span>;
}

const RULESET_LABELS = {
  method_enforcement: "Method", scanner_detection: "Scanner", protocol_enforcement: "Protocol enf.",
  protocol_attack: "Protocol atk", multipart_attack: "Multipart", lfi: "LFI", rfi: "RFI", rce: "RCE",
  php: "PHP", generic: "Generic", xss: "XSS", sqli: "SQLi", session_fixation: "Session", java: "Java",
};
const DEFAULT_RULESETS = {
  method_enforcement: true, scanner_detection: true, protocol_enforcement: false, protocol_attack: true,
  multipart_attack: true, lfi: true, rfi: true, rce: true, php: true, generic: true, xss: true,
  sqli: true, session_fixation: true, java: true,
};
const PARANOIA_LEVELS = [
  { level: 1, name: "Baseline", description: "Broad protection with the lowest false-positive risk." },
  { level: 2, name: "Elevated", description: "Deeper inspection for applications with predictable inputs." },
  { level: 3, name: "Strict", description: "Aggressive detection that usually requires service-specific tuning." },
  { level: 4, name: "Maximum", description: "Maximum sensitivity for tightly controlled, high-risk traffic." },
];
const RULESET_GROUPS = [
  {
    label: "Request integrity",
    keys: ["method_enforcement", "protocol_enforcement", "protocol_attack", "multipart_attack"],
  },
  {
    label: "Injection & scripting",
    keys: ["sqli", "xss", "rce"],
  },
  {
    label: "Application exploits",
    keys: ["lfi", "rfi", "php", "java"],
  },
  {
    label: "Discovery & abuse",
    keys: ["scanner_detection", "generic", "session_fixation"],
  },
];

const ENGINE_FLAGS = [
  ["engine_fast_path", "Fast path", "Skips the per-rule ARGS deep-copy when it is not needed."],
  ["engine_re2_scan", "RE2 scan", "Pre-filters @rx rules with one RE2::Set scan per request value."],
  ["engine_ac_pm", "Aho-Corasick", "Runs @pm and @pmFromFile keyword matching through the native matcher."],
  ["engine_re2_match", "RE2 matching", "Runs compatible @rx patterns with linear-time RE2 matching."],
];
const DEFAULT_ENGINE_FLAGS = Object.fromEntries(ENGINE_FLAGS.map(([key]) => [key, true]));
const SERVICE_CONFIG_TABS = [
  ["protection", "Protection"],
  ["validation", "Request validation"],
  ["mcp", "MCP"],
  ["responses", "Responses & logs"],
  ["runtime", "Runtime & Redis"],
];

const SORT_VALUE = {
  name: (s) => s.name || "",
  mode: (s) => s.config.engine_blocking_mode ? "blocking" : "detection",
  policy: (s) => s.config.paranoia_level,
  requests: (s) => s.observed.reqs_24h,
  matchRate: (s) => s.observed.block_rate,
  routes: (s) => s.routes,
  latency: (s) => s.observed.latency_p95_ms,
  readiness: (s) => s.observed.status || "",
};

const DEFAULT_SORT_DIRECTION = {
  name: "asc", mode: "asc", policy: "asc", requests: "desc",
  matchRate: "desc", routes: "desc", latency: "desc", readiness: "asc",
};

function SortHeader({ id, label, sort, onSort, align }) {
  const active = sort.key === id;
  return (
    <th className={align === "right" ? "right" : ""} aria-sort={active ? (sort.direction === "asc" ? "ascending" : "descending") : "none"}>
      <button className={`sort-head${active ? " active" : ""}`} onClick={() => onSort(id)}>
        {label}<Icon name={active ? (sort.direction === "asc" ? "up" : "down") : "chevd"} size={11} />
      </button>
    </th>
  );
}

export default function Services({
  data, param, navReplace, writable, refresh,
  refreshInventory, inventoryRefreshing, inventoryError,
}) {
  const [modal, setModal] = React.useState(null); // {mode, svc}
  const [query, setQuery] = React.useState("");
  const [modeFilter, setModeFilter] = React.useState("all");
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [sort, setSort] = React.useState({ key: "name", direction: "asc" });
  const [view, setViewState] = React.useState(readView);
  const setView = (v) => { setViewState(v); try { window.localStorage.setItem(VIEW_KEY, v); } catch { /* per-browser convenience only */ } };
  const { run, pending } = useMutation(refresh);
  const svc = data.services;
  const totalRoutes = svc.reduce((a, b) => a + b.routes, 0);

  const visibleServices = React.useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    const filtered = svc.filter((s) => {
      if (modeFilter === "blocking" && !s.config.engine_blocking_mode) return false;
      if (modeFilter === "detection" && s.config.engine_blocking_mode) return false;
      if (statusFilter !== "all" && s.observed.status !== statusFilter) return false;
      if (!needle) return true;
      const searchable = [
        s.name, s.host, s.upstream_url,
        ...(s.route_hosts || []), ...(s.route_paths || []),
      ].filter(Boolean).join(" ").toLocaleLowerCase();
      return searchable.includes(needle);
    });
    const valueOf = SORT_VALUE[sort.key] || SORT_VALUE.name;
    return [...filtered].sort((a, b) => {
      const av = valueOf(a), bv = valueOf(b);
      const compared = typeof av === "number" && typeof bv === "number"
        ? av - bv
        : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: "base" });
      const ordered = sort.direction === "asc" ? compared : -compared;
      return ordered || String(a.name).localeCompare(String(b.name), undefined, { sensitivity: "base" });
    });
  }, [svc, query, modeFilter, statusFilter, sort]);

  const changeSort = (key) => {
    setSort((current) => current.key === key
      ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
      : { key, direction: DEFAULT_SORT_DIRECTION[key] || "asc" });
  };
  const filtersActive = query.trim() || modeFilter !== "all" || statusFilter !== "all";
  const clearFilters = () => { setQuery(""); setModeFilter("all"); setStatusFilter("all"); };

  // Deep link: #/services/<id> opens that service's dialog.
  React.useEffect(() => {
    if (!param) return;
    const s = svc.find((x) => x.id === param);
    if (s) setModal({ mode: writable ? "edit" : "view", svc: s });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [param]);

  const closeModal = () => { setModal(null); if (param) navReplace("services"); };

  const setMode = (s, blocking) => {
    if (s.config.engine_blocking_mode === blocking || !s.plugin_id) return;
    const copy = blocking
      ? {
          title: `Switch "${s.name}" to blocking?`,
          message: `Requests matching a rule will be rejected with a 403. In the last 24 hours ${s.observed.block_rate}% of this service's traffic matched a rule — those requests would have been blocked.`,
          danger: true,
          confirmLabel: "Enable blocking",
        }
      : {
          title: `Switch "${s.name}" to detection?`,
          message: `Karna keeps inspecting and logging every request, but stops blocking. Matches only show up in the audit trail.`,
          confirmLabel: "Switch to detection",
        };
    run(() => api.patchEngine(s.plugin_id, { engine_blocking_mode: blocking }), copy);
  };

  return (
    <div className="view-inner">
      <div className="page-head">
        <div className="ph-top">
          <div>
            <span className="eyebrow">Configuration · per service</span>
            <h1>Services</h1>
            <p className="lead">Each protected service has its own Karna configuration: detection or blocking, paranoia level, rule categories, and its own rules.</p>
          </div>
          <div className="row" style={{ gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
            {inventoryError && <span className="tag danger">{inventoryError}</span>}
            {writable && MODE === "live" && <button className="btn ghost" disabled={inventoryRefreshing} onClick={refreshInventory}>
              <Icon name="refresh" size={15} />
              {inventoryRefreshing ? "Refreshing inventory…" : "Refresh Kong inventory"}
            </button>}
            <span className="tag info dot">Topology managed in Kong</span>
          </div>
        </div>
      </div>

      <div className="grid g-4" style={{ marginBottom: "var(--gap)" }}>
        <KpiCard label="Protected services" value={svc.length} sub={`${totalRoutes} routes total`} />
        <KpiCard label="In blocking" value={svc.filter((s) => s.config.engine_blocking_mode).length} sub="matches are rejected" />
        <KpiCard label="In detection" value={svc.filter((s) => !s.config.engine_blocking_mode).length} sub="matches are only logged" />
        <KpiCard label="MCP-aware" value={svc.filter((s) => s.config.mcp_enabled).length} sub="agentic gateways" />
      </div>

      {svc.length === 0 ? (
        <div className="card" style={{ textAlign: "center", padding: 40 }}>
          <div style={{ fontWeight: 600, marginBottom: 7 }}>No protected services found</div>
          <div className="hint">Attach Karna to a service in Kong. It will appear here automatically.</div>
        </div>
      ) : (
        <div className="card flush service-table-card">
          <div className="filter-bar service-filter-bar">
            <label className="service-search" htmlFor="service-search">
              <Icon name="search" size={15} />
              <input id="service-search" value={query} onChange={(e) => setQuery(e.target.value)}
                placeholder="Search name, host, upstream or route…" autoComplete="off" />
            </label>
            <select className="input sel" value={modeFilter} onChange={(e) => setModeFilter(e.target.value)} aria-label="Filter by mode">
              <option value="all">All modes</option>
              <option value="blocking">Blocking</option>
              <option value="detection">Detection</option>
            </select>
            <select className="input sel" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Filter by readiness">
              <option value="all">All readiness</option>
              <option value="healthy">Healthy</option>
              <option value="tuning">Needs tuning</option>
            </select>
            {filtersActive && <button className="btn ghost sm" onClick={clearFilters}><Icon name="x" size={12} />Clear</button>}
            <span className="service-result-count mono">{visibleServices.length} of {svc.length}</span>
            <div className="seg service-view-seg" role="group" aria-label="Services view">
              <button className={view === "map" ? "on" : ""} aria-pressed={view === "map"} onClick={() => setView("map")}>Map</button>
              <button className={view === "table" ? "on" : ""} aria-pressed={view === "table"} onClick={() => setView("table")}>Table</button>
            </div>
          </div>

          {view === "map" ? (
            <ServicesMap services={visibleServices} writable={writable}
              onOpen={(s) => s && setModal({ mode: writable ? "edit" : "view", svc: s })} />
          ) : (
          <div className="service-table-scroll">
            <table className="tbl service-table">
              <thead><tr>
                <SortHeader id="name" label="Service" sort={sort} onSort={changeSort} />
                <SortHeader id="mode" label="Mode" sort={sort} onSort={changeSort} />
                <SortHeader id="policy" label="Policy" sort={sort} onSort={changeSort} />
                <SortHeader id="requests" label="Requests 24h" sort={sort} onSort={changeSort} align="right" />
                <SortHeader id="matchRate" label="Match rate" sort={sort} onSort={changeSort} align="right" />
                <SortHeader id="routes" label="Routes" sort={sort} onSort={changeSort} align="right" />
                <SortHeader id="latency" label="p95" sort={sort} onSort={changeSort} align="right" />
                <SortHeader id="readiness" label="Readiness" sort={sort} onSort={changeSort} />
                <th><span className="sr-only">Actions</span></th>
              </tr></thead>
              <tbody>
                {visibleServices.length === 0 && <EmptyRow colSpan={9} label="No services match the current search and filters" />}
                {visibleServices.map((s) => (
                  <tr key={s.id}>
                    <td className="service-identity-cell">
                      <div className="row" style={{ gap: 10, minWidth: 0 }}>
                        <StatusDot status={s.observed.status} />
                        <div className="service-identity">
                          <span>{s.name}</span>
                          <span className="mono" title={s.host}>{s.host}</span>
                        </div>
                      </div>
                    </td>
                    <td>
                      {writable && s.plugin_id ? (
                        <div className="seg service-mode-seg" role="group" aria-label={`Mode for ${s.name}`}>
                          <button className={!s.config.engine_blocking_mode ? "on" : ""} disabled={pending} onClick={() => setMode(s, false)}>Detect</button>
                          <button className={s.config.engine_blocking_mode ? "on" : ""} disabled={pending} onClick={() => setMode(s, true)}>Block</button>
                        </div>
                      ) : <ModePill blocking={s.config.engine_blocking_mode} />}
                    </td>
                    <td><span className="row service-policy-tags">
                      <span className="tag">PL{s.config.paranoia_level}</span>
                      {s.config.coreruleset_enabled && <span className="tag accent">CRS</span>}
                      {s.config.mcp_enabled && <span className="tag success">MCP</span>}
                    </span></td>
                    <td className="num">{fmt(s.observed.reqs_24h)}</td>
                    <td className="num" style={{ color: s.observed.block_rate > 4 ? "var(--warning)" : undefined }}>{s.observed.block_rate}%</td>
                    <td className="num">{s.routes}</td>
                    <td className="num">{s.observed.latency_p95_ms}ms</td>
                    <td className="service-readiness"><TuningHint svc={s} />{s.config.engine_blocking_mode && <span className="tag success">enforcing</span>}</td>
                    <td className="service-manage-cell"><button className="btn sm" onClick={() => setModal({ mode: writable ? "edit" : "view", svc: s })}>
                      <Icon name="gear" size={13} />{writable ? "Manage" : "View"}
                    </button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          )}
        </div>
      )}

      <ServiceModal state={modal} engine={data.engine} writable={writable} refresh={refresh} onClose={closeModal} />
    </div>
  );
}

function ServiceModal({ state, engine, writable, refresh, onClose }) {
  const { run, pending, error } = useMutation(refresh);
  const svc = state?.svc;
  const editable = writable && Boolean(svc?.plugin_id);

  const [blocking, setBlocking] = React.useState(false);
  const [pl, setPl] = React.useState(1);
  const [crs, setCrs] = React.useState(true);
  const [rulesets, setRulesets] = React.useState(DEFAULT_RULESETS);
  const [crsPlugins, setCrsPlugins] = React.useState([]);
  const [engineFlags, setEngineFlags] = React.useState(DEFAULT_ENGINE_FLAGS);
  const [configTab, setConfigTab] = React.useState("protection");
  const [baseConfig, setBaseConfig] = React.useState(() => createServiceConfig());
  const [serviceConfig, setServiceConfig] = React.useState(() => createServiceConfig());
  const [redisPassword, setRedisPassword] = React.useState("");
  const [clearRedisPassword, setClearRedisPassword] = React.useState(false);

  React.useEffect(() => {
    if (!svc) return;
    setBlocking(svc.config.engine_blocking_mode); setPl(svc.config.paranoia_level);
    setCrs(svc.config.coreruleset_enabled);
    setRulesets({ ...(svc.config.coreruleset_rulesets || DEFAULT_RULESETS) });
    setCrsPlugins([...(svc.config.crs_plugins_enabled || [])]);
    setEngineFlags(Object.fromEntries(ENGINE_FLAGS.map(([key]) => [key, svc.config[key] ?? true])));
    const config = createServiceConfig(svc.config);
    setBaseConfig(config);
    setServiceConfig(config);
    setRedisPassword("");
    setClearRedisPassword(false);
    setConfigTab("protection");
  }, [svc]);

  if (!state) return null;

  const save = async () => {
    const body = {
      engine_blocking_mode: blocking, paranoia_level: pl, coreruleset_enabled: crs,
      coreruleset_rulesets: rulesets,
      crs_plugins_enabled: crsPlugins,
      ...engineFlags,
      ...diffServiceConfig(baseConfig, serviceConfig),
    };
    if (clearRedisPassword) body.redis_password = null;
    else if (redisPassword) body.redis_password = redisPassword;
    const ok = await run(
      () => api.patchEngine(svc.plugin_id, body),
      {
        title: `Update Karna on "${svc.name}"?`,
        message: "The Karna policy applies to live traffic immediately. The Kong service, upstream, and routes remain unchanged.",
        confirmLabel: "Update Karna policy",
      },
    );
    if (ok) onClose();
  };

  const title = (
    <div className="service-config-title">
      <span className="ct">{svc.name}</span>
      <small>Karna service configuration</small>
    </div>
  );
  const head = (
    <div className="service-config-tabs" role="tablist" aria-label="Karna configuration sections">
      {SERVICE_CONFIG_TABS.map(([key, label]) => (
        <button type="button" role="tab" aria-selected={configTab === key}
          className={configTab === key ? "active" : ""} key={key} onClick={() => setConfigTab(key)}>
          {label}
        </button>
      ))}
    </div>
  );

  const foot = editable ? (
    <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <button className="btn primary" disabled={pending} onClick={save}>
        {pending ? "Updating…" : "Update Karna policy"}
      </button>
      <button className="btn" onClick={onClose}>Cancel</button>
      {error && <span className="tag danger" style={{ fontSize: 10.5 }}>{error}</span>}
    </div>
  ) : (
    <button className="btn" onClick={onClose}>Close</button>
  );

  return (
    <Modal open={!!state} onClose={onClose} title={title} head={head} foot={foot} className="service-config-modal">
      <div className="service-config-content">
        {configTab === "protection" && (
          <React.Fragment>
            <KongTopology svc={svc} />
            <KarnaPolicyEditor
              blocking={blocking}
              pl={pl}
              crs={crs}
              rulesets={rulesets}
              editable={editable}
              onBlockingChange={setBlocking}
              onPlChange={setPl}
              onCrsChange={setCrs}
              onRulesetToggle={(key) => setRulesets((current) => ({ ...current, [key]: !current[key] }))}
            />

            <CrsPluginsSettings
              path={serviceConfig.crs_plugins_path}
              available={svc.config.crs_plugins_available}
              enabled={crsPlugins}
              editable={editable}
              onPathChange={(path) => setServiceConfig((current) => ({ ...current, crs_plugins_path: path }))}
              onToggle={(name) => setCrsPlugins((current) =>
                current.includes(name) ? current.filter((item) => item !== name) : [...current, name]
              )}
            />
            <RulesBoundary value={{ ...svc.config, ...serviceConfig }} disabled={!editable}
              onToggle={() => setServiceConfig((current) => ({ ...current, local_rules_enabled: !current.local_rules_enabled }))} />
          </React.Fragment>
        )}
        {configTab === "validation" && <RequestValidationSettings value={serviceConfig} onChange={setServiceConfig} disabled={!editable} />}
        {configTab === "mcp" && <McpSettings value={serviceConfig} onChange={setServiceConfig} disabled={!editable} />}
        {configTab === "responses" && <ResponsesAndLogsSettings value={serviceConfig} onChange={setServiceConfig} disabled={!editable} />}
        {configTab === "runtime" && (
          <div className="service-config-panels">
            <EngineSettings engine={engine} flags={engineFlags} editable={editable}
              onToggle={(key) => setEngineFlags((current) => ({ ...current, [key]: !current[key] }))} />
            <RedisSettings value={serviceConfig} onChange={setServiceConfig} disabled={!editable}
              password={redisPassword} onPasswordChange={setRedisPassword}
              clearPassword={clearRedisPassword} onClearPasswordChange={setClearRedisPassword} />
          </div>
        )}
      </div>
    </Modal>
  );
}

function KarnaPolicyEditor({
  blocking, pl, crs, rulesets, editable = false,
  onBlockingChange, onPlChange, onCrsChange, onRulesetToggle,
}) {
  const currentPl = PARANOIA_LEVELS.find((item) => item.level === pl) || PARANOIA_LEVELS[0];
  const activeCategories = Object.values(rulesets).filter(Boolean).length;
  const totalCategories = Object.keys(rulesets).length;

  return (
    <section className={`karna-policy-stack${editable ? "" : " read-only"}`}>
      <div className="karna-policy-intro">
        <div>
          <span className="eyebrow">Traffic policy</span>
          <h3>How Karna protects this service</h3>
          <p>Set the outcome of a match, the inspection depth, and which CoreRuleSet protections participate.</p>
        </div>
        <span className={`tag dot ${blocking ? "danger" : "warning"}`}>
          {blocking ? "enforcing" : "observing"}
        </span>
      </div>

      <div className="policy-layer enforcement-layer">
        <span className="policy-layer-index" aria-hidden="true">01</span>
        <div className="policy-layer-body">
          <div className="policy-layer-head">
            <div>
              <span className="policy-kicker">Match outcome</span>
              <h4>Enforcement</h4>
            </div>
            <span className="policy-value">{blocking ? "Requests are rejected" : "Traffic is never interrupted"}</span>
          </div>
          <p>Choose what happens when Karna detects a rule match.</p>
          <div className="policy-mode-options" role="radiogroup" aria-label="Karna enforcement mode">
            <button type="button" role="radio" aria-checked={!blocking}
              disabled={!editable} className={!blocking ? "active" : ""}
              onClick={() => onBlockingChange(false)}>
              <Icon name="pulse" size={18} />
              <span><strong>Detection</strong><small>Inspect and record matches</small></span>
              <Icon name="check" size={14} />
            </button>
            <button type="button" role="radio" aria-checked={blocking}
              disabled={!editable} className={blocking ? "active danger" : ""}
              onClick={() => onBlockingChange(true)}>
              <Icon name="shield" size={18} />
              <span><strong>Blocking</strong><small>Reject matching requests</small></span>
              <Icon name="check" size={14} />
            </button>
          </div>
        </div>
      </div>

      <div className="policy-layer depth-layer">
        <span className="policy-layer-index" aria-hidden="true">02</span>
        <div className="policy-layer-body">
          <div className="policy-layer-head">
            <div>
              <span className="policy-kicker">Inspection sensitivity</span>
              <h4>Paranoia level</h4>
            </div>
            <span className="policy-value mono">PL{pl} · {currentPl.name}</span>
          </div>
          <p>Higher levels inspect more patterns and may require additional tuning.</p>
          <div className="policy-pl-scale" role="radiogroup" aria-label="CoreRuleSet paranoia level">
            {PARANOIA_LEVELS.map((item) => (
              <button type="button" role="radio" aria-checked={pl === item.level}
                disabled={!editable} className={pl === item.level ? "active" : ""}
                key={item.level} onClick={() => onPlChange(item.level)}>
                <span>PL{item.level}</span><small>{item.name}</small>
              </button>
            ))}
          </div>
          <div className="policy-pl-explainer">
            <Icon name="pulse" size={14} />
            <span>{currentPl.description}</span>
          </div>
        </div>
      </div>

      <div className={`policy-layer coverage-layer${crs ? "" : " disabled"}`}>
        <span className="policy-layer-index" aria-hidden="true">03</span>
        <div className="policy-layer-body">
          <div className="policy-layer-head">
            <div>
              <span className="policy-kicker">Managed rule coverage</span>
              <h4>OWASP CoreRuleSet</h4>
            </div>
            <div className="policy-crs-state">
              <span>{crs ? `${activeCategories} of ${totalCategories} categories` : "Protection disabled"}</span>
              {editable ? (
                <button type="button" className={`switch${crs ? " on" : ""}`}
                  aria-label={`${crs ? "Disable" : "Enable"} OWASP CoreRuleSet`}
                  aria-pressed={crs} onClick={() => onCrsChange(!crs)} />
              ) : <span className={`tag dot ${crs ? "success" : ""}`}>{crs ? "enabled" : "off"}</span>}
            </div>
          </div>
          <p>Enable the managed CRS pack, then tailor its coverage to the application.</p>

          {crs ? (
            <div className="policy-category-groups">
              {RULESET_GROUPS.map((group) => (
                <div className="policy-category-group" key={group.label}>
                  <span>{group.label}</span>
                  <div>
                    {group.keys.map((key) => {
                      const active = Boolean(rulesets[key]);
                      return (
                        <button type="button" key={key} disabled={!editable}
                          aria-pressed={active} className={active ? "active" : ""}
                          onClick={() => onRulesetToggle(key)}>
                          <span className="policy-category-check"><Icon name="check" size={10} /></span>
                          {RULESET_LABELS[key] || key}
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="policy-crs-disabled">
              <Icon name="shield" size={16} />
              CoreRuleSet rules and category selections will not run for this service.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function CrsPluginsSettings({ path, available = [], enabled = [], editable = false, onToggle, onPathChange }) {
  const installedByName = new Map((available || []).map((item) => [item.name, item]));
  const names = [...new Set([...installedByName.keys(), ...(enabled || [])])].sort();

  return (
    <section className="crs-plugin-panel">
      <div className="crs-plugin-head">
        <div>
          <div className="row" style={{ gap: 8 }}>
            <Icon name="layers" size={15} />
            <div className="sec-h">CoreRuleSet plugins</div>
          </div>
          <p>Application-specific exclusion packs installed on this Kong node. Enable them only for services running that application.</p>
        </div>
        <span className="tag info">{enabled.length} active</span>
      </div>

      <div className="crs-plugin-path">
        <span>Filesystem</span>
        {editable ? (
          <input className="input mono" value={path || ""} aria-label="CoreRuleSet plugins filesystem path"
            onChange={(event) => onPathChange(event.target.value)} />
        ) : <code title={path || "/opt/coreruleset-plugins/"}>{path || "/opt/coreruleset-plugins/"}</code>}
      </div>

      <div className="crs-plugin-list">
        {names.map((name) => {
          const item = installedByName.get(name);
          const active = enabled.includes(name);
          const canEnable = Boolean(item);
          return (
            <div className="crs-plugin-row" key={name}>
              <div className="crs-plugin-marker" aria-hidden="true" />
              <div className="crs-plugin-copy">
                <strong className="mono">{name}</strong>
                <span>
                  {item
                    ? `${item.config_file_count || 0} configuration file${item.config_file_count === 1 ? "" : "s"}`
                    : "Configured but missing from the filesystem"}
                </span>
              </div>
              <span className={`tag ${item ? "success" : "danger"}`}>{item ? "installed" : "missing"}</span>
              {editable ? (
                <button type="button" className={`switch${active ? " on" : ""}`}
                  disabled={!canEnable && !active}
                  aria-label={`${active ? "Disable" : "Enable"} ${name}`}
                  aria-pressed={active}
                  onClick={() => onToggle(name)} />
              ) : (
                <span className={`tag dot ${active ? "accent" : ""}`}>{active ? "active" : "off"}</span>
              )}
            </div>
          );
        })}
        {names.length === 0 && (
          <div className="crs-plugin-empty">
            No CoreRuleSet plugins were found in this directory. Install the package on the Kong filesystem, then reopen this service.
          </div>
        )}
      </div>
    </section>
  );
}

function EngineSettings({ engine, flags, editable, onToggle }) {
  return (
    <section className="service-engine-panel">
      <div className="service-engine-head">
        <div>
          <div className="row" style={{ gap: 8 }}><Icon name="shield" size={15} /><div className="sec-h service-engine-title">Engine</div></div>
          <p>Runtime details are shared by this Karna installation; optimization flags belong to this service.</p>
        </div>
        <span className="mono hint">GET /.well-known/karna</span>
      </div>

      <div className="service-engine-runtime">
        <span className="tag accent">{engine.name || "karna"} {engine.version || "unknown"}</span>
        <span className="tag">commit {engine.commit_short || "unknown"}</span>
        <span className="tag">build {engine.built_at || "unknown"}</span>
        <span className="tag">CRS {engine.crs_version || "unknown"}</span>
      </div>

      <div className="service-engine-grid compact">
        <div>
          <div className="sec-h">Optimizations · this service</div>
          <div className="engine-option-list">
            {ENGINE_FLAGS.map(([key, label, description]) => (
              <div key={key} className="engine-option">
                <div>
                  <div className="engine-option-label">{label}<span className="mono">{key}</span></div>
                  <div className="hint">{description}</div>
                </div>
                {editable ? (
                  <button type="button" className={`switch${flags[key] ? " on" : ""}`}
                    aria-label={`${label} ${flags[key] ? "enabled" : "disabled"}`} aria-pressed={flags[key]}
                    onClick={() => onToggle(key)} />
                ) : <span className={`tag dot ${flags[key] ? "success" : ""}`}>{flags[key] ? "on" : "off"}</span>}
              </div>
            ))}
          </div>
        </div>

      </div>
    </section>
  );
}

function KongTopology({ svc }) {
  return (
    <section className="managed-boundary">
      <div className="managed-boundary-head">
        <div className="row" style={{ gap: 8 }}><Icon name="route" size={15} /><span>Kong topology</span></div>
        <span className="tag info">Managed in Kong</span>
      </div>
      <p>Service identity and routing are imported from Kong and cannot be changed from Karna.</p>
      <dl className="topology-grid">
        <div><dt>Name</dt><dd>{svc.name}</dd></div>
        <div><dt>Upstream</dt><dd className="mono">{svc.upstream_url || "—"}</dd></div>
        <div><dt>Route hosts</dt><dd className="mono">{(svc.route_hosts || []).join(", ") || "—"}</dd></div>
        <div><dt>Route paths</dt><dd className="mono">{(svc.route_paths || []).join(", ") || "—"}</dd></div>
      </dl>
    </section>
  );
}
