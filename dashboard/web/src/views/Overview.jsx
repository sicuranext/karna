import { Icon } from "../components/icons.jsx";
import React from "react";
import { BarRows } from "../components/charts.jsx";
import { ActionTag, CatTag, Flag } from "../components/ui.jsx";
import { Scene3D } from "../components/Scene3D.jsx";
import { TrafficScene } from "../components/TrafficScene.jsx";
import { EmptyRow } from "../components/states.jsx";
import { fmt, whenOf, primaryMatch, eventCategory, eventDisposition } from "../data/index.js";

const ENFORCED = new Set(["blocked", "rate_limited", "sanitized"]);

// Stable loader: the scene module (and Three.js) is fetched once, on first use.
const loadRules = () => import("../components/scene3d/rules.js").then((m) => m.rulesScene);

function RulesScene({ data, focus, onHover }) {
  const rules = data.ruleActivity;
  const total = rules.reduce((a, r) => a + r.hits, 0);
  const sceneData = React.useMemo(() => ({
    rules: data.ruleActivity.map((r) => ({
      rule_id: r.rule_id, message: r.message, hits: r.hits, action: r.action, hourly: r.hourly,
      ips: r.ips, services: r.services, top_service: r.top_service, blocked_pct: r.blocked_pct,
    })),
    labels: data.traffic.map((d) => d.label),
  }), [data.ruleActivity, data.traffic]);
  if (rules.length === 0) return <div className="card k3d-empty">No rule matched in the last 24 hours.</div>;
  return (
    <div className="k3d k3d-compact">
      <Scene3D load={loadRules} data={sceneData} focus={focus} onHover={onHover}
        fallback={<div className="k3d-fallback"><BarRows items={rules.map((r) => ({ name: r.message || r.rule_id, via: r.rule_id, count: r.hits }))} /></div>}>
        <div className="k3d-telemetry" aria-hidden="true">
          <span className="hot">top {rules.length} rules · last 24 hours</span>
          <span>{fmt(total)} matches · height on a square-root scale</span>
          <span>solid = mostly blocked · dashed = mostly detected</span>
        </div>
      </Scene3D>
      <div className="k3d-controls">
        <span className="k3d-note">one row per rule · drag to rotate · hover a row to read an hour</span>
      </div>
    </div>
  );
}

function Onboarding({ nav }) {
  return (
    <div className="card" style={{ textAlign: "center", padding: "56px 40px" }}>
      <div style={{ color: "var(--accent)", marginBottom: 14 }}><Icon name="shield" size={30} /></div>
      <div style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>No Karna plugins found</div>
      <p className="hint" style={{ maxWidth: 460, margin: "0 auto 18px" }}>
        Attach Karna to a service in Kong to start seeing traffic, threats, and
        audit events here. Service identity and routing stay managed in Kong.
      </p>
      <button className="btn primary" onClick={() => nav("services")}>
        <Icon name="arrowr" size={15} />Go to Services
      </button>
    </div>
  );
}

export default function Overview({ data, nav, writable, refresh }) {
  // hover shared by the rule towers and the detections list: { rule, from }
  const [focus, setFocus] = React.useState(null);
  const fromScene = React.useCallback((v) => setFocus(v ? { ...v, from: "scene" } : null), []);
  const recent = data.events.filter((e) => ENFORCED.has(eventDisposition(e))).slice(0, 6);
  const activeRules = data.ruleActivity;
  const maxRuleHits = Math.max(...activeRules.map((rule) => rule.hits), 1);

  const peak = data.traffic.reduce((m, t) => (t.blocked > m.blocked ? t : m), data.traffic[0]) || { blocked: 0, label: "–" };
  const catsActive = Object.values(data.crsRulesets).filter(Boolean).length;
  const catsTotal = Object.keys(data.crsRulesets).length;
  const overridesActive = data.ruleActionOverrides.length + data.ruleResponseOverrides.length;
  const blocking = data.services.filter((s) => s.config.engine_blocking_mode).length;
  const detection = data.services.length - blocking;
  const enforcementPct = data.services.length ? Math.round((blocking / data.services.length) * 100) : 0;

  if (data.services.length === 0) {
    return (
      <div className="view-inner">
        <div className="page-head">
          <div className="ph-top">
            <div>
              <span className="eyebrow">Overview</span>
              <h1>Traffic &amp; threats</h1>
              <p className="lead">What Karna inspected and mitigated over the last 24 hours, across all protected services.</p>
            </div>
          </div>
        </div>
        <Onboarding nav={nav} />
      </div>
    );
  }

  return (
    <div className="view-inner overview">
      <section className="posture-hero">
        <div className="posture-copy">
          <div className="posture-meta">
            <span className="eyebrow">Protection summary</span>
            <span className="time-window">Last 24 hours</span>
          </div>
          <h1><strong>{fmt(data.totalBlk)}</strong>{" "}hostile requests contained</h1>
          <p>Karna inspected {fmt(data.totalReq)} requests across {data.services.length} protected services. The control room surfaces what needs attention first; the evidence stays one click away.</p>
          <div className="posture-actions">
            <button className="btn primary" onClick={() => nav("events")}>Review enforced events<Icon name="arrowr" size={14} /></button>
            {writable && <button className="btn ghost" onClick={refresh}><Icon name="refresh" size={15} />Refresh data</button>}
          </div>
        </div>
        <div className="posture-panel">
          <div className="posture-panel-head">
            <span>Protection posture</span>
            <span className={"tag dot " + (data.kongConnected ? "success" : "danger")}>
              {data.kongConnected ? "Operational" : "Connection issue"}
            </span>
          </div>
          <div className="coverage-value"><strong>{blocking}</strong><span>of {data.services.length} services enforcing</span></div>
          <div className="coverage-track" aria-label={`${enforcementPct}% of services in blocking mode`}>
            <span style={{ width: `${enforcementPct}%` }} />
          </div>
          <div className="posture-breakdown">
            <div><span className="status-mark danger" /><strong>{blocking}</strong><small>Blocking</small></div>
            <div><span className="status-mark warning" /><strong>{detection}</strong><small>Detection</small></div>
            <div><span className="status-mark accent" /><strong>{overridesActive}</strong><small>Overrides</small></div>
          </div>
          <dl className="posture-engine">
            <div><dt>Engine</dt><dd className="mono">karna {data.engine.version}</dd></div>
            <div><dt>CoreRuleSet</dt><dd className="mono">{data.engine.crs_version} · {catsActive}/{catsTotal} categories</dd></div>
          </dl>
        </div>
      </section>

      <section className="ov-section">
        <div className="ov-section-head">
          <h2>Traffic <span>last 24 hours</span></h2>
          <p>Each row is one series on its own scale.{peak.blocked > 0 && " The red beacon marks the hour Karna blocked the most."}</p>
        </div>
        <TrafficScene data={data} />
        <div className="ov-proof">
          <div><span>requests inspected</span><b>{fmt(data.totalReq)}</b><small>complete traffic sample</small></div>
          <div><span>hostile requests</span><b>{fmt(data.totalBlk)}</b><small>blocked, sanitized or rate-limited</small></div>
          <div><span>block rate</span><b>{data.blockRate}<em>%</em></b><small>peak {fmt(peak.blocked)} at {peak.label}</small></div>
          <div><span>kong/waf latency · p95</span><b>{data.latency.p95}<em>ms</em></b><small>p50 {data.latency.p50}ms · p99 {data.latency.p99}ms</small></div>
        </div>
      </section>

      <section className="ov-section">
        <div className="ov-section-head">
          <h2>Threats <span>what matched</span></h2>
          <p>When each of the ten most matched rules fired. A spike is a burst or a scan, a flat band is steady noise worth tuning.</p>
        </div>
        <div className="ov-threats">
          <RulesScene data={data} focus={focus && focus.from === "list" ? focus : null} onHover={fromScene} />
          <div className="card flush active-detections-card">
            <div className="card-head" style={{ padding: "var(--card-pad) var(--card-pad) 14px" }}>
              <div>
                <div className="ct">Most frequent detections</div>
                <div className="cs" style={{ marginTop: 3 }}>top matches · last 24 hours</div>
              </div>
              <button className="btn ghost sm" onClick={() => nav("events")}>Review events<Icon name="arrowr" size={13} /></button>
            </div>
            <div className="active-detection-list">
              {activeRules.length === 0 && <div className="active-detection-empty">No detections in the last 24 hours.</div>}
              {activeRules.map((rule) => (
                <div key={rule.rule_id}
                  className={"active-detection" + (focus ? (focus.rule === rule.rule_id ? " is-focus" : " is-dim") : "")}
                  onMouseEnter={() => setFocus({ rule: rule.rule_id, from: "list" })}
                  onMouseLeave={() => setFocus(null)}>
                  <div className="active-detection-copy">
                    <div className="active-detection-message">{rule.message || "Unnamed detection"}</div>
                    <div className="active-detection-meta">
                      <CatTag cat={rule.cat} />
                      <span className={`tag plain ${rule.action === "block" ? "danger" : "warning"}`}>
                        {rule.action === "block" ? "Blocked" : "Detected"}
                      </span>
                      <span className="active-detection-facts mono">
                        {fmt(rule.ips)} IP{rule.ips === 1 ? "" : "s"} · {rule.services} service{rule.services === 1 ? "" : "s"} · {rule.blocked_pct}% blocked
                      </span>
                    </div>
                  </div>
                  <div className="active-detection-count">
                    <strong>{fmt(rule.hits)}</strong>
                    <span>matches</span>
                  </div>
                  <span className="active-detection-meter" style={{ width: `${Math.max(6, (rule.hits / maxRuleHits) * 100)}%` }} />
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <div className="card flush">
        <div className="card-head" style={{ padding: "var(--card-pad) var(--card-pad) 14px" }}>
          <div>
            <div className="ct">Latest enforced events</div>
            <div className="cs" style={{ marginTop: 3 }}>requests Karna blocked, sanitized, or rate-limited</div>
          </div>
          <button className="btn sm" onClick={() => nav("events")}>Open events<Icon name="arrowr" size={13} /></button>
        </div>
        <table className="tbl">
          <thead><tr><th>Time</th><th>Service</th><th>Source</th><th>Request</th><th>Rule</th><th>Category</th><th className="right">Action</th></tr></thead>
          <tbody>
            {recent.length === 0 && <EmptyRow colSpan={7} label="Nothing enforced in the last 24 hours — traffic looks clean" />}
            {recent.map((e) => {
              const m = primaryMatch(e);
              const cc = e.enrichment?.geoip?.country_code;
              return (
                <tr key={e.request_id} className="clickable" tabIndex={0} onClick={() => nav("events", e.request_id)}
                  onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); nav("events", e.request_id); } }}>
                  <td className="mono" style={{ color: "var(--fg-3)", whiteSpace: "nowrap" }}>{whenOf(e.timestamp)}</td>
                  <td>{e.service.name}</td>
                  <td><span className="row" style={{ gap: 7 }}><Flag cc={cc} /><span className="mono">{e.client.ip}</span></span></td>
                  <td><span className="mono" style={{ color: "var(--fg-2)" }}>{e.request.method} {e.request.uri.length > 28 ? e.request.uri.slice(0, 28) + "…" : e.request.uri}</span></td>
                  <td className="mono" style={{ color: "var(--accent)" }}>{m?.rule_id}</td>
                  <td><CatTag cat={eventCategory(e)} /></td>
                  <td className="right"><ActionTag disposition={eventDisposition(e)} /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
