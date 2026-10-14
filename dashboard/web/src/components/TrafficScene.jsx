import React from "react";
import { AreaChart } from "./charts.jsx";
import { Scene3D } from "./Scene3D.jsx";
import { fmt } from "../data/index.js";

/* The 24h traffic scene (scene3d/traffic.js) with its chrome.
 * Overview shows the full version (status card, focus stages, Replay);
 * `compact` drops those for pages where the chart is context, like Events. */
const loadTraffic = () => import("./scene3d/traffic.js").then((m) => m.trafficScene);
const TRAFFIC_STAGES = [
  { label: "Traffic", title: "Traffic and blocks", desc: "Every hour Karna inspected, what it stopped, and the share of traffic that was hostile." },
  { label: "Blocks", title: "What Karna stopped", desc: "Requests blocked, sanitized or rate-limited per hour, on their own scale." },
  { label: "Peak", title: "Peak blocking hour", desc: null },
];

export function TrafficScene({ data, compact = false }) {
  const peak = data.traffic.reduce((m, t) => (t.blocked > m.blocked ? t : m), data.traffic[0]) || { blocked: 0, label: "–" };
  const [stage, setStage] = React.useState(0);
  const [replay, setReplay] = React.useState(0);
  const st = TRAFFIC_STAGES[stage];
  if (data.traffic.length < 2) return <div className="k3d-fallback card"><AreaChart data={data.traffic} height={252} /></div>;
  const desc = st.desc || `${fmt(peak.blocked)} requests stopped at ${peak.label}, the busiest hour for Karna in the window.`;
  return (
    <div className={"k3d" + (compact ? " k3d-short" : "")}>
      <Scene3D load={loadTraffic} data={data.traffic} stageIndex={stage} replay={replay}
        fallback={<div className="k3d-fallback"><AreaChart data={data.traffic} height={252} /></div>}>
        {compact ? (
          <div className="k3d-status k3d-status-sm">
            <span className="k3d-step">last 24 hours · hourly</span>
            <strong>Requests over time</strong>
          </div>
        ) : (
          <div className="k3d-status" aria-live="polite">
            <span className="k3d-step">{String(stage + 1).padStart(2, "0")} / {String(TRAFFIC_STAGES.length).padStart(2, "0")}</span>
            <strong>{st.title}</strong>
            <span>{desc}</span>
          </div>
        )}
        <div className="k3d-telemetry" aria-hidden="true">
          <span className="hot">last 24 hours · hourly</span>
          <span>{fmt(data.totalReq)} inspected · {fmt(data.totalBlk)} blocked</span>
          <span>{data.services.length} services · karna {data.engine.version}</span>
        </div>
      </Scene3D>
      <div className="k3d-controls">
        {!compact && <div className="k3d-phases" role="group" aria-label="Scene focus">
          {TRAFFIC_STAGES.map((s, i) => (
            <button key={s.label} type="button" aria-pressed={stage === i} onClick={() => setStage(i)}
              disabled={i === 2 && !peak.blocked} title={i === 2 && !peak.blocked ? "No blocked requests in the window" : undefined}>
              <span>{String(i + 1).padStart(2, "0")}</span> {s.label}
            </button>
          ))}
        </div>}
        <span className="k3d-note">drag to rotate · hover the floor to read an hour</span>
        {!compact && <button type="button" className="k3d-replay" onClick={() => { setStage(0); setReplay((n) => n + 1); }}>Replay</button>}
      </div>
    </div>
  );
}
