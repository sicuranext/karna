/* Data layer. One assemble() maps the raw shape (the keys exported by
 * sample.js — and returned verbatim by the FastAPI backend at /api/dashboard)
 * into the display model the views consume. Sample vs live is just where that
 * raw shape comes from, chosen at build time via VITE_DATA_MODE. */
import { useCallback, useEffect, useState } from "react";
import * as S from "./sample.js";
import { api } from "./api.js";
import { MODE } from "./mode.js";
import { demoPayload, onDemoChange } from "./demo.js";
import { categoryForRule, categoryMeta } from "./categories.js";

export { MODE };

export const fmt = (n) => Number(n).toLocaleString("en-US");
export const dateOf = (iso) => new Date(iso);
export const clockOf = (iso) => new Date(iso).toTimeString().slice(0, 8);

/* Unambiguous event time: clock plus the date whenever it isn't today
 * ("16:32:08" today, "Jun 16 · 16:32:08" otherwise). */
export function whenOf(iso) {
  const d = new Date(iso);
  const now = new Date();
  const clock = d.toTimeString().slice(0, 8);
  if (d.toDateString() === now.toDateString()) return clock;
  const day = d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  return `${day} · ${clock}`;
}

const VIA = {
  sqli: "libinjection_sqli", xss: "libinjection_xss", rce: "CRS 932/933",
  lfi: "CRS 930", rfi: "CRS 931", php: "CRS 933", java: "CRS 944",
  generic: "CRS 934", scanner: "CRS 913", proto: "gates · 920-922",
  session: "CRS 943", mcp: "mcp_method_in", gate: "always-on gates", other: "—",
};

/* ---- helpers over a real audit log v2 event ---- */
export function primaryMatch(ev) {
  return ev.matches && ev.matches.length ? ev.matches[0] : null;
}
export function eventCategory(ev) {
  const m = primaryMatch(ev);
  return m ? categoryForRule(m.rule_id, m.tags) : "other";
}
// Request-level disposition derived from the per-match actions + status.
export function eventDisposition(ev) {
  const acts = (ev.matches || []).map((m) => m.action);
  if (acts.includes("block")) return "blocked";
  if (acts.includes("rate_limited")) return "rate_limited";
  if (acts.includes("sanitized")) return "sanitized";
  if (acts.includes("detect")) return "detected";
  if (acts.length && acts.every((a) => a === "log")) return "observed";
  return "allowed";
}

// raw -> display model. `src` has the keys exported by sample.js / returned by
// the backend (ENGINE, TRAFFIC, CATEGORY_COUNTS, ...).
function assemble(src) {
  const traffic = src.TRAFFIC || [];
  const totalReq = traffic.reduce((a, b) => a + b.requests, 0);
  const totalBlk = traffic.reduce((a, b) => a + b.blocked, 0);

  const categories = (src.CATEGORY_COUNTS || []).map((c) => {
    const meta = categoryMeta(c.id);
    return { id: c.id, name: meta.name, color: meta.color, count: c.count, via: VIA[c.id] };
  });

  const topRules = (src.TOP_RULES || []).map((r) => ({ ...r, cat: categoryForRule(r.rule_id, []) }));
  const ruleActivity = (src.RULE_ACTIVITY || []).map((r) => ({ ...r, cat: categoryForRule(r.rule_id, []) }));

  return {
    engine: src.ENGINE || {},
    traffic,
    totalReq,
    totalBlk,
    blockRate: totalReq ? +((totalBlk / totalReq) * 100).toFixed(2) : 0,
    categories,
    topRules,
    ruleActivity,
    services: src.SERVICES || [],
    events: src.EVENTS || [],
    ruleActionOverrides: src.RULE_ACTION_OVERRIDES || [],
    ruleResponseOverrides: src.RULE_RESPONSE_OVERRIDES || [],
    crsRulesets: src.CRS_RULESETS || {},
    localRules: src.LOCAL_RULES || [],
    customSecrules: src.CUSTOM_SECRULES || [],
    crsPlugins: src.CRS_PLUGINS || [],
    crsFixImpact: src.CRS_FIX_IMPACT || { pruned: 0, bridged: 0, buckets: [] },
    redis: src.REDIS || {},
    logSources: src.LOG_SOURCES || [],
    latency: src.LATENCY || { p50: 0, p95: 0, p99: 0, max: 0 },
    changes: src.CHANGES || [],
    kongConnected: src.KONG_CONNECTED !== false, // sample (undefined) treated as connected
    kongConnection: src.KONG_CONNECTION || null,
  };
}

// The whole sample module, bundled into the raw shape.
const SAMPLE_SRC = {
  ENGINE: S.ENGINE, TRAFFIC: S.TRAFFIC, CATEGORY_COUNTS: S.CATEGORY_COUNTS,
  TOP_RULES: S.TOP_RULES, RULE_ACTIVITY: S.RULE_ACTIVITY, SERVICES: S.SERVICES, EVENTS: S.EVENTS,
  RULE_ACTION_OVERRIDES: S.RULE_ACTION_OVERRIDES, RULE_RESPONSE_OVERRIDES: S.RULE_RESPONSE_OVERRIDES,
  CRS_RULESETS: S.CRS_RULESETS, LOCAL_RULES: S.LOCAL_RULES, CUSTOM_SECRULES: S.CUSTOM_SECRULES,
  CRS_PLUGINS: S.CRS_PLUGINS, CRS_FIX_IMPACT: S.CRS_FIX_IMPACT, REDIS: S.REDIS,
  LOG_SOURCES: S.LOG_SOURCES, LATENCY: S.LATENCY, CHANGES: S.CHANGES,
  KONG_CONNECTION: S.KONG_CONNECTION,
};

// Single hook for every view. Same loading/error contract in both modes.
export function useDashboard() {
  const [state, setState] = useState({ data: null, loading: true, error: null });
  const [inventoryState, setInventoryState] = useState({ loading: false, error: null });
  const [nonce, setNonce] = useState(0);
  const refresh = useCallback(() => setNonce((n) => n + 1), []);
  const refreshInventory = useCallback(async () => {
    if (MODE !== "live") return;
    setInventoryState({ loading: true, error: null });
    try {
      const result = await api.refreshKongInventory();
      if (!result.connected) throw new Error("Kong Admin API is unreachable");
      setNonce((n) => n + 1);
    } catch (error) {
      setInventoryState({ loading: false, error: error.message || String(error) });
      return;
    }
    setInventoryState({ loading: false, error: null });
  }, []);

  useEffect(() => (MODE === "demo" ? onDemoChange(refresh) : undefined), [refresh]);

  useEffect(() => {
    let alive = true;
    if (MODE === "sample") {
      setState({ data: assemble(SAMPLE_SRC), loading: false, error: null });
      return;
    }
    if (MODE === "demo") {
      setState({ data: assemble(demoPayload(SAMPLE_SRC)), loading: false, error: null });
      return;
    }
    setState((s) => ({ ...s, loading: true, error: null }));
    api.dashboard()
      .then((json) => { if (alive) setState({ data: assemble(json), loading: false, error: null }); })
      .catch((err) => { if (alive) setState((s) => ({ data: s.data, loading: false, error: err.message || String(err) })); });
    return () => { alive = false; };
  }, [nonce]);

  return {
    ...state, mode: MODE, refresh, refreshInventory,
    inventoryRefreshing: inventoryState.loading,
    inventoryError: inventoryState.error,
  };
}
