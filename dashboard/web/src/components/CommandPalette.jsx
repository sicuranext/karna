/* ⌘K command palette — the topbar search, made real. Searches views,
 * protected services, custom rules, and recent events; selecting a result
 * navigates there (deep-linked via the hash router). Hand-rolled, CSP-safe. */
import React from "react";
import { Icon } from "./icons.jsx";
import { primaryMatch, eventDisposition } from "../data/index.js";

const VIEW_ITEMS = [
  { view: "overview", label: "Overview", icon: "grid" },
  { view: "events", label: "Events", icon: "pulse" },
  { view: "services", label: "Services", icon: "cube" },
  { view: "rules", label: "Rules", icon: "layers" },
  { view: "audit", label: "Audit", icon: "history" },
  { view: "settings", label: "Settings", icon: "gear" },
];

function buildResults(q, data) {
  const needle = q.trim().toLowerCase();
  const hit = (s) => s && String(s).toLowerCase().includes(needle);
  const out = [];

  const views = VIEW_ITEMS.filter((v) => !needle || hit(v.label));
  views.forEach((v) => out.push({
    kind: "Go to", icon: v.icon, primary: v.label, secondary: null,
    to: [v.view],
  }));

  if (needle) {
    data.services.filter((s) => hit(s.name) || hit(s.host)).slice(0, 5).forEach((s) => out.push({
      kind: "Service", icon: "cube", primary: s.name, secondary: s.host,
      to: ["services", s.id],
    }));
    data.localRules.filter((r) => hit(r.id) || hit(r.message)).slice(0, 5).forEach((r) => out.push({
      kind: "Rule", icon: "doc", primary: r.id, secondary: r.message || r.service,
      to: ["rules"],
    }));
    data.events.filter((e) => {
      const m = primaryMatch(e);
      return hit(e.client.ip) || hit(e.request.uri) || hit(m?.rule_id) || hit(m?.message) || hit(e.service.name);
    }).slice(0, 6).forEach((e) => {
      const m = primaryMatch(e);
      out.push({
        kind: "Event", icon: "pulse",
        primary: `${e.request.method} ${e.request.uri}`,
        secondary: `${e.client.ip} · ${m?.rule_id || "no match"} · ${eventDisposition(e)}`,
        to: ["events", e.request_id],
      });
    });
  }
  return out.slice(0, 12);
}

export function CommandPalette({ open, onClose, data, nav }) {
  const [q, setQ] = React.useState("");
  const [sel, setSel] = React.useState(0);
  const inputRef = React.useRef(null);
  const results = React.useMemo(() => (open ? buildResults(q, data) : []), [open, q, data]);

  React.useEffect(() => {
    if (open) { setQ(""); setSel(0); setTimeout(() => inputRef.current?.focus(), 0); }
  }, [open]);
  React.useEffect(() => { setSel(0); }, [q]);

  if (!open) return null;

  const go = (r) => { onClose(); nav(r.to[0], r.to[1]); };
  const onKey = (e) => {
    if (e.key === "Escape") { e.preventDefault(); onClose(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, results.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
    else if (e.key === "Enter" && results[sel]) { e.preventDefault(); go(results[sel]); }
  };

  return (
    <div className="modal-scrim" style={{ alignItems: "flex-start", paddingTop: "14vh" }} onClick={onClose}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Search" onClick={(e) => e.stopPropagation()} onKeyDown={onKey}>
        <div className="pal-input">
          <Icon name="search" size={16} />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search services, rules, events…"
            aria-label="Search services, rules, events"
          />
          <span className="kbd">esc</span>
        </div>
        <div className="pal-list">
          {results.length === 0 && <div className="pal-empty">No matches for “{q}”</div>}
          {results.map((r, i) => (
            <button
              key={`${r.kind}-${r.primary}-${i}`}
              className={"pal-item" + (i === sel ? " sel" : "")}
              onMouseEnter={() => setSel(i)}
              onClick={() => go(r)}
            >
              <Icon name={r.icon} size={15} />
              <span className="pal-primary">{r.primary}</span>
              {r.secondary && <span className="pal-secondary">{r.secondary}</span>}
              <span className="pal-kind">{r.kind}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
