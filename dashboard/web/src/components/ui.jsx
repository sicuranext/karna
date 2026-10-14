/* Small shared UI atoms used across views. */
import React from "react";
import { Icon } from "./icons.jsx";
import { Sparkline } from "./charts.jsx";
import { categoryMeta } from "../data/categories.js";

/* Copy-to-clipboard icon button with a brief "copied" acknowledgement. */
export function CopyBtn({ text, label = "Copy" }) {
  const [done, setDone] = React.useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(text).then(() => {
      setDone(true);
      setTimeout(() => setDone(false), 1200);
    });
  };
  return (
    <button className="icon-btn copy-btn" title={label} aria-label={label} onClick={copy}
      style={done ? { color: "var(--success)", borderColor: "var(--success)" } : undefined}>
      <Icon name={done ? "check" : "copy"} size={13} />
    </button>
  );
}

export function KpiCard({ label, value, unit, delta, dir, sub, spark, sparkColor = "var(--accent)" }) {
  return (
    <div className="card kpi">
      <div className="k-top">
        <span className="k-label">{label}</span>
        {spark && <Sparkline data={spark} color={sparkColor} />}
      </div>
      <div className="k-val">{value}{unit && <span className="u">{unit}</span>}</div>
      <div className="k-foot">
        {delta != null && (
          <span className={"delta " + (dir || "neutral")}>
            <Icon name={dir === "down" ? "down" : "up"} size={12} stroke={2} />{delta}
          </span>
        )}
        {sub && <span className="k-sub">{sub}</span>}
      </div>
    </div>
  );
}

// Request-level disposition tag. Labels match Karna's real action vocabulary.
const DISPOSITION = {
  blocked:      { cls: "danger",  label: "blocked" },
  rate_limited: { cls: "danger",  label: "rate-limited" },
  sanitized:    { cls: "accent",  label: "sanitized" },
  detected:     { cls: "warning", label: "detected" },
  observed:     { cls: "info",    label: "observed" },
  allowed:      { cls: "success", label: "allowed" },
};
export function ActionTag({ disposition }) {
  const d = DISPOSITION[disposition] || DISPOSITION.allowed;
  return <span className={`tag ${d.cls} dot`}>{d.label}</span>;
}

export function CatTag({ cat }) {
  const c = categoryMeta(cat);
  return (
    <span className="tag" style={{ color: c.color, borderColor: c.color ? `color-mix(in srgb, ${c.color} 36%, transparent)` : undefined }}>
      {c.name}
    </span>
  );
}

export function Flag({ cc }) {
  if (!cc) return null;
  return (
    <span className="mono" style={{ fontSize: 10, color: "var(--fg-3)", border: "1px solid var(--border-2)", borderRadius: 3, padding: "1px 4px" }}>
      {cc}
    </span>
  );
}
