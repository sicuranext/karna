/* Loading / error / empty placeholders — shared so phase-2 live fetches get
 * consistent states for free. */
import { Brand } from "./brand.jsx";
import { Icon } from "./icons.jsx";

export function LoadingScreen() {
  return (
    <div style={{ position: "fixed", inset: 0, display: "grid", placeItems: "center", background: "var(--page)" }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, opacity: 0.8 }}>
        <Brand size={40} />
        <span className="mono" style={{ color: "var(--accent)", fontSize: 12 }}>loading…</span>
      </div>
    </div>
  );
}

export function ErrorScreen({ error, onRetry }) {
  return (
    <div style={{ position: "fixed", inset: 0, display: "grid", placeItems: "center", background: "var(--page)" }}>
      <div className="card" style={{ maxWidth: 420, textAlign: "center" }}>
        <div style={{ color: "var(--danger)", marginBottom: 10 }}><Icon name="flame" size={26} /></div>
        <div style={{ fontWeight: 600, marginBottom: 6 }}>Couldn’t load data</div>
        <p className="hint" style={{ marginBottom: 14 }}>{String(error || "Unknown error")}</p>
        {onRetry && <button className="btn" onClick={onRetry}><Icon name="refresh" size={14} />Retry</button>}
      </div>
    </div>
  );
}

export function EmptyRow({ colSpan, label = "No data" }) {
  return (
    <tr>
      <td colSpan={colSpan} style={{ textAlign: "center", color: "var(--fg-4)", padding: "28px 0" }}>{label}</td>
    </tr>
  );
}
