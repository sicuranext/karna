import React from "react";
import { Brand, PoweredBy } from "./components/brand.jsx";
import { Icon } from "./components/icons.jsx";
import { LoadingScreen, ErrorScreen } from "./components/states.jsx";
import { CommandPalette } from "./components/CommandPalette.jsx";
import { ConfirmProvider } from "./components/ConfirmProvider.jsx";
import { useDashboard, MODE } from "./data/index.js";
import { useRoute } from "./router.js";
import { AuthProvider, useAuth } from "./auth/AuthProvider.jsx";
import { api } from "./data/api.js";
import Login from "./views/Login.jsx";
import Setup from "./views/Setup.jsx";
import Overview from "./views/Overview.jsx";
import Events from "./views/Events.jsx";
import Services from "./views/Services.jsx";
import Rules from "./views/Rules.jsx";
import Audit from "./views/Audit.jsx";
import Settings from "./views/Settings.jsx";

const Assistant = React.lazy(() => import("./views/Assistant.jsx"));

const NAV = [
  { id: "overview", label: "Overview", icon: "grid" },
  { id: "events", label: "Events", icon: "pulse" },
  { id: "services", label: "Services", icon: "cube" },
  { id: "rules", label: "Rules", icon: "layers" },
  { id: "assistant", label: "Assistant", icon: "chat" },
  { id: "audit", label: "Audit", icon: "history" },
  { id: "settings", label: "Settings", icon: "gear" },
];

function Sidebar({ view, nav, data }) {
  const { authed, email, logout } = useAuth();
  return (
    <nav className="sidebar">
      <div className="sb-brand">
        <span className="seal"><Brand size={30} /></span>
        <div>
          <div className="word">Karna</div>
          <div className="sub">WAF Console</div>
        </div>
      </div>

      {!data.kongConnected && (
        <div className="row" style={{ gap: 8, margin: "12px 12px 0", padding: "9px 11px", borderRadius: "var(--r-md)",
          background: "var(--danger-soft)", color: "var(--danger)", border: "1px solid color-mix(in srgb, var(--danger) 28%, transparent)" }}>
          <Icon name="flame" size={14} />
          <span style={{ fontSize: 12, fontWeight: 500 }}>Kong Admin unreachable</span>
        </div>
      )}

      <div className="sb-nav">
        <div className="sb-group">
          {NAV.map((it) => (
            <button key={it.id} className={"sb-item" + (view === it.id ? " active" : "")} onClick={() => nav(it.id)}>
              <Icon name={it.icon} size={17} />
              <span>{it.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="sb-foot">
        {authed ? (
          <React.Fragment>
            <span className="mono" style={{ fontSize: 11, color: "var(--fg-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={email}>{email}</span>
            <span className="spacer" style={{ flex: 1 }} />
            <button className="icon-btn" title="Sign out" aria-label="Sign out" onClick={logout}><Icon name="arrowr" size={16} /></button>
          </React.Fragment>
        ) : (
          <React.Fragment>
            <span className="mono" style={{ fontSize: 11, color: "var(--fg-3)" }}>karna {data.engine.version}</span>
            <span className="spacer" style={{ flex: 1 }} />
            <span className="mono" style={{ fontSize: 11, color: "var(--fg-4)" }}>{MODE === "demo" ? "live demo" : "read-only"}</span>
          </React.Fragment>
        )}
      </div>
    </nav>
  );
}

function Topbar({ onSearch, onOpenConnections, data }) {
  const connection = data.kongConnection || {};
  const kongVersion = connection.metadata?.version;
  const kongName = connection.name || "Active Kong";
  const kongEndpoint = connection.url || "Endpoint not configured";
  const karnaVersion = data.engine?.version && data.engine.version !== "unknown"
    ? data.engine.version
    : "unknown";
  return (
    <React.Fragment>
      <header className="topbar">
        <button type="button" className="topbar-context topbar-target" onClick={onOpenConnections}
          aria-label={`Open Kong connections. Active target: ${kongName}, ${kongEndpoint}`}>
          <span className={"system-dot " + (data.kongConnected ? "online" : "offline")} />
          <div className="topbar-target-copy">
            <span className="topbar-label">
              {kongName}
              {connection.metadata?.hostname && <span> · {connection.metadata.hostname}</span>}
            </span>
            <span className="topbar-state">
              <strong>{data.kongConnected ? `Kong ${kongVersion || "connected"}` : "Kong unreachable"}</strong>
              <span className="topbar-endpoint mono">{kongEndpoint}</span>
              <span className="topbar-separator" aria-hidden="true">/</span>
              <span>Karna {karnaVersion}</span>
            </span>
          </div>
          <Icon name="chev" size={12} />
        </button>
        <span className="spacer" />
        <PoweredBy />
        <button className="search search-btn" onClick={onSearch} aria-label="Search (Cmd+K)">
          <Icon name="search" size={15} />
          <span className="ph">Search services, rules, events…</span>
          <span className="kbd">⌘K</span>
        </button>
      </header>
      <div className="scanline" />
    </React.Fragment>
  );
}

function MobileNav({ view, nav }) {
  return (
    <nav className="mobile-nav" aria-label="Primary navigation">
      {NAV.map((it) => (
        <button key={it.id} className={view === it.id ? "active" : ""} onClick={() => nav(it.id)}>
          <Icon name={it.icon} size={18} />
          <span>{it.label}</span>
        </button>
      ))}
    </nav>
  );
}

function DashboardApp() {
  const {
    data, loading, error, refresh, refreshInventory,
    inventoryRefreshing, inventoryError, mode,
  } = useDashboard();
  const { route, nav, navReplace } = useRoute();
  const [paletteOpen, setPaletteOpen] = React.useState(false);
  const [ruleDraft, setRuleDraft] = React.useState(null);
  const openRuleDraft = React.useCallback((draft) => {
    setRuleDraft(draft);
    nav("rules");
  }, [nav]);
  const clearRuleDraft = React.useCallback(() => setRuleDraft(null), []);

  // Live mode: poll for fresh data every 15s.
  React.useEffect(() => {
    if (mode !== "live") return;
    const t = setInterval(refresh, 15000);
    return () => clearInterval(t);
  }, [mode, refresh]);

  // ⌘K / Ctrl+K opens the palette from anywhere.
  React.useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Scroll to top when the view (not just the param) changes.
  const view = route.view;
  React.useEffect(() => {
    const vp = document.querySelector(".view");
    if (vp) vp.scrollTop = 0;
  }, [view]);

  if (loading && !data) return <LoadingScreen />;
  if (error && !data) return <ErrorScreen error={error} onRetry={refresh} />;

  const writable = mode === "live" || mode === "demo";
  const common = {
    data, nav, navReplace, writable, refresh, refreshInventory,
    inventoryRefreshing, inventoryError, param: route.param,
    ruleDraft, openRuleDraft, clearRuleDraft,
  };
  let Body = null;
  if (view === "overview") Body = <Overview {...common} />;
  else if (view === "events") Body = <Events {...common} />;
  else if (view === "services") Body = <Services {...common} />;
  else if (view === "rules") Body = <Rules {...common} />;
  else if (view === "assistant") Body = <Assistant {...common} />;
  else if (view === "audit") Body = <Audit {...common} />;
  else if (view === "settings") Body = <Settings {...common} />;

  return (
    <div className="app" data-theme="dark" data-accent="gold" data-density="airy" data-charts="rich">
      <Sidebar view={view} nav={nav} data={data} />
      <div className="main">
        {MODE === "demo" && <DemoBanner />}
        <Topbar onSearch={() => setPaletteOpen(true)} onOpenConnections={() => nav("settings")} data={data} />
        <div className="view" key={view}><React.Suspense fallback={<LoadingScreen />}>{Body}</React.Suspense></div>
      </div>
      <MobileNav view={view} nav={nav} />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} data={data} nav={nav} />
    </div>
  );
}

/* The public demo says what it is: sample data, changes kept in this tab only. */
function DemoBanner() {
  return (
    <div className="demo-banner" role="note">
      <span><strong>Live demo.</strong> Sample data, no real traffic. Your changes stay in this browser tab and reset when you reload.</span>
      <a href="https://github.com/sicuranext/karna" target="_blank" rel="noreferrer noopener">Get Karna <Icon name="arrowr" size={12} /></a>
    </div>
  );
}

// The first-run setup shows until it is finished or skipped once (kept on the
// server), and again on #/setup ("Run setup again" in Settings).
const SETUP_HASH = "#/setup";

function SetupGate() {
  const [completed, setCompleted] = React.useState(null);
  const [forced, setForced] = React.useState(() => window.location.hash === SETUP_HASH);

  React.useEffect(() => {
    api.setupState()
      .then((s) => setCompleted(Boolean(s.completed)))
      .catch(() => setCompleted(true));     // never lock the console out over this
    const onHash = () => setForced(window.location.hash === SETUP_HASH);
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  if (completed === null) return <LoadingScreen />;
  if (!completed || forced) {
    return <Setup onDone={(view) => {
      window.history.replaceState(null, "", `#/${view || "overview"}`);
      setForced(false);
      setCompleted(true);
    }} />;
  }
  return <DashboardApp />;
}

function Gate() {
  const { ready, authed } = useAuth();
  if (MODE !== "live") return <DashboardApp />;
  if (!ready) return <LoadingScreen />;
  if (!authed) return <Login />;
  return <SetupGate />;
}

export default function App() {
  return (
    <AuthProvider>
      <ConfirmProvider>
        <Gate />
      </ConfirmProvider>
    </AuthProvider>
  );
}
