import React from "react";
import { Brand } from "../components/brand.jsx";
import { Icon } from "../components/icons.jsx";
import { CopyBtn } from "../components/ui.jsx";
import { api } from "../data/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";

/* First-run setup, shown after sign-in until it is finished or skipped once
 * (kept server-side), and again from Settings → "Run setup again".
 * Every step uses the same endpoints as Settings, so nothing here is special:
 * it is a guided path through the settings that matter on day one. */

const STEPS = ["Kong", "AI assistant", "Done"];
const plural = (n, one, many) => `${n ?? "—"} ${n === 1 ? one : many}`;
const TRY_CMD = 'curl "http://127.0.0.1:8000/?q=<script>alert(1)</script>"';

function Stepper({ step }) {
  return (
    <ol className="setup-steps" aria-label="Setup progress">
      {STEPS.map((label, i) => {
        const n = i + 1;
        const state = step > n ? "done" : step === n ? "current" : "todo";
        return (
          <li key={label} className={state} aria-current={state === "current" ? "step" : undefined}>
            <span className="setup-step-n">{state === "done" ? <Icon name="check" size={12} /> : n}</span>
            <span>{label}</span>
          </li>
        );
      })}
    </ol>
  );
}

function Welcome({ onStart, onSkip, busy }) {
  return (
    <React.Fragment>
      <h1 className="setup-title">Welcome to Karna Console</h1>
      <p className="setup-lead">
        Two short steps: check which Kong this console manages, then, if you want, connect a model for the
        assistant. You can change all of it later in Settings.
      </p>
      <div className="setup-foot">
        <button type="button" className="btn link" onClick={onSkip} disabled={busy}>Skip setup</button>
        <span className="spacer" />
        <button type="button" className="btn primary" onClick={onStart} autoFocus>Start<Icon name="arrowr" size={14} /></button>
      </div>
    </React.Fragment>
  );
}

const EMPTY_KONG = { name: "Kong", protocol: "http", host: "", port: "8001" };

function KongStep({ kong, setKong, onBack, onNext }) {
  const [checking, setChecking] = React.useState(false);
  const [other, setOther] = React.useState(false);
  const [form, setForm] = React.useState(EMPTY_KONG);
  const [busy, setBusy] = React.useState(false);
  const [formError, setFormError] = React.useState("");
  const [tokenConfigured, setTokenConfigured] = React.useState(false);

  const summarize = (response) => ({
    connected: Boolean(response.connected && response.activated !== false),
    name: response.name, url: response.url, detail: response.detail,
    version: response.version ?? response.metadata?.version,
    services: response.services_count ?? response.metadata?.services_count,
    karna: response.karna_plugins_count ?? response.metadata?.karna_plugins_count,
  });

  // Probe the active connection: the one from the environment on a new install.
  const check = React.useCallback(async () => {
    setChecking(true);
    try {
      const list = await api.kongConnections();
      setTokenConfigured(Boolean(list.token_configured));
      const active = (list.connections || []).find((c) => c.active) || list.connections?.[0];
      if (!active) { setKong({ connected: false, detail: "No Kong connection configured" }); return; }
      const response = await api.activateKongConnection(active.id);
      setKong(summarize({ ...active, ...response }));
    } catch (err) {
      setKong({ connected: false, detail: err.message });
    } finally {
      setChecking(false);
    }
  }, [setKong]);

  React.useEffect(() => { if (!kong) check(); }, [kong, check]);

  const host = form.host.trim();
  const port = Number(form.port);
  const valid = host && !/[\s/@?#]/.test(host) && /^\d+$/.test(String(form.port)) && port >= 1 && port <= 65535;
  const change = (key) => (e) => { setForm((f) => ({ ...f, [key]: e.target.value })); setFormError(""); };

  const testOther = async (e) => {
    e.preventDefault();
    if (!valid) return;
    setBusy(true); setFormError("");
    try {
      const response = await api.testKongConnection({ name: form.name.trim() || "Kong", protocol: form.protocol, host, port });
      if (!response.connected || !response.activated) { setFormError(response.detail || "Kong is unreachable"); return; }
      setKong(summarize(response));
      setOther(false);
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const status = checking || !kong
    ? <span className="tag">Checking…</span>
    : kong.connected
      ? <span className="tag dot success">Connected{kong.version ? ` · Kong ${kong.version}` : ""}</span>
      : <span className="tag dot danger">Unreachable</span>;

  return (
    <React.Fragment>
      <h1 className="setup-title">Connect to Kong</h1>
      <p className="setup-lead">
        The console reads your services and changes Karna's configuration through the Kong Admin API.
        This is the Kong it is using now.
      </p>

      <div className="setup-box">
        <div className="between" style={{ gap: 12 }}>
          <div style={{ minWidth: 0 }}>
            <strong>{kong?.name || "Active Kong"}</strong>
            <div className="mono hint setup-ellipsis">{kong?.url || "—"}</div>
          </div>
          {status}
        </div>
        {kong?.connected && (
          <div className="setup-inventory">
            <span><strong>{kong.services ?? "—"}</strong> {kong.services === 1 ? "service" : "services"}</span>
            <span><strong>{kong.karna ?? "—"}</strong> protected by Karna</span>
          </div>
        )}
        {kong && !kong.connected && !checking && (
          <p className="hint setup-error">{kong.detail || "Kong did not answer."} Check that the Admin API is reachable from the console's API container, or connect a different Kong below.</p>
        )}
        {kong?.connected && kong.karna === 0 && (
          <p className="hint" style={{ margin: "10px 0 0" }}>No service runs Karna yet. After setup, add one from Services.</p>
        )}
        <div className="row" style={{ gap: 8, marginTop: 14 }}>
          <button type="button" className="btn sm" onClick={check} disabled={checking || busy}><Icon name="refresh" size={12} />Check again</button>
          {!other && <button type="button" className="btn sm" onClick={() => setOther(true)}>Use a different Kong</button>}
        </div>
      </div>

      {other && (
        <form className="setup-box" onSubmit={testOther}>
          <div className="sec-h" style={{ marginTop: 0 }}>A different Kong</div>
          <div className="setup-kong-fields">
            <div className="field"><label htmlFor="setup-kong-protocol">Protocol</label>
              <select id="setup-kong-protocol" className="input sel mono" value={form.protocol} onChange={change("protocol")}><option value="http">http</option><option value="https">https</option></select></div>
            <div className="field"><label htmlFor="setup-kong-host">Admin API host</label>
              <input id="setup-kong-host" className="input mono" value={form.host} onChange={change("host")} placeholder="kong.internal" autoComplete="off" spellCheck={false} autoFocus /></div>
            <div className="field"><label htmlFor="setup-kong-port">Port</label>
              <input id="setup-kong-port" className="input mono" type="number" min={1} max={65535} value={form.port} onChange={change("port")} /></div>
            <div className="field"><label htmlFor="setup-kong-name">Name</label>
              <input id="setup-kong-name" className="input" value={form.name} onChange={change("name")} placeholder="Production" autoComplete="off" /></div>
          </div>
          <p className="hint" style={{ margin: "0 0 12px" }}>
            The address is resolved from the console's API container, not from your browser.{" "}
            {tokenConfigured
              ? "An Admin API token is configured and is sent only to its configured origin."
              : <>If your Kong needs an Admin API token, set <span className="mono">KONG_ADMIN_TOKEN</span> on that container.</>}
          </p>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <button type="submit" className="btn primary sm" disabled={!valid || busy}>{busy ? "Testing…" : "Test and use"}</button>
            <button type="button" className="btn sm" onClick={() => { setOther(false); setFormError(""); }} disabled={busy}>Cancel</button>
            {formError && <span className="tag danger">{formError}</span>}
          </div>
        </form>
      )}

      <div className="setup-foot">
        <button type="button" className="btn" onClick={onBack}>Back</button>
        <span className="spacer" />
        {kong?.connected
          ? <button type="button" className="btn primary" onClick={onNext}>Continue<Icon name="arrowr" size={14} /></button>
          : <button type="button" className="btn" onClick={onNext} disabled={checking}>Continue without Kong</button>}
      </div>
    </React.Fragment>
  );
}

function AiStep({ ai, setAi, onBack, onNext }) {
  const [providers, setProviders] = React.useState([]);
  const [existing, setExisting] = React.useState(0);
  const [form, setForm] = React.useState({ provider: "", base_url: "", model: "", api_key: "", bill_to: "" });
  const [busy, setBusy] = React.useState("");
  const [probe, setProbe] = React.useState(null);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    Promise.all([api.aiProviders(), api.aiProfiles()]).then(([p, profiles]) => {
      const list = p.providers || [];
      setProviders(list);
      setExisting((profiles.profiles || []).length);
      const first = list.find((x) => x.id === "ollama") || list[0];
      if (first) setForm((f) => ({ ...f, provider: first.id, base_url: first.default_base_url }));
    }).catch((err) => setError(err.message));
  }, []);

  const provider = providers.find((x) => x.id === form.provider);
  const baseEditable = provider?.local || provider?.id === "custom";
  const keyRequired = provider?.api_key_required;
  const valid = form.provider && form.model.trim() && form.base_url.trim() && (!keyRequired || form.api_key.trim());

  const set = (key) => (e) => { setForm((f) => ({ ...f, [key]: e.target.value })); setError(""); setProbe(null); };
  const setProvider = (e) => {
    const next = providers.find((x) => x.id === e.target.value);
    setForm({ provider: next.id, base_url: next.default_base_url, model: "", api_key: "", bill_to: "" });
    setError(""); setProbe(null);
  };
  const payload = () => ({
    name: `${provider?.label || form.provider} · ${form.model.trim()}`.slice(0, 64),
    provider: form.provider, base_url: form.base_url.trim(), model: form.model.trim(), is_default: true,
    ...(form.api_key.trim() ? { api_key: form.api_key.trim() } : {}),
    options: form.provider === "huggingface" && form.bill_to.trim() ? { bill_to: form.bill_to.trim() } : {},
  });

  const test = async () => {
    if (!valid) return;
    setBusy("test"); setError(""); setProbe(null);
    try {
      const response = await api.testAiProfile(payload());
      setProbe(response);
      if (!response.connected) setError(response.detail || "The provider did not answer");
    } catch (err) { setError(err.message); } finally { setBusy(""); }
  };
  const save = async () => {
    if (!valid) return;
    setBusy("save"); setError("");
    try {
      const response = await api.saveAiProfile(payload());
      setAi({ name: response.profile.name });
      onNext();
    } catch (err) { setError(err.message); } finally { setBusy(""); }
  };

  return (
    <React.Fragment>
      <h1 className="setup-title">AI assistant <span className="hint" style={{ fontSize: 14, fontWeight: 500 }}>· optional</span></h1>
      <p className="setup-lead">
        The assistant drafts configuration changes from a conversation, using a model you choose. It never applies
        anything by itself: every proposal waits for you to review and confirm it.
      </p>
      {existing > 0 && !ai && (
        <p className="hint" style={{ margin: "0 0 14px" }}>
          You already have {existing} AI {existing === 1 ? "profile" : "profiles"}. Add another one here, or skip this step.
        </p>
      )}

      <div className="setup-box">
        <div className="setup-ai-fields">
          <div className="field"><label htmlFor="setup-ai-provider">Provider</label>
            <select id="setup-ai-provider" className="input sel" value={form.provider} onChange={setProvider}>
              {providers.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}
            </select></div>
          <div className="field"><label htmlFor="setup-ai-model">Model</label>
            <input id="setup-ai-model" className="input mono" list="setup-ai-models" value={form.model} onChange={set("model")}
              placeholder={provider?.local ? "qwen3:8b" : "model id"} autoComplete="off" spellCheck={false} />
            <datalist id="setup-ai-models">{(probe?.models || []).map((m) => <option key={m} value={m} />)}</datalist></div>
          {baseEditable && (
            <div className="field setup-span"><label htmlFor="setup-ai-url">Base URL</label>
              <input id="setup-ai-url" className="input mono" value={form.base_url} onChange={set("base_url")} autoComplete="off" spellCheck={false} /></div>
          )}
          {(keyRequired || provider?.id === "custom") && (
            <div className="field setup-span"><label htmlFor="setup-ai-key">API key {keyRequired ? "" : <span className="hint">· optional</span>}</label>
              <input id="setup-ai-key" className="input mono" type="password" value={form.api_key} onChange={set("api_key")} autoComplete="new-password" /></div>
          )}
          {form.provider === "huggingface" && (
            <div className="field setup-span"><label htmlFor="setup-ai-bill-to">Bill to <span className="hint">· optional</span></label>
              <input id="setup-ai-bill-to" className="input mono" value={form.bill_to} onChange={set("bill_to")} placeholder="organization or resource-group ID" autoComplete="off" spellCheck={false} /></div>
          )}
        </div>
        <p className="hint" style={{ margin: "0 0 12px" }}>
          {provider?.local
            ? `${provider.label} runs on this machine: the console reaches it at host.docker.internal. Requests stay local.`
            : "Prompts and the parts of your configuration the assistant reads are sent to this provider. The key is stored encrypted and never sent back to the browser."}
        </p>
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <button type="button" className="btn sm" onClick={test} disabled={!valid || Boolean(busy)}><Icon name="refresh" size={12} />{busy === "test" ? "Testing…" : "Test connection"}</button>
          {probe?.connected && (
            <span className={`tag ${probe.model_available === false ? "warning" : "success"}`}>
              {probe.model_available === false ? "Connected · model not found, pick one from the list" : `Connected · ${probe.latency_ms} ms`}
            </span>
          )}
          {error && <span className="tag danger">{error}</span>}
        </div>
      </div>

      <div className="setup-foot">
        <button type="button" className="btn" onClick={onBack}>Back</button>
        <span className="spacer" />
        <button type="button" className="btn" onClick={() => { setAi(null); onNext(); }} disabled={Boolean(busy)}>Skip for now</button>
        <button type="button" className="btn primary" onClick={save} disabled={!valid || Boolean(busy)}>{busy === "save" ? "Saving…" : "Save and continue"}</button>
      </div>
    </React.Fragment>
  );
}

function DoneStep({ kong, ai, onBack, onFinish, busy, error }) {
  const noKarna = kong?.connected && kong.karna === 0;
  return (
    <React.Fragment>
      <h1 className="setup-title">You're set</h1>
      <ul className="setup-summary">
        <li className={kong?.connected ? "ok" : "warn"}>
          <Icon name={kong?.connected ? "check" : "x"} size={14} />
          <span>{kong?.connected
            ? <>Kong <strong>{kong.name}</strong> connected, {kong.karna ?? 0} of {plural(kong.services ?? 0, "service", "services")} protected by Karna</>
            : "Kong not connected yet: set it in Settings → Kong connections"}</span>
        </li>
        <li className={ai ? "ok" : "skip"}>
          <Icon name={ai ? "check" : "chat"} size={14} />
          <span>{ai ? <>Assistant ready with <strong>{ai.name}</strong></> : "Assistant not configured: add a model later in Settings → AI profiles"}</span>
        </li>
      </ul>

      <div className="setup-box">
        <div className="sec-h" style={{ marginTop: 0 }}>Try it</div>
        {noKarna ? (
          <p className="hint" style={{ margin: 0 }}>Add Karna to a service from Services, then send it a request: every request Karna inspects shows up in Events.</p>
        ) : (
          <React.Fragment>
            <p className="hint" style={{ margin: "0 0 8px" }}>Send an attack through Kong's proxy (127.0.0.1:8000 with the quickstart) and watch it in Events.</p>
            <div className="row" style={{ gap: 6 }}>
              <code className="mono setup-cmd">{TRY_CMD}</code>
              <CopyBtn text={TRY_CMD} label="Copy command" />
            </div>
          </React.Fragment>
        )}
      </div>

      {error && <p className="tag danger" style={{ marginTop: 12 }}>{error}</p>}
      <div className="setup-foot">
        <button type="button" className="btn" onClick={onBack} disabled={busy}>Back</button>
        <span className="spacer" />
        {noKarna && <button type="button" className="btn" onClick={() => onFinish("services")} disabled={busy}>Go to Services</button>}
        <button type="button" className="btn primary" onClick={() => onFinish(noKarna ? "overview" : "events")} disabled={busy} autoFocus>
          {busy ? "…" : noKarna ? "Open the console" : "Open Events"}
        </button>
      </div>
    </React.Fragment>
  );
}

export default function Setup({ onDone }) {
  const { email, logout } = useAuth();
  const [step, setStep] = React.useState(0);
  const [kong, setKong] = React.useState(null);
  const [ai, setAi] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  const finish = async (view, skipped = false) => {
    setBusy(true); setError("");
    try {
      await api.completeSetup(skipped);
      onDone(view);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <div className="setup-page" data-theme="dark" data-accent="gold" data-density="airy">
      <div className="setup-wrap">
        <div className="row setup-brand">
          <Brand size={30} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 16, letterSpacing: "-0.01em" }}>Karna</div>
            <div className="mono" style={{ fontSize: 11, color: "var(--fg-3)" }}>Console setup</div>
          </div>
          {email && (
            <div className="setup-user">
              <span className="hint">Signed in as <span className="mono">{email}</span></span>
              <button type="button" className="btn link" onClick={logout}>Sign out</button>
            </div>
          )}
        </div>
        {step > 0 && <Stepper step={step} />}
        <div className="card setup-card">
          {step === 0 && <Welcome onStart={() => setStep(1)} onSkip={() => finish("overview", true)} busy={busy} />}
          {step === 1 && <KongStep kong={kong} setKong={setKong} onBack={() => setStep(0)} onNext={() => setStep(2)} />}
          {step === 2 && <AiStep ai={ai} setAi={setAi} onBack={() => setStep(1)} onNext={() => setStep(3)} />}
          {step === 3 && <DoneStep kong={kong} ai={ai} onBack={() => setStep(2)} onFinish={finish} busy={busy} error={error} />}
          {step === 0 && error && <p className="tag danger" style={{ marginTop: 12 }}>{error}</p>}
        </div>
      </div>
    </div>
  );
}
