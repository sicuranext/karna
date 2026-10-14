import React from "react";
import { Icon } from "./icons.jsx";
import { Modal } from "./modal.jsx";
import { api } from "../data/api.js";
import { MODE } from "../data/index.js";

const EMPTY = {
  id: null, name: "", provider: "ollama", base_url: "", model: "",
  api_key: "", is_default: false, options: { bill_to: "" }, api_key_configured: false,
};

function formFor(profile) {
  if (!profile) return { ...EMPTY, options: { ...EMPTY.options } };
  return {
    ...profile,
    api_key: "",
    options: { bill_to: profile.options?.bill_to || "" },
  };
}

export function AIProfilesSettings() {
  const [providers, setProviders] = React.useState([]);
  const [profiles, setProfiles] = React.useState([]);
  const [form, setForm] = React.useState(formFor());
  const [busy, setBusy] = React.useState("");
  const [error, setError] = React.useState("");
  const [note, setNote] = React.useState("");
  const [probe, setProbe] = React.useState(null);
  const [removeTarget, setRemoveTarget] = React.useState(null);

  const load = React.useCallback(async (selectId = null) => {
    if (MODE !== "live") return;
    const [providerResponse, profileResponse] = await Promise.all([api.aiProviders(), api.aiProfiles()]);
    const nextProviders = providerResponse.providers || [];
    const nextProfiles = profileResponse.profiles || [];
    setProviders(nextProviders);
    setProfiles(nextProfiles);
    if (selectId) {
      const selected = nextProfiles.find((item) => item.id === selectId);
      if (selected) setForm(formFor(selected));
    } else if (!form.id && nextProviders.length) {
      const selectedProvider = nextProviders.find((item) => item.id === form.provider) || nextProviders[0];
      setForm((current) => ({ ...current, provider: selectedProvider.id, base_url: selectedProvider.default_base_url }));
    }
  }, [form.id, form.provider]);

  React.useEffect(() => {
    load().catch((err) => setError(err.message));
    // Loading once is intentional; subsequent state changes are local edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (MODE !== "live") return null;

  const provider = providers.find((item) => item.id === form.provider);
  const baseEditable = provider?.local || provider?.id === "custom";
  const keyRequired = provider?.api_key_required;
  const valid = form.name.trim() && form.model.trim() && form.base_url.trim()
    && (!keyRequired || form.api_key.trim() || form.api_key_configured);

  const set = (key) => (event) => {
    setForm((current) => ({ ...current, [key]: event.target.value }));
    setError(""); setNote(""); setProbe(null);
  };
  const setProvider = (event) => {
    const next = providers.find((item) => item.id === event.target.value);
    setForm((current) => ({
      ...current,
      provider: next.id,
      base_url: next.default_base_url,
      api_key: "",
      api_key_configured: false,
      options: { bill_to: "" },
    }));
    setError(""); setNote(""); setProbe(null);
  };
  const payload = () => ({
    ...(form.id ? { id: form.id } : {}),
    name: form.name.trim(), provider: form.provider, base_url: form.base_url.trim(),
    model: form.model.trim(), is_default: Boolean(form.is_default),
    ...(form.api_key.trim() ? { api_key: form.api_key.trim() } : {}),
    options: form.provider === "huggingface" && form.options.bill_to.trim()
      ? { bill_to: form.options.bill_to.trim() }
      : {},
  });

  const save = async () => {
    if (!valid) return;
    setBusy("save"); setError(""); setNote("");
    try {
      const response = await api.saveAiProfile(payload());
      await load(response.profile.id);
      setNote(`${response.profile.name} saved`);
    } catch (err) { setError(err.message); } finally { setBusy(""); }
  };
  const test = async () => {
    if (!valid) return;
    setBusy("test"); setError(""); setNote(""); setProbe(null);
    try {
      const response = await api.testAiProfile(payload());
      setProbe(response);
      if (!response.connected) setError(response.detail || "Provider is unreachable");
    } catch (err) { setError(err.message); } finally { setBusy(""); }
  };
  const remove = async () => {
    if (!removeTarget) return;
    setBusy("remove"); setError("");
    try {
      await api.deleteAiProfile(removeTarget.id);
      setRemoveTarget(null); setForm(formFor()); setProbe(null);
      await load();
      setNote(`${removeTarget.name} removed`);
    } catch (err) { setError(err.message); } finally { setBusy(""); }
  };
  const startNew = () => {
    const first = providers.find((item) => item.id === "ollama") || providers[0];
    setForm({ ...formFor(), provider: first?.id || "ollama", base_url: first?.default_base_url || "" });
    setError(""); setNote(""); setProbe(null);
  };

  return (
    <div className="card flush ai-profiles-card" style={{ marginBottom: "var(--gap)" }}>
      <div className="ai-profile-editor">
        <div className="card-head">
          <div><div className="ct">AI profiles</div><div className="cs" style={{ marginTop: 3 }}>model connections used by the Karna assistant</div></div>
          <button type="button" className="btn sm" onClick={startNew}><Icon name="plus" size={13} />Add profile</button>
        </div>

        <div className="ai-profile-fields">
          <div className="field"><label htmlFor="ai-profile-name">Name</label><input id="ai-profile-name" className="input" value={form.name} onChange={set("name")} placeholder="Ollama local" autoComplete="off" /></div>
          <div className="field"><label htmlFor="ai-provider">Provider</label><select id="ai-provider" className="input sel" value={form.provider} onChange={setProvider}>{providers.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></div>
          <div className="field"><label htmlFor="ai-model">Model</label><input id="ai-model" className="input mono" value={form.model} onChange={set("model")} placeholder="qwen3:8b" autoComplete="off" spellCheck={false} /></div>
          <div className="field ai-endpoint-field"><label htmlFor="ai-endpoint">Base URL</label><input id="ai-endpoint" className="input mono" value={form.base_url} onChange={set("base_url")} readOnly={!baseEditable} autoComplete="off" spellCheck={false} /></div>
          <div className="field"><label htmlFor="ai-key">API key {keyRequired ? "" : <span className="hint">· optional</span>}</label><input id="ai-key" className="input mono" type="password" value={form.api_key} onChange={set("api_key")} placeholder={form.api_key_configured ? "Configured · leave blank to keep" : keyRequired ? "Required" : "Not required"} autoComplete="new-password" /></div>
          {form.provider === "huggingface" && <div className="field"><label htmlFor="hf-bill-to">Bill to <span className="hint">· optional</span></label><input id="hf-bill-to" className="input mono" value={form.options.bill_to} onChange={(event) => setForm((current) => ({ ...current, options: { bill_to: event.target.value } }))} placeholder="organization or resource-group ID" autoComplete="off" /></div>}
        </div>

        <div className="ai-profile-actions">
          <button type="button" className="btn primary sm" disabled={!valid || Boolean(busy)} onClick={test}><Icon name="refresh" size={13} />{busy === "test" ? "Testing…" : "Test connection"}</button>
          <button type="button" className="btn sm" disabled={!valid || Boolean(busy)} onClick={save}>{busy === "save" ? "Saving…" : "Save profile"}</button>
          <label className="ai-default-check"><input type="checkbox" checked={Boolean(form.is_default)} onChange={(event) => setForm((current) => ({ ...current, is_default: event.target.checked }))} />Use by default</label>
          <span className="spacer" />
          <span className="connection-feedback" aria-live="polite">
            {probe?.connected && <span className={`tag ${probe.model_available === false ? "warning" : "success"}`}>{probe.model_available === false ? "Connected · model not listed" : `Connected · ${probe.latency_ms}ms`}</span>}
            {note && <span className="tag success">{note}</span>}
            {error && <span className="tag danger">{error}</span>}
          </span>
        </div>
        <div className="connection-meta">
          <div className="connection-meta-copy"><span>Credential storage</span><span>Each profile has its own encrypted credential. Saved keys are never returned to the browser.</span></div>
          <span className={`tag dot ${provider?.local ? "success" : "warning"}`}>{provider?.local ? "Local processing" : "Remote provider"}</span>
        </div>
      </div>

      <div className="ai-profile-table-scroll">
        <table className="tbl ai-profile-table">
          <thead><tr><th>Profile</th><th>Provider</th><th>Model</th><th>Endpoint</th><th>Credential</th><th className="right">Actions</th></tr></thead>
          <tbody>
            {profiles.length === 0 && <tr><td colSpan="6" className="hint" style={{ padding: 24, textAlign: "center" }}>No AI profile configured. Save one to enable the assistant.</td></tr>}
            {profiles.map((item) => (
              <tr key={item.id}>
                <td><div className="ai-profile-name"><strong>{item.name}</strong>{item.is_default && <span className="tag dot success">default</span>}</div></td>
                <td><span className="tag">{providers.find((p) => p.id === item.provider)?.label || item.provider}</span></td>
                <td><span className="mono ai-model-name" title={item.model}>{item.model}</span></td>
                <td><span className="mono ai-endpoint" title={item.base_url}>{item.base_url}</span></td>
                <td><span className={`tag dot ${item.api_key_configured ? "success" : ""}`}>{item.api_key_configured ? "configured" : "none"}</span></td>
                <td className="right"><div className="kong-row-actions"><button className="btn sm" disabled={Boolean(busy)} onClick={() => { setForm(formFor(item)); setProbe(null); setError(""); setNote(""); }}>Edit</button><button className="icon-btn" title={`Remove ${item.name}`} aria-label={`Remove ${item.name}`} disabled={Boolean(busy)} onClick={() => setRemoveTarget(item)}><Icon name="x" size={13} /></button></div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Modal open={Boolean(removeTarget)} onClose={() => setRemoveTarget(null)} size="sm"
        title={<div className="ct" style={{ fontSize: 16 }}>Remove {removeTarget?.name}?</div>}
        foot={<div className="row" style={{ gap: 8 }}><button className="btn danger" disabled={Boolean(busy)} onClick={remove}>{busy === "remove" ? "Removing…" : "Remove profile"}</button><button className="btn" onClick={() => setRemoveTarget(null)}>Cancel</button></div>}>
        <p className="hint" style={{ lineHeight: 1.6 }}>This removes the profile and its encrypted credential. Existing conversations will no longer be able to use it.</p>
      </Modal>
    </div>
  );
}
