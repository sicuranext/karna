import React from "react";
import { Modal } from "./modal.jsx";
import { api } from "../data/api.js";
import { useMutation } from "../data/hooks.js";

const JsonEditor = React.lazy(() => import("./JsonEditor.jsx"));

const SCAFFOLD = {
  action: `{
  "selector": { "ids": ["942100"] },
  "action": { "type": "passthrough" }
}`,
  response: `{
  "selector": { "id_ranges": ["942000-942999"] },
  "response": { "status_code": 403, "body": "", "headers": {} }
}`,
};

const splitList = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);
const joinList = (a) => (Array.isArray(a) ? a.join(", ") : "");

function parseHeaders(text) {
  const out = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) { const k = line.slice(0, i).trim(); const v = line.slice(i + 1).trim(); if (k) out[k] = v; }
  }
  return out;
}
const serializeHeaders = (obj) => Object.entries(obj || {}).map(([k, v]) => `${k}: ${v}`).join("\n");

export default function OverrideModal({ state, services, refresh, onClose }) {
  const { run, pending, error } = useMutation(refresh);
  const mode = state?.mode;        // 'create' | 'edit'
  const kind = state?.kind;        // 'action' | 'response'
  const withPlugin = (services || []).filter((s) => s.plugin_id);

  const [tab, setTab] = React.useState("guided");
  const [pluginId, setPluginId] = React.useState("");
  // selector
  const [ids, setIds] = React.useState("");
  const [idRanges, setIdRanges] = React.useState("");
  const [tags, setTags] = React.useState("");
  const [exceptIds, setExceptIds] = React.useState("");
  const [exceptTags, setExceptTags] = React.useState("");
  const [any, setAny] = React.useState(false);
  // action
  const [actionType, setActionType] = React.useState("passthrough");
  const [removeChars, setRemoveChars] = React.useState("[<>\"'&;|`$()]");
  // response
  const [statusCode, setStatusCode] = React.useState(403);
  const [body, setBody] = React.useState("");
  const [headers, setHeaders] = React.useState("");
  // raw
  const [rawText, setRawText] = React.useState("");

  React.useEffect(() => {
    if (!state) return;
    setTab(mode === "edit" ? "raw" : "guided");
    setPluginId(mode === "edit" ? state.pluginId : (withPlugin[0]?.plugin_id || ""));
    const sel = (state.entry && state.entry.selector) || {};
    setIds(joinList(sel.ids)); setIdRanges(joinList(sel.id_ranges)); setTags(joinList(sel.tags));
    setExceptIds(joinList(sel.except_ids)); setExceptTags(joinList(sel.except_tags)); setAny(sel.any === true);
    const act = (state.entry && state.entry.action) || {};
    setActionType(act.type || "passthrough"); setRemoveChars(act.remove_chars_pattern || "[<>\"'&;|`$()]");
    const resp = (state.entry && state.entry.response) || {};
    setStatusCode(resp.status_code != null ? resp.status_code : 403); setBody(resp.body || ""); setHeaders(serializeHeaders(resp.headers));
    setRawText(state.entry ? JSON.stringify(state.entry, null, 2) : SCAFFOLD[kind]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  if (!state) return null;

  const buildSelector = () => {
    const sel = {};
    if (splitList(ids).length) sel.ids = splitList(ids);
    if (splitList(idRanges).length) sel.id_ranges = splitList(idRanges);
    if (splitList(tags).length) sel.tags = splitList(tags);
    if (splitList(exceptIds).length) sel.except_ids = splitList(exceptIds);
    if (splitList(exceptTags).length) sel.except_tags = splitList(exceptTags);
    if (any) sel.any = true;
    return sel;
  };
  const buildEntry = () => {
    const selector = buildSelector();
    if (kind === "action") {
      const action = { type: actionType };
      if (actionType === "fix" && removeChars.trim()) action.remove_chars_pattern = removeChars;
      return { selector, action };
    }
    const response = { status_code: Number(statusCode) || 403 };
    if (body.trim()) response.body = body;
    const h = parseHeaders(headers);
    if (Object.keys(h).length) response.headers = h;
    return { selector, response };
  };

  const selectorOk = splitList(ids).length || splitList(idRanges).length || splitList(tags).length || any;
  const canSave = !pending && pluginId && (tab === "guided" ? selectorOk : rawText.trim());

  const save = async () => {
    let entry;
    if (tab === "guided") entry = buildEntry();
    else { try { entry = JSON.parse(rawText); } catch { return run(() => { throw new Error("Invalid JSON"); }); } }
    const verb = mode === "edit"
      ? api.editOverride(pluginId, kind, state.index, entry, state.etag)
      : api.addOverride(pluginId, kind, entry);
    const ok = await run(() => verb, `${mode === "edit" ? "Save" : "Add"} this ${kind} override?`);
    if (ok) onClose();
  };

  const title = <div className="ct" style={{ fontSize: 16, fontWeight: 600 }}>{mode === "edit" ? "Edit" : "New"} {kind} override</div>;
  const head = (
    <div className="tabs">
      <button className={tab === "guided" ? "on" : ""} onClick={() => setTab("guided")}>Guided</button>
      <button className={tab === "raw" ? "on" : ""} onClick={() => setTab("raw")}>Raw JSON</button>
    </div>
  );
  const foot = (
    <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <button className="btn primary" style={{ opacity: canSave ? 1 : 0.55 }} disabled={!canSave} onClick={save}>{pending ? "Saving…" : mode === "edit" ? "Save override" : "Add override"}</button>
      <button className="btn" onClick={onClose}>Cancel</button>
      {error && <span className="tag danger" style={{ fontSize: 10.5 }}>{error}</span>}
    </div>
  );

  const field = (label, val, setter, ph) => (
    <div className="field"><label>{label}</label><input className="input mono" value={val} onChange={(e) => setter(e.target.value)} placeholder={ph} /></div>
  );

  return (
    <Modal open={!!state} onClose={onClose} title={title} head={head} foot={foot}>
      {tab === "guided" ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          {mode === "create" && (
            <div className="field"><label>Target service</label>
              <select className="input" value={pluginId} onChange={(e) => setPluginId(e.target.value)}>
                {withPlugin.length === 0 && <option value="">No services with a karna plugin</option>}
                {withPlugin.map((s) => <option key={s.id} value={s.plugin_id}>{s.name}</option>)}
              </select>
            </div>
          )}

          <section>
            <div className="sec-h">Selector — which CRS rules this targets</div>
            <div className="grid g-2" style={{ gap: 12 }}>
              {field("ids (comma-separated)", ids, setIds, "942100, 941100")}
              {field("id_ranges", idRanges, setIdRanges, "942000-942999")}
              {field("tags", tags, setTags, "attack-sqli")}
              {field("except_ids", exceptIds, setExceptIds, "942110")}
              {field("except_tags", exceptTags, setExceptTags, "")}
            </div>
            <label className="row" style={{ gap: 6, fontSize: 13, cursor: "pointer", marginTop: 10 }}>
              <input type="checkbox" checked={any} onChange={(e) => setAny(e.target.checked)} />any — match every rule
            </label>
            {!selectorOk && <span className="desc" style={{ color: "var(--danger)" }}>Provide ids, id_ranges, tags, or check “any”.</span>}
          </section>

          {kind === "action" ? (
            <section>
              <div className="sec-h">Action</div>
              <div className="seg" style={{ maxWidth: 360 }}>
                <button className={actionType === "fix" ? "on" : ""} onClick={() => setActionType("fix")}>fix (sanitize)</button>
                <button className={actionType === "passthrough" ? "on" : ""} onClick={() => setActionType("passthrough")}>passthrough</button>
                <button className={actionType === "block" ? "on" : ""} onClick={() => setActionType("block")}>block</button>
              </div>
              <p className="hint" style={{ marginTop: 8 }}>
                {actionType === "fix" ? "Strip matched characters and forward upstream." : actionType === "passthrough" ? "Drop the rule's terminal action (log only)." : "Force a 403 block for matched rules."}
              </p>
              {actionType === "fix" && <div className="field" style={{ marginTop: 8, maxWidth: 360 }}><label>remove_chars_pattern</label><input className="input mono" value={removeChars} onChange={(e) => setRemoveChars(e.target.value)} /></div>}
            </section>
          ) : (
            <section>
              <div className="sec-h">Response (for matched rules that block)</div>
              <div className="grid g-2" style={{ gap: 12 }}>
                <div className="field"><label>status_code</label><input className="input mono" type="number" value={statusCode} onChange={(e) => setStatusCode(e.target.value)} /></div>
              </div>
              <div className="field" style={{ marginTop: 12 }}><label>body (static text)</label><input className="input mono" value={body} onChange={(e) => setBody(e.target.value)} placeholder="Request refused." /></div>
              <div className="field" style={{ marginTop: 12 }}><label>headers (one “Name: value” per line)</label>
                <textarea className="input mono" style={{ minHeight: 70, resize: "vertical", padding: "8px 10px" }} value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder="x-blocked-by: karna" /></div>
            </section>
          )}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {mode === "create" && (
            <div className="field"><label>Target service</label>
              <select className="input" value={pluginId} onChange={(e) => setPluginId(e.target.value)}>
                {withPlugin.length === 0 && <option value="">No services with a karna plugin</option>}
                {withPlugin.map((s) => <option key={s.id} value={s.plugin_id}>{s.name}</option>)}
              </select>
            </div>
          )}
          <div className="hint">Override entry: {`{ "selector": {…}, "${kind}": {…} }`}. Autocomplete: keys, selector fields, and {kind === "action" ? "action.type" : "status_code"} values.</div>
          <React.Suspense fallback={<div className="hint" style={{ padding: "20px 4px" }}>Loading editor…</div>}>
            <JsonEditor value={rawText} onChange={setRawText} minHeight={260} schema={`override-${kind}`} />
          </React.Suspense>
        </div>
      )}
    </Modal>
  );
}
