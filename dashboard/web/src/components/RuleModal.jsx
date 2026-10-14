import React from "react";
import { Modal } from "./modal.jsx";
import { Icon } from "./icons.jsx";
import { api } from "../data/api.js";
import { useMutation } from "../data/hooks.js";
import {
  EXCLUSION_FIELD_TYPES,
  buildExclusionControls,
  exclusionBuilderFromFields,
  exclusionBuilderToFields,
  exclusionBuilderValid,
  exclusionFieldsFromControls,
  splitExclusionValues,
} from "../data/exclusions.js";

// CodeMirror is heavy — load it only when the native raw editor is shown.
const JsonEditor = React.lazy(() => import("./JsonEditor.jsx"));

/* Rule manager modal. New rules default to the guided builder (single
 * condition → action), which emits native Karna JSON. Complex rules — and any
 * edit — use the Raw tab (native JSON or hand-written SecLang). */

const VARS = [
  "request.arg.value", "request.arg.name", "request.raw_path", "request.path_with_query", "request.method",
  "request.header.value:user-agent", "request.header.value:content-type",
  "request.cookie.value", "request.body",
];
const OPS = ["rx", "pm", "contains", "beginsWith", "endsWith", "eq", "ge", "gt", "lt", "le",
  "within", "ipMatch", "libinjection_sqli", "libinjection_xss", "isSet",
  "validateUrlEncoding", "validateUtf8Encoding", "validateByteRange"];
const NO_VALUE_OPS = new Set(["isSet", "libinjection_sqli", "libinjection_xss",
  "validateUrlEncoding", "validateUtf8Encoding"]);
const TRANSFORMS = ["lowercase", "urlDecodeUni", "urlDecode", "htmlEntityDecode",
  "removeWhitespace", "compressWhitespace", "removeNulls", "normalizePath", "base64Decode"];

const DEFAULT_GUIDED = {
  id: "local_rule", phase: "access", message: "", variable: VARS[0], op: "rx",
  negated: false, value: "", transforms: ["lowercase"], action: "block",
  limit: 100, window: 60, exclusionKind: "fields", allCrs: false,
  selectedRuleIds: [], selectedTags: [], advancedRuleIds: "", advancedTags: "",
  requestFields: [{ type: "parameter", name: "" }], matchedAt: "",
};

function buildNativeRule(g, sourceRule = null) {
  const cond = { variables: [g.variable], op: g.op, negated: g.negated };
  if (!NO_VALUE_OPS.has(g.op)) cond.value = g.value;
  if (g.transforms.length) cond.transform = g.transforms;
  const rule = sourceRule ? { ...sourceRule } : {};
  rule.id = g.id;
  rule.phase = g.action === "exclusion" ? "access" : g.phase;
  rule.message = g.message;
  rule.conditions = [cond];
  delete rule.action;
  delete rule.rule_control;

  if (g.action === "exclusion") {
    rule.rule_control = buildExclusionControls(exclusionBuilderToFields(g));
    return rule;
  }

  let action;
  if (g.action === "sanitize") action = { fix_matched_parts: { remove_chars_pattern: "[<>\"'&;|`$()]" } };
  else if (g.action === "rate_limit") action = { rate_limit: { key: "%{remote_addr}", limit: Number(g.limit) || 100, window_seconds: Number(g.window) || 60 } };
  else action = { fixed_response: { status_code: 403 } };
  rule.action = action;
  return rule;
}

function guidedFromRule(rule) {
  if (!rule || !Array.isArray(rule.conditions) || rule.conditions.length !== 1) return null;
  const cond = rule.conditions[0] || {};
  if (!Array.isArray(cond.variables) || cond.variables.length !== 1) return null;

  let action = null;
  const controls = Array.isArray(rule.rule_control) ? rule.rule_control : [];
  const hasAction = rule.action && typeof rule.action === "object" && Object.keys(rule.action).length > 0;
  const exclusionFields = !hasAction ? exclusionFieldsFromControls(controls) : null;
  const exclusionBuilder = exclusionFields ? exclusionBuilderFromFields(exclusionFields) : null;
  if (exclusionBuilder) {
    action = "exclusion";
  } else if (rule.action?.fixed_response) action = "block";
  else if (rule.action?.fix_matched_parts) action = "sanitize";
  else if (rule.action?.rate_limit) action = "rate_limit";
  if (!action) return null;

  return {
    ...DEFAULT_GUIDED,
    id: String(rule.id || ""),
    phase: String(rule.phase || "access"),
    message: String(rule.message || ""),
    variable: String(cond.variables[0] || ""),
    op: String(cond.op || "rx"),
    negated: cond.negated === true,
    value: cond.value == null ? "" : String(cond.value),
    transforms: Array.isArray(cond.transform) ? cond.transform : [],
    action,
    limit: rule.action?.rate_limit?.limit ?? 100,
    window: rule.action?.rate_limit?.window_seconds ?? 60,
    ...(exclusionBuilder || {}),
    matchedAt: "",
  };
}

function ExclusionBuilder({ value, onChange, detections, categories, preview, onCopy, copied, onContinueRaw }) {
  const [search, setSearch] = React.useState("");
  const [searchActive, setSearchActive] = React.useState(false);
  const selectedRuleIds = Array.isArray(value.selectedRuleIds) ? value.selectedRuleIds : [];
  const selectedTags = Array.isArray(value.selectedTags) ? value.selectedTags : [];
  const requestFields = Array.isArray(value.requestFields) ? value.requestFields : [];
  const detectionById = new Map((detections || []).map((item) => [String(item.id), item]));
  const update = (patch) => onChange((previous) => ({ ...previous, ...patch }));
  const toggle = (key, current, item) => update({
    [key]: current.includes(item) ? current.filter((value) => value !== item) : [...current, item],
  });
  const query = search.trim().toLocaleLowerCase();
  const results = (detections || []).filter((item) => !selectedRuleIds.includes(String(item.id)) && (
    !query || `${item.message} ${item.id}`.toLocaleLowerCase().includes(query)
  )).slice(0, 6);
  const updateField = (index, patch) => update({
    requestFields: requestFields.map((field, i) => i === index ? { ...field, ...patch } : field),
  });
  const removeField = (index) => update({ requestFields: requestFields.filter((_, i) => i !== index) });
  const scopeCount = Number(value.allCrs) + selectedRuleIds.length + selectedTags.length
    + splitExclusionValues(value.advancedRuleIds).length + splitExclusionValues(value.advancedTags).length;
  const scopeParts = [
    value.allCrs ? "all CRS rules" : "",
    selectedRuleIds.length ? `${selectedRuleIds.length} specific detection${selectedRuleIds.length === 1 ? "" : "s"}` : "",
    selectedTags.length ? `${selectedTags.length} attack categor${selectedTags.length === 1 ? "y" : "ies"}` : "",
  ].filter(Boolean);
  const summary = !scopeCount
    ? "Choose where this exclusion applies."
    : value.exclusionKind === "detections"
      ? `Exclude complete detections across ${scopeParts.join(", ") || "the advanced selection"}.`
      : `Ignore ${requestFields.length} request field${requestFields.length === 1 ? "" : "s"} across ${scopeParts.join(", ") || "the advanced selection"}.`;

  return (
    <div className="exclusion-builder">
      <div className="exclusion-builder-head">
        <div><div className="ct">Scoped exclusion</div><p>Choose the outcome in plain language. Karna controls are generated automatically.</p></div>
        <span className="tag accent">request phase</span>
      </div>

      <div className="exclusion-step">
        <div className="exclusion-step-label"><span>1</span><div><strong>What do you want to exclude?</strong><small>Keep the detection active when only one field causes a false positive.</small></div></div>
        <div className="exclusion-intent-grid">
          <button type="button" className={value.exclusionKind === "fields" ? "selected" : ""}
            onClick={() => update({ exclusionKind: "fields", requestFields: requestFields.length ? requestFields : [{ type: "parameter", name: "" }] })}>
            <Icon name="filter" size={18} /><span><strong>Request fields</strong><small>Ignore selected parameters, headers, cookies, or body fields.</small></span>
          </button>
          <button type="button" className={value.exclusionKind === "detections" ? "selected" : ""}
            onClick={() => update({ exclusionKind: "detections" })}>
            <Icon name="shield" size={18} /><span><strong>Complete detections</strong><small>Skip the selected detections entirely when this rule matches.</small></span>
          </button>
        </div>
      </div>

      <div className="exclusion-step">
        <div className="exclusion-step-label"><span>2</span><div><strong>Where should it apply?</strong><small>Select the whole Core Rule Set, observed detections, attack categories, or combine them.</small></div></div>
        <button type="button" className={`exclusion-all-crs${value.allCrs ? " selected" : ""}`}
          aria-pressed={value.allCrs} onClick={() => update({ allCrs: !value.allCrs })}>
          <span className="exclusion-check"><Icon name={value.allCrs ? "check" : "shield"} size={15} /></span>
          <span><strong>All CRS rules</strong><small>Apply to the complete OWASP Core Rule Set.</small></span>
          <span className="tag plain">OWASP CRS</span>
        </button>

        <div className="exclusion-picker">
          <label>Specific detections</label>
          <div className="exclusion-search"><Icon name="search" size={14} /><input value={search} onFocus={() => setSearchActive(true)} onChange={(event) => setSearch(event.target.value)}
            placeholder="Search by detection name…" aria-label="Search detections" /></div>
          {searchActive && results.length > 0 && (
            <div className="exclusion-results">
              {results.map((item) => (
                <button type="button" key={item.id} onClick={() => { toggle("selectedRuleIds", selectedRuleIds, String(item.id)); setSearch(""); setSearchActive(false); }}>
                  <span><strong>{item.message || "Unnamed detection"}</strong><small>{item.category || "Detection"} · Rule {item.id}</small></span>
                  <Icon name="plus" size={14} />
                </button>
              ))}
            </div>
          )}
          {searchActive && query && results.length === 0 && <div className="exclusion-empty">No observed detections match this search. Use Advanced selection for a rule that has not appeared in events yet.</div>}
          {selectedRuleIds.length > 0 && (
            <div className="exclusion-selections">
              {selectedRuleIds.map((id) => {
                const item = detectionById.get(String(id));
                return <button type="button" key={id} onClick={() => toggle("selectedRuleIds", selectedRuleIds, id)} title="Remove selection">
                  <span><strong>{item?.message || (value.sourceRuleMessage && selectedRuleIds.length === 1 ? value.sourceRuleMessage : "Selected detection")}</strong><small>{item?.category || "Detection"} · Rule {id}</small></span><Icon name="x" size={13} />
                </button>;
              })}
            </div>
          )}
        </div>

        <div className="exclusion-picker">
          <label>Attack categories</label>
          <div className="exclusion-category-grid">
            {(categories || []).map((category) => (
              <button type="button" key={category.tag} className={selectedTags.includes(category.tag) ? "selected" : ""}
                aria-pressed={selectedTags.includes(category.tag)} onClick={() => toggle("selectedTags", selectedTags, category.tag)}>
                <span className="exclusion-category-dot" style={{ background: category.color }} />{category.label}
                {selectedTags.includes(category.tag) && <Icon name="check" size={12} />}
              </button>
            ))}
          </div>
        </div>

        <details className="exclusion-advanced">
          <summary>Advanced selection</summary>
          <p>Add rules or tags that have not appeared in the dashboard yet. Separate multiple values with commas or new lines.</p>
          <div className="grid g-2" style={{ gap: 12 }}>
            <div className="field"><label>Rule IDs or ranges</label><textarea className="input mono" rows={2} maxLength={2000}
              value={value.advancedRuleIds} onChange={(event) => update({ advancedRuleIds: event.target.value })} placeholder={"942100\n920100-920199"} /></div>
            <div className="field"><label>Rule tags</label><textarea className="input mono" rows={2} maxLength={2000}
              value={value.advancedTags} onChange={(event) => update({ advancedTags: event.target.value })} placeholder={"attack-sqli\ncustom-policy"} /></div>
          </div>
        </details>
      </div>

      {value.exclusionKind === "fields" && (
        <div className="exclusion-step">
          <div className="exclusion-step-label"><span>3</span><div><strong>Which request fields should be ignored?</strong><small>Use the names your application uses. The Karna target is generated for you.</small></div></div>
          <div className="exclusion-fields">
            {requestFields.map((field, index) => {
              const meta = EXCLUSION_FIELD_TYPES.find((item) => item.id === field.type) || EXCLUSION_FIELD_TYPES[0];
              return (
                <div className="exclusion-field-row" key={index}>
                  <div className="field"><label>Field type</label><select className="input" value={field.type}
                    onChange={(event) => updateField(index, { type: event.target.value, name: event.target.value === "body" ? "" : field.name })}>
                    {EXCLUSION_FIELD_TYPES.map((item) => <option value={item.id} key={item.id}>{item.label}</option>)}
                  </select></div>
                  <div className="field"><label>{field.type === "body" ? "Field" : "Field name"}</label><input className="input" maxLength={240}
                    disabled={field.type === "body"} value={field.type === "body" ? "Entire request body" : field.name}
                    onChange={(event) => updateField(index, { name: event.target.value })} placeholder={meta.placeholder} /></div>
                  <button type="button" className="icon-btn" disabled={requestFields.length === 1}
                    onClick={() => removeField(index)} title="Remove field" aria-label={`Remove request field ${index + 1}`}><Icon name="x" size={13} /></button>
                </div>
              );
            })}
            <button type="button" className="btn ghost sm" onClick={() => update({ requestFields: [...requestFields, { type: "parameter", name: "" }] })}>
              <Icon name="plus" size={13} />Add field
            </button>
          </div>
        </div>
      )}

      <div className="exclusion-summary">
        <Icon name={exclusionBuilderValid(value) ? "check" : "pulse"} size={17} />
        <div><strong>Summary</strong><p>{summary}</p></div>
        <details><summary>Advanced preview</summary><pre className="json">{preview}</pre>
          <div className="row" style={{ gap: 8, marginTop: 8, justifyContent: "flex-end", flexWrap: "wrap" }}>
            <button type="button" className="btn ghost sm" onClick={onCopy}><Icon name={copied ? "check" : "copy"} size={13} />{copied ? "Copied" : "Copy JSON"}</button>
            <button type="button" className="btn sm" onClick={onContinueRaw}><Icon name="doc" size={13} />Continue in Raw rule</button>
          </div>
        </details>
      </div>
      {!exclusionBuilderValid(value) && <div className="exclusion-validation">Select at least one scope and complete every request field before adding the rule.</div>}
    </div>
  );
}

// Starter scaffold for the raw Native JSON editor — the mandatory/essential
// fields a Karna rule must carry (id, phase, conditions[], action), ready to edit.
const NATIVE_SCAFFOLD = `{
  "id": "local_rule",
  "phase": "access",
  "message": "",
  "conditions": [
    {
      "variables": ["request.arg.value"],
      "op": "rx",
      "value": "",
      "transform": ["lowercase"]
    }
  ],
  "action": {
    "fixed_response": { "status_code": 403 }
  }
}`;

function ServiceCombobox({ services, value, onChange }) {
  const inputId = React.useId();
  const listId = `${inputId}-results`;
  const inputRef = React.useRef(null);
  const [query, setQuery] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const [activeIndex, setActiveIndex] = React.useState(0);
  const selected = services.find((service) => service.plugin_id === value);
  const normalized = query.trim().toLocaleLowerCase();
  const matches = services.filter((service) => {
    if (!normalized) return true;
    const searchable = [
      service.name, service.host, service.upstream_url,
      ...(service.route_hosts || []), ...(service.route_paths || []),
    ].filter(Boolean).join(" ").toLocaleLowerCase();
    return searchable.includes(normalized);
  });
  const visible = matches.slice(0, 8);

  React.useEffect(() => {
    if (!open) setQuery(selected?.name || "");
  }, [open, selected?.name]);

  React.useEffect(() => {
    setActiveIndex((index) => Math.min(index, Math.max(visible.length - 1, 0)));
  }, [visible.length]);

  const choose = (service) => {
    onChange(service.plugin_id);
    setQuery(service.name);
    setOpen(false);
  };
  const handleKeyDown = (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setOpen(true);
      setActiveIndex((index) => Math.min(index + 1, Math.max(visible.length - 1, 0)));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setOpen(true);
      setActiveIndex((index) => Math.max(index - 1, 0));
    } else if (event.key === "Enter" && open && visible[activeIndex]) {
      event.preventDefault();
      choose(visible[activeIndex]);
    } else if (event.key === "Escape") {
      setOpen(false);
      setQuery(selected?.name || "");
    }
  };
  const handleBlur = (event) => {
    if (event.currentTarget.contains(event.relatedTarget)) return;
    setOpen(false);
    if (selected) setQuery(selected.name);
  };

  return (
    <div className="service-combobox" onBlur={handleBlur}>
      <div className={`service-combobox-input${open ? " open" : ""}${selected ? " selected" : ""}`}>
        <Icon name={selected ? "shield" : "search"} size={15} />
        <input ref={inputRef} id={inputId} role="combobox" aria-autocomplete="list"
          aria-expanded={open} aria-controls={listId}
          aria-activedescendant={open && visible[activeIndex] ? `${inputId}-option-${activeIndex}` : undefined}
          value={query} placeholder={services.length ? "Search protected services…" : "No protected services available"}
          disabled={services.length === 0}
          onFocus={(event) => { setOpen(true); event.currentTarget.select(); }}
          onChange={(event) => { setQuery(event.target.value); onChange(""); setOpen(true); setActiveIndex(0); }}
          onKeyDown={handleKeyDown} />
        {selected && <button type="button" className="service-combobox-clear" aria-label="Clear selected service"
          onClick={() => { onChange(""); setQuery(""); setOpen(true); inputRef.current?.focus(); }}>
          <Icon name="x" size={12} />
        </button>}
        {!selected && services.length > 0 && <span className="service-combobox-count mono">{services.length}</span>}
      </div>
      {open && services.length > 0 && (
        <div className="service-combobox-results" id={listId} role="listbox">
          {visible.map((service, index) => {
            const detail = service.host || service.route_hosts?.[0] || service.upstream_url || "Protected service";
            return <button type="button" role="option" id={`${inputId}-option-${index}`} key={service.id}
              aria-selected={service.plugin_id === value}
              className={index === activeIndex ? "active" : ""}
              onMouseDown={(event) => event.preventDefault()} onClick={() => choose(service)}
              onMouseEnter={() => setActiveIndex(index)}>
              <span className="service-combobox-mark"><Icon name="shield" size={13} /></span>
              <span><strong>{service.name}</strong><small>{detail}</small></span>
              {service.plugin_id === value && <Icon name="check" size={13} />}
            </button>;
          })}
          {visible.length === 0 && <div className="service-combobox-empty">No protected services match “{query.trim()}”.</div>}
          {matches.length > visible.length && <div className="service-combobox-more mono">
            {matches.length - visible.length} more matches · keep typing to narrow the list
          </div>}
        </div>
      )}
      {selected && <div className="service-combobox-selection">
        Rule target: <strong>{selected.name}</strong>
      </div>}
    </div>
  );
}

export default function RuleModal({ state, services, detections = [], categories = [], refresh, onClose }) {
  const { run, pending, error } = useMutation(refresh);
  const open = !!state;
  const mode = state?.mode; // 'create' | 'edit'
  const editKind = state?.kind; // 'native' | 'seclang' (edit only)

  const withPlugin = (services || []).filter((s) => s.plugin_id);
  const [pluginId, setPluginId] = React.useState("");
  const [tab, setTab] = React.useState("guided");

  // guided form
  const [g, setG] = React.useState(DEFAULT_GUIDED);
  // raw — separate buffers so toggling format never clobbers the other side
  const [rawFormat, setRawFormat] = React.useState("native");
  const [nativeText, setNativeText] = React.useState(NATIVE_SCAFFOLD);
  const [seclangText, setSeclangText] = React.useState("");
  const [previewCopied, setPreviewCopied] = React.useState(false);

  React.useEffect(() => {
    if (!state) return;
    setPreviewCopied(false);
    if (mode === "edit") {
      setPluginId(state.pluginId);
      if (editKind === "native") {
        const guided = guidedFromRule(state.rule);
        setTab(guided ? "guided" : "raw");
        if (guided) setG(guided);
        setRawFormat("native");
        setNativeText(JSON.stringify(state.rule, null, 2));
      } else {
        setTab("raw");
        setRawFormat("seclang");
        setSeclangText(state.text || "");
      }
    } else {
      setTab("guided");
      setPluginId(state.draft?.pluginId || "");
      const draft = state.draft || {};
      const legacyFields = draft.targetRuleGroups || draft.targetTagGroups
        ? exclusionBuilderFromFields({ removeRuleIds: draft.removeRuleIds, removeTags: draft.removeTags, targetRuleGroups: draft.targetRuleGroups, targetTagGroups: draft.targetTagGroups })
        : null;
      setG({ ...DEFAULT_GUIDED, ...draft, ...(legacyFields || {}) });
      setRawFormat("native"); setNativeText(NATIVE_SCAFFOLD); setSeclangText("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  if (!state) return null;

  const set = (k, v) => setG((p) => ({ ...p, [k]: v }));
  const toggleTransform = (t) => setG((p) => ({ ...p, transforms: p.transforms.includes(t) ? p.transforms.filter((x) => x !== t) : [...p.transforms, t] }));
  const preview = (() => { try { return JSON.stringify(buildNativeRule(g, mode === "edit" ? state.rule : null), null, 2); } catch { return "{}"; } })();
  const copyPreview = () => {
    navigator.clipboard?.writeText(preview).then(() => {
      setPreviewCopied(true);
      setTimeout(() => setPreviewCopied(false), 1200);
    });
  };
  const continueInRaw = () => {
    setNativeText(preview);
    setRawFormat("native");
    setTab("raw");
  };

  const guidedValid = pluginId && g.id.trim() && g.variable.trim()
    && (NO_VALUE_OPS.has(g.op) || g.value.trim())
    && (g.action !== "exclusion" || exclusionBuilderValid(g));

  const parseNative = () => { try { return JSON.parse(nativeText); } catch { return undefined; } };

  const save = async () => {
    let ok = false;
    if (mode === "edit") {
      if (editKind === "native") {
        const obj = tab === "guided" ? buildNativeRule(g, state.rule) : parseNative();
        if (obj === undefined) return run(() => { throw new Error("Invalid JSON"); });
        ok = await run(() => api.editRule(pluginId, "native", state.index, { rule: obj }, state.etag), `Save changes to rule on this service?`);
      } else {
        ok = await run(() => api.editRule(pluginId, "seclang", state.index, { rule: seclangText }, state.etag), `Save SecLang rule changes?`);
      }
    } else if (tab === "guided") {
      ok = await run(() => api.addRule(pluginId, { kind: "native", rule: buildNativeRule(g) }), `Add this rule to "${withPlugin.find((s) => s.plugin_id === pluginId)?.name}"?`);
    } else if (rawFormat === "native") {
      const obj = parseNative();
      if (obj === undefined) return run(() => { throw new Error("Invalid JSON"); });
      ok = await run(() => api.addRule(pluginId, { kind: "native", rule: obj }), `Add this native rule?`);
    } else {
      ok = await run(() => api.addRule(pluginId, { kind: "seclang", rule: seclangText }), `Add this SecLang rule?`);
    }
    if (ok) onClose();
  };

  const rawHasText = (rawFormat === "native" ? nativeText : seclangText).trim();
  const canSave = !pending && pluginId && (
    tab === "guided" && (mode === "create" || editKind === "native")
      ? guidedValid
      : rawHasText
  );

  const title = <div className="ct" style={{ fontSize: 16, fontWeight: 600 }}>{mode === "edit" ? "Edit rule" : "New rule"}</div>;
  const guidedEdit = mode === "edit" && editKind === "native" && guidedFromRule(state.rule);
  const head = (mode === "create" || guidedEdit) ? (
    <div className="tabs">
      <button className={tab === "guided" ? "on" : ""} onClick={() => setTab("guided")}>Guided</button>
      <button className={tab === "raw" ? "on" : ""} onClick={() => setTab("raw")}>Raw rule</button>
    </div>
  ) : null;
  const foot = (
    <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <button className="btn primary" style={{ opacity: canSave ? 1 : 0.55 }} disabled={!canSave} onClick={save}>{pending ? "Saving…" : mode === "edit" ? "Save rule" : "Add rule"}</button>
      <button className="btn" onClick={onClose}>Cancel</button>
      {error && <span className="tag danger" style={{ fontSize: 10.5 }}>{error}</span>}
    </div>
  );

  return (
    <Modal open={open} onClose={onClose} title={title} head={head} foot={foot}>
      {mode === "create" && (
        <div className="field" style={{ marginBottom: 18 }}>
          <label>Target service</label>
          <ServiceCombobox services={withPlugin} value={pluginId} onChange={setPluginId} />
        </div>
      )}

      {tab === "guided" && (mode === "create" || editKind === "native") ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <section>
            <div className="sec-h">Rule</div>
            <div className="grid g-2" style={{ gap: 12 }}>
              <div className="field"><label>Rule ID</label><input className="input" value={g.id} onChange={(e) => set("id", e.target.value)} /></div>
              <div className="field"><label>Phase</label>
                <select className="input" value={g.action === "exclusion" ? "access" : g.phase}
                  disabled={g.action === "exclusion"} onChange={(e) => set("phase", e.target.value)}>
                  <option value="access">access (request)</option>
                  <option value="header_filter">header_filter (response headers)</option>
                  <option value="body_filter">body_filter (response body)</option>
                </select>
              </div>
            </div>
            <div className="field" style={{ marginTop: 12 }}><label>Message</label><input className="input" value={g.message} onChange={(e) => set("message", e.target.value)} placeholder="What this rule detects" /></div>
          </section>

          <section>
            <div className="sec-h">Condition</div>
            <div className="grid g-2" style={{ gap: 12 }}>
              <div className="field"><label>Variable</label>
                <select className="input" value={VARS.includes(g.variable) ? g.variable : "__custom"} onChange={(e) => set("variable", e.target.value === "__custom" ? "" : e.target.value)}>
                  {VARS.map((v) => <option key={v} value={v}>{v}</option>)}
                  <option value="__custom">custom…</option>
                </select>
                {!VARS.includes(g.variable) && <input className="input" style={{ marginTop: 6 }} value={g.variable} onChange={(e) => set("variable", e.target.value)} placeholder="request.…" />}
              </div>
              <div className="field"><label>Operator</label>
                <select className="input" value={g.op} onChange={(e) => set("op", e.target.value)}>
                  {OPS.map((o) => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
            </div>
            {!NO_VALUE_OPS.has(g.op) && (
              <div className="field" style={{ marginTop: 12 }}><label>Value / pattern</label><input className="input mono" value={g.value} onChange={(e) => set("value", e.target.value)} placeholder={g.op === "rx" ? "(?i)attack-regex" : "value"} /></div>
            )}
            <div className="row" style={{ gap: 10, marginTop: 10, alignItems: "center" }}>
              <label className="row" style={{ gap: 6, fontSize: 13, cursor: "pointer" }}>
                <input type="checkbox" checked={g.negated} onChange={(e) => set("negated", e.target.checked)} />negate (match when it does NOT match)
              </label>
            </div>
            <div style={{ marginTop: 12 }}>
              <label className="desc" style={{ display: "block", marginBottom: 6 }}>Transforms (applied before the operator)</label>
              <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                {TRANSFORMS.map((t) => (
                  <button key={t} className={"chip " + (g.transforms.includes(t) ? "on" : "off")} onClick={() => toggleTransform(t)}>{t}</button>
                ))}
              </div>
            </div>
          </section>

          <section>
            <div className="sec-h">Action</div>
            <div className="seg" style={{ maxWidth: 520 }}>
              <button className={g.action === "block" ? "on" : ""} onClick={() => set("action", "block")}>block (403)</button>
              <button className={g.action === "sanitize" ? "on" : ""} onClick={() => set("action", "sanitize")}>sanitize</button>
              <button className={g.action === "rate_limit" ? "on" : ""} onClick={() => set("action", "rate_limit")}>rate-limit</button>
              <button className={g.action === "exclusion" ? "on" : ""}
                onClick={() => setG((p) => ({ ...p, action: "exclusion", phase: "access" }))}>exclusion</button>
            </div>
            {g.action === "rate_limit" && (
              <div className="grid g-2" style={{ gap: 12, marginTop: 12, maxWidth: 360 }}>
                <div className="field"><label>Limit</label><input className="input" type="number" value={g.limit} onChange={(e) => set("limit", e.target.value)} /></div>
                <div className="field"><label>Window (s)</label><input className="input" type="number" value={g.window} onChange={(e) => set("window", e.target.value)} /></div>
              </div>
            )}
            {g.action === "exclusion" && (
              <ExclusionBuilder value={g} onChange={setG} detections={detections} categories={categories}
                preview={preview} onCopy={copyPreview} copied={previewCopied} onContinueRaw={continueInRaw} />
            )}
          </section>

          {g.action !== "exclusion" && <section>
            <div className="sec-h">Generated rule (native Karna JSON)</div>
            <pre className="json" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0 }}>{preview}</pre>
            <div className="row" style={{ gap: 8, marginTop: 10, justifyContent: "flex-end", flexWrap: "wrap" }}>
              <button className="btn ghost sm" onClick={copyPreview}>
                <Icon name={previewCopied ? "check" : "copy"} size={13} />
                {previewCopied ? "Copied" : "Copy JSON"}
              </button>
              <button className="btn sm" onClick={continueInRaw}
                title="Copy this preview into Raw rule and continue editing">
                <Icon name="doc" size={13} />Continue in Raw rule
              </button>
            </div>
          </section>}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {mode === "create" && (
            <div className="seg" style={{ maxWidth: 320 }}>
              <button className={rawFormat === "native" ? "on" : ""} onClick={() => setRawFormat("native")}>Native JSON</button>
              <button className={rawFormat === "seclang" ? "on" : ""} onClick={() => setRawFormat("seclang")}>SecLang</button>
            </div>
          )}
          <div className="hint">
            {rawFormat === "native"
              ? "Karna rule object: { id, phase, conditions:[…], action:{…} }. Supports chains, setvar, redis actions, etc. Autocomplete: Ctrl-Space; keys and operator/transform/variable values are suggested."
              : 'ModSecurity SecLang directive, e.g. SecRule REQUEST_HEADERS:X-Tenant "@rx ^[a-z0-9-]{1,32}$" "id:990001,phase:1,pass,t:none"'}
          </div>
          {rawFormat === "native" ? (
            <React.Suspense fallback={<div className="hint" style={{ padding: "20px 4px" }}>Loading editor…</div>}>
              <JsonEditor value={nativeText} onChange={setNativeText} minHeight={300} />
            </React.Suspense>
          ) : (
            <textarea className="input mono" style={{ minHeight: 300, resize: "vertical", lineHeight: 1.5, padding: "10px 12px" }}
              value={seclangText} onChange={(e) => setSeclangText(e.target.value)} placeholder={'SecRule …'} />
          )}
        </div>
      )}
    </Modal>
  );
}
