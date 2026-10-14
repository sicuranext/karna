import React from "react";
import { EmptyRow } from "../components/states.jsx";
import { Icon } from "../components/icons.jsx";
import OverrideModal from "../components/OverrideModal.jsx";
import RuleModal from "../components/RuleModal.jsx";
import { fmt } from "../data/index.js";
import { api } from "../data/api.js";
import { useMutation } from "../data/hooks.js";
import { categoryForRule, categoryMeta } from "../data/categories.js";

function selectorSummary(sel) {
  const parts = [];
  if (sel.ids) parts.push(`ids: ${sel.ids.join(", ")}`);
  if (sel.id_ranges) parts.push(`ranges: ${sel.id_ranges.join(", ")}`);
  if (sel.tags) parts.push(`tags: ${sel.tags.join(", ")}`);
  if (sel.except_ids) parts.push(`except_ids: ${sel.except_ids.join(", ")}`);
  if (sel.except_tags) parts.push(`except_tags: ${sel.except_tags.join(", ")}`);
  if (sel.any) parts.push("any rule");
  return parts.join(" · ") || "—";
}

/* One human word per override action; the config keyword rides along. */
const ACTION_TAG = {
  passthrough: ["warning", "allow"], fix: ["accent", "sanitize"], block: ["danger", "block"],
};

const TABS = [
  ["custom", "Custom rules"],
  ["overrides", "Overrides"],
];
const RULE_PAGE_SIZES = [10, 25, 50];

function secLangId(text, fallback) {
  return String(text || "").match(/\bid\s*:\s*["']?(\d+)/i)?.[1] || fallback;
}

function secLangPhase(text) {
  const phase = String(text || "").match(/\bphase\s*:\s*["']?(\d+)/i)?.[1];
  return phase ? `phase ${phase}` : "—";
}

function searchableRule(rule) {
  return [
    rule.id, rule.service, rule.kind, rule.phase, rule.message, rule.action,
    rule.source,
  ].filter(Boolean).join(" ").toLocaleLowerCase();
}

export default function Rules({ data, param, nav, writable, refresh, ruleDraft, clearRuleDraft }) {
  const tab = param === "overrides" ? "overrides" : "custom";
  const overrideCount = data.ruleActionOverrides.length + data.ruleResponseOverrides.length;
  const customCount = data.localRules.length + data.customSecrules.length;
  const counts = { overrides: overrideCount, custom: customCount };

  React.useEffect(() => {
    if (param === "crs" || param === "custom") nav("rules");
  }, [param, nav]);

  return (
    <div className="view-inner">
      <div className="page-head">
        <div className="ph-top">
          <div>
            <span className="eyebrow">Configuration · rules</span>
            <h1>Rules</h1>
            <p className="lead">Create service-specific Karna rules and tune how existing rules behave.</p>
          </div>
        </div>
        <div className="tabs page-tabs" role="tablist">
          {TABS.map(([id, label]) => (
            <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "on" : ""}
              onClick={() => nav("rules", id === "custom" ? null : id)}>
              {label}{counts[id] != null && <span className="tab-count">{counts[id]}</span>}
            </button>
          ))}
        </div>
      </div>

      {tab === "overrides" && <OverridesPanel data={data} writable={writable} refresh={refresh} />}
      {tab === "custom" && <CustomPanel data={data} writable={writable} refresh={refresh}
        ruleDraft={ruleDraft} clearRuleDraft={clearRuleDraft} />}
    </div>
  );
}

/* ---------------- Overrides ---------------- */

function OverridesPanel({ data, writable, refresh }) {
  const actO = data.ruleActionOverrides, respO = data.ruleResponseOverrides;
  const { run, pending, error } = useMutation(refresh);
  const [ovrModal, setOvrModal] = React.useState(null);

  const removeOverride = (o, kind) =>
    run(() => api.deleteOverride(o.plugin_id, kind, o.index, o.etag), {
      title: "Remove this override?",
      message: `The selected rules on "${o.service}" go back to their original behaviour immediately.`,
      confirmLabel: "Remove override",
    });
  const editOverride = (o, kind) =>
    setOvrModal({ mode: "edit", kind, pluginId: o.plugin_id, index: o.index, etag: o.etag,
      entry: kind === "action" ? { selector: o.selector, action: o.action } : { selector: o.selector, response: o.response } });

  return (
    <React.Fragment>
      <div className="card" style={{ background: "var(--inset)", marginBottom: "var(--gap)", padding: 16 }}>
        <span className="hint">Overrides change how <b style={{ color: "var(--fg-2)" }}>existing</b> rules behave on a service, without touching the CoreRuleSet:
          {" "}<b style={{ color: "var(--fg-2)" }}>allow</b> lets matching requests through (still logged), <b style={{ color: "var(--fg-2)" }}>sanitize</b> strips
          the matched characters instead of blocking, <b style={{ color: "var(--fg-2)" }}>block</b> forces a block. First matching override wins.</span>
      </div>

      <div className="card flush" style={{ marginBottom: "var(--gap)" }}>
        <div className="card-head" style={{ padding: "var(--card-pad) var(--card-pad) 14px" }}>
          <div><div className="ct">Action overrides</div><div className="cs" style={{ marginTop: 3 }}>rule_action_overrides</div></div>
          <span className="row" style={{ gap: 8 }}>
            {error && <span className="tag danger" style={{ fontSize: 10.5 }}>{error}</span>}
            {writable && <button className="btn primary sm" onClick={() => setOvrModal({ mode: "create", kind: "action" })}><Icon name="plus" size={13} />Add</button>}
          </span>
        </div>
        <table className="tbl">
          <thead><tr><th>Service</th><th>Applies to</th><th>Action</th><th className="right">Hits 24h</th>{writable && <th></th>}</tr></thead>
          <tbody>
            {actO.length === 0 && <EmptyRow colSpan={writable ? 5 : 4} label="No action overrides — rules run as shipped" />}
            {actO.map((o, i) => {
              const [cls, lbl] = ACTION_TAG[o.action.type] || ["", o.action.type];
              return (
                <tr key={i}>
                  <td><span className="tag plain">{o.service}</span></td>
                  <td className="mono" style={{ fontSize: 11.5, color: "var(--fg-2)" }}>{selectorSummary(o.selector)}</td>
                  <td><span className={"tag " + cls}>{lbl}</span></td>
                  <td className="right mono tnum">{fmt(o.hits)}</td>
                  {writable && (
                    <td className="row-actions">
                      <button className="icon-btn" title="Edit" aria-label="Edit override" disabled={pending} onClick={() => editOverride(o, "action")}><Icon name="gear" size={13} /></button>
                      <button className="icon-btn" title="Remove" aria-label="Remove override" disabled={pending || o.plugin_id == null}
                        style={{ color: "var(--danger)" }} onClick={() => removeOverride(o, "action")}><Icon name="x" size={13} /></button>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="card flush">
        <div className="card-head" style={{ padding: "var(--card-pad) var(--card-pad) 14px" }}>
          <div><div className="ct">Response overrides</div><div className="cs" style={{ marginTop: 3 }}>rule_response_overrides · custom block response</div></div>
          {writable && <button className="btn primary sm" onClick={() => setOvrModal({ mode: "create", kind: "response" })}><Icon name="plus" size={13} />Add</button>}
        </div>
        <table className="tbl">
          <thead><tr><th>Service</th><th>Applies to</th><th className="right">Status</th>{writable && <th></th>}</tr></thead>
          <tbody>
            {respO.length === 0 && <EmptyRow colSpan={writable ? 4 : 3} label="No response overrides — blocks return the default 403" />}
            {respO.map((o, i) => (
              <tr key={i}>
                <td><span className="tag plain">{o.service}</span></td>
                <td className="mono" style={{ fontSize: 11.5, color: "var(--fg-2)" }}>{selectorSummary(o.selector)}</td>
                <td className="right mono tnum">{o.response.status_code}</td>
                {writable && (
                  <td className="row-actions">
                    <button className="icon-btn" title="Edit" aria-label="Edit override" disabled={pending} onClick={() => editOverride(o, "response")}><Icon name="gear" size={13} /></button>
                    <button className="icon-btn" title="Remove" aria-label="Remove override" disabled={pending || o.plugin_id == null} style={{ color: "var(--danger)" }} onClick={() => removeOverride(o, "response")}><Icon name="x" size={13} /></button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <OverrideModal state={ovrModal} services={data.services} refresh={refresh} onClose={() => setOvrModal(null)} />
    </React.Fragment>
  );
}

/* ---------------- Custom rules ---------------- */

function CustomPanel({ data, writable, refresh, ruleDraft, clearRuleDraft }) {
  const { run, pending, error } = useMutation(refresh);
  const [ruleModal, setRuleModal] = React.useState(null);
  const [query, setQuery] = React.useState("");
  const [serviceFilter, setServiceFilter] = React.useState("");
  const [kindFilter, setKindFilter] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(RULE_PAGE_SIZES[0]);
  const native = data.localRules;
  const seclang = data.customSecrules;

  const exclusionCatalog = React.useMemo(() => {
    const byId = new Map();
    const add = (id, message, tags = [], hits = 0) => {
      const key = String(id || "").trim();
      if (!key) return;
      const existing = byId.get(key) || { id: key, message: "", tags: [], hits: 0 };
      existing.message = existing.message || String(message || "").trim();
      existing.tags = [...new Set([...existing.tags, ...(Array.isArray(tags) ? tags.map(String) : [])])];
      existing.hits = Math.max(existing.hits, Number(hits) || 0);
      byId.set(key, existing);
    };
    (data.events || []).forEach((event) => (event.matches || []).forEach((match) => add(match.rule_id, match.message, match.tags, 1)));
    (data.topRules || []).forEach((rule) => add(rule.rule_id, rule.message, rule.tags, rule.hits));
    (data.localRules || []).forEach((rule) => add(rule.id, rule.message, rule.tags, rule.hits));

    const detections = [...byId.values()].map((item) => {
      const categoryId = categoryForRule(item.id, item.tags);
      return { ...item, categoryId, category: categoryMeta(categoryId).name };
    }).sort((a, b) => b.hits - a.hits || a.message.localeCompare(b.message));

    const byTag = new Map();
    detections.forEach((item) => item.tags.filter((tag) => tag.startsWith("attack-")).forEach((tag) => {
      if (!byTag.has(tag)) byTag.set(tag, {
        tag,
        label: categoryMeta(item.categoryId).name,
        color: categoryMeta(item.categoryId).color,
      });
    }));
    return { detections, categories: [...byTag.values()].sort((a, b) => a.label.localeCompare(b.label)) };
  }, [data.events, data.topRules, data.localRules]);

  const rules = React.useMemo(() => [
    ...native.map((rule) => ({
      ...rule,
      key: `native:${rule.service}:${rule.id}:${rule.index}`,
      kind: "native",
      source: JSON.stringify(rule.rule || rule),
      action: rule.action_kind || "—",
      edit: () => setRuleModal({
        mode: "edit", kind: "native", pluginId: rule.plugin_id,
        index: rule.index, etag: rule.etag, rule: rule.rule,
      }),
    })),
    ...seclang.map((rule) => ({
      ...rule,
      id: secLangId(rule.text, rule.id),
      key: `seclang:${rule.service}:${rule.id}:${rule.index}`,
      kind: "seclang",
      phase: secLangPhase(rule.text),
      message: rule.text,
      source: rule.text,
      action: "SecLang",
      edit: () => setRuleModal({
        mode: "edit", kind: "seclang", pluginId: rule.plugin_id,
        index: rule.index, etag: rule.etag, text: rule.text,
      }),
    })),
  ], [native, seclang]);

  const services = React.useMemo(() =>
    [...new Set(rules.map((rule) => rule.service).filter(Boolean))]
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" })),
  [rules]);

  const filteredRules = React.useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return rules.filter((rule) => {
      if (serviceFilter && rule.service !== serviceFilter) return false;
      if (kindFilter && rule.kind !== kindFilter) return false;
      return !needle || searchableRule(rule).includes(needle);
    });
  }, [rules, query, serviceFilter, kindFilter]);

  const pages = Math.max(1, Math.ceil(filteredRules.length / pageSize));
  const currentPage = Math.min(page, pages - 1);
  const visibleRules = filteredRules.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const hasFilters = Boolean(query || serviceFilter || kindFilter);
  const setFilter = (setter, value) => { setter(value); setPage(0); };
  const clearFilters = () => {
    setQuery(""); setServiceFilter(""); setKindFilter(""); setPage(0);
  };

  React.useEffect(() => {
    if (!ruleDraft) return;
    setRuleModal({ mode: "create", draft: ruleDraft });
    clearRuleDraft?.();
  }, [ruleDraft, clearRuleDraft]);
  const removeRule = (pid, kind, index, label, etag) =>
    run(() => api.deleteRule(pid, kind, index, etag), {
      title: `Delete rule ${label}?`,
      message: "The rule stops matching immediately. This cannot be undone.",
      danger: true,
      confirmLabel: "Delete rule",
    });

  return (
    <React.Fragment>
      <div className="between" style={{ marginBottom: "var(--gap)" }}>
        <span className="hint">Rules you write yourself, per service — in Karna's native JSON or as ModSecurity SecLang directives.</span>
        {writable && (
          <button className="btn primary" onClick={() => setRuleModal({ mode: "create" })}>
            <Icon name="plus" size={15} />New rule
          </button>
        )}
      </div>

      <div className="card flush rules-inventory">
        <div className="card-head" style={{ padding: "var(--card-pad) var(--card-pad) 14px" }}>
          <div>
            <div className="ct">Custom rule inventory</div>
            <div className="cs" style={{ marginTop: 3 }}>rules_request + custom_secrules · scoped by service</div>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <span className="tag plain">{filteredRules.length} of {rules.length}</span>
            {error && <span className="tag danger" style={{ fontSize: 10.5 }}>{error}</span>}
          </div>
        </div>

        <div className="rules-query-rail">
          <label className="rules-search">
            <Icon name="search" size={14} />
            <input value={query} onChange={(event) => setFilter(setQuery, event.target.value)}
              placeholder="Search ID, message, service or rule source…" aria-label="Search custom rules" />
            {query && <button type="button" className="icon-btn" aria-label="Clear rule search" onClick={() => setFilter(setQuery, "")}>
              <Icon name="x" size={12} />
            </button>}
          </label>
          <select className="input sel" value={serviceFilter} aria-label="Filter rules by service"
            onChange={(event) => setFilter(setServiceFilter, event.target.value)}>
            <option value="">All services</option>
            {services.map((service) => <option value={service} key={service}>{service}</option>)}
          </select>
          <select className="input sel" value={kindFilter} aria-label="Filter rules by type"
            onChange={(event) => setFilter(setKindFilter, event.target.value)}>
            <option value="">All types</option>
            <option value="native">Native JSON</option>
            <option value="seclang">SecLang</option>
          </select>
          {hasFilters && <button type="button" className="btn ghost sm" onClick={clearFilters}>Clear filters</button>}
        </div>

        <div className="rules-table-wrap">
          <table className="tbl">
            <thead><tr><th>Rule</th><th>Type</th><th>Service</th><th>Phase</th><th>Message / source</th><th>Behaviour</th><th className="right">Hits</th>{writable && <th></th>}</tr></thead>
            <tbody>
              {visibleRules.length === 0 && <EmptyRow colSpan={writable ? 8 : 7}
                label={hasFilters ? "No rules match the current search and filters" : "No custom rules"} />}
              {visibleRules.map((rule) => (
                <tr key={rule.key}>
                  <td className="mono rules-rule-id">{rule.id}</td>
                  <td><span className={`tag ${rule.kind === "native" ? "accent" : "info"}`}>{rule.kind === "native" ? "native" : "SecLang"}</span></td>
                  <td className="hint" style={{ whiteSpace: "nowrap" }}>{rule.service}</td>
                  <td className="mono" style={{ fontSize: 10.5 }}>{rule.phase || "—"}</td>
                  <td className="rules-rule-source" title={rule.source}>{rule.message || rule.source || "—"}</td>
                  <td className="mono" style={{ fontSize: 10.5 }}>{rule.action}</td>
                  <td className="right mono tnum">{fmt(Number(rule.hits) || 0)}</td>
                  {writable && (
                    <td className="row-actions">
                      <button className="icon-btn" title="Edit" aria-label={`Edit rule ${rule.id}`} disabled={pending} onClick={rule.edit}><Icon name="gear" size={13} /></button>
                      <button className="icon-btn" title="Delete" aria-label={`Delete rule ${rule.id}`} disabled={pending}
                        style={{ color: "var(--danger)" }} onClick={() => removeRule(rule.plugin_id, rule.kind, rule.index, rule.id, rule.etag)}><Icon name="x" size={13} /></button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="pager rules-pager">
          <div className="row" style={{ gap: 8 }}>
            <span className="hint">
              {filteredRules.length === 0 ? "0 results" : `${currentPage * pageSize + 1}–${Math.min((currentPage + 1) * pageSize, filteredRules.length)} of ${filteredRules.length}`}
            </span>
            <label className="rules-page-size">
              <span>Rows</span>
              <select className="input sel" value={pageSize} aria-label="Rules per page"
                onChange={(event) => { setPageSize(Number(event.target.value)); setPage(0); }}>
                {RULE_PAGE_SIZES.map((size) => <option value={size} key={size}>{size}</option>)}
              </select>
            </label>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <button className="btn ghost sm" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>← Prev</button>
            <span className="mono hint">Page {currentPage + 1} / {pages}</span>
            <button className="btn ghost sm" disabled={currentPage >= pages - 1} onClick={() => setPage(currentPage + 1)}>Next →</button>
          </div>
        </div>
      </div>

      <RuleModal state={ruleModal} services={data.services} detections={exclusionCatalog.detections}
        categories={exclusionCatalog.categories} refresh={refresh} onClose={() => setRuleModal(null)} />
    </React.Fragment>
  );
}
