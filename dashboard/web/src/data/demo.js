/* The live demo's backend, in the browser (VITE_DATA_MODE=demo).
 *
 * The sample fleet is kept the way Kong would store it (one Karna plugin per
 * service, rules and overrides as JSON strings), the dashboard payload is
 * derived from it the way the FastAPI backend derives it, and the write calls
 * change it in place. A scripted assistant proposes changes through the same
 * action cards as the real one. Everything lives in memory: a reload starts
 * over, and nothing leaves the page. */
import * as S from "./sample.js";

const clone = (value) => JSON.parse(JSON.stringify(value));
const uid = () => (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`);
const ACTOR = "admin@example.com";
const ACTION_TTL_MS = 10 * 60 * 1000;

function abortError() {
  const error = new Error("Aborted");
  error.name = "AbortError";
  return error;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(abortError()); return; }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => { clearTimeout(timer); reject(abortError()); }, { once: true });
  });
}

function etagOf(raw) {
  let h = 5381;
  for (let i = 0; i < raw.length; i += 1) h = ((h * 33) ^ raw.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

// ---- seed: the sample fleet as Kong stores it ----
const SEED_RULES = {
  "public-api": [
    { id: "local_login_bruteforce", phase: "access", message: "Login rate limit",
      conditions: [{ variables: ["request.method"], op: "eq", value: "POST" },
                   { variables: ["request.path"], op: "beginsWith", value: "/login" }],
      action: { rate_limit: { key: "%{remote_addr}", limit: 10, window_seconds: 60 } } },
    { id: "local_autoban_sqli", phase: "access", message: "Auto-ban repeat SQLi sources",
      conditions: [{ variables: ["request.arg.value"], op: "libinjection_sqli" }],
      action: { redis_sadd: { key: "karna:banned", member: "%{remote_addr}", ttl: 3600 } } },
  ],
  "legacy-portal": [
    { id: "local_block_admin_cidr", phase: "access", message: "Deny /admin from public CIDRs",
      conditions: [{ variables: ["request.path"], op: "beginsWith", value: "/admin" },
                   { variables: ["request.remote_addr"], op: "ipMatch", negated: true, value: "10.0.0.0/8,192.168.0.0/16" }],
      action: { fixed_response: { status_code: 403 } } },
  ],
  checkout: [
    { id: "local_trusted_internal", phase: "access", message: "Flag trusted internal caller",
      conditions: [{ variables: ["request.header.value:x-internal-caller"], op: "isSet" }],
      action: { set_variable: { type: "shared", name: "trusted_internal", value: "1" } } },
  ],
  "model-gateway": [
    { id: "mcp_method_not_allowed", phase: "access", message: "MCP method not in allow-list",
      conditions: [{ variables: ["mcp.method"], op: "mcp_method_in", negated: true, value: "initialize,ping,tools/list,tools/call" }],
      action: { fixed_response: { status_code: 403 } } },
  ],
};
const SEED_SECRULES = {
  checkout: ['SecRule REQUEST_HEADERS:X-Tenant "!@rx ^[a-z0-9-]{1,32}$" "id:990001,phase:1,deny,status:400,msg:\'Malformed tenant header\'"'],
};
const SEED_ACTION_OVERRIDES = {
  "partner-api": [{ selector: { ids: ["942440"] }, action: { type: "passthrough" } }],
  "public-api": [{ selector: { ids: ["941310"] }, action: { type: "fix", remove_chars_pattern: "[<>\"'&]" } }],
  "webhooks-ingress": [{ selector: { tags: ["attack-scanner"] }, action: { type: "block" } }],
};
const SEED_RESPONSE_OVERRIDES = {
  "public-api": [{ selector: { id_ranges: ["942000-942999"] },
    response: { status_code: 403, body: "Request rejected.", headers: { "x-blocked-by": "karna" } } }],
};
const HITS = Object.fromEntries([
  ...S.LOCAL_RULES.map((r) => [r.id, r.hits]),
  ...S.TOP_RULES.map((r) => [r.rule_id, r.hits]),
  ["990001", 14],
]);
const OVERRIDE_HITS = { "942440": 128, "941310": 64, "attack-scanner": 412 };

function seed() {
  return S.SERVICES.map((svc) => {
    const { rules_request_count, custom_secrules_count, ...config } = svc.config; // eslint-disable-line no-unused-vars
    return {
      base: { id: svc.id, name: svc.name, host: svc.host, routes: svc.routes, observed: svc.observed, enrichment: svc.enrichment },
      plugin_id: `demo-plugin-${svc.name}`,
      config: {
        ...clone(config),
        rules_request: (SEED_RULES[svc.name] || []).map((r) => JSON.stringify(r)),
        custom_secrules: [...(SEED_SECRULES[svc.name] || [])],
        rule_action_overrides: (SEED_ACTION_OVERRIDES[svc.name] || []).map((o) => JSON.stringify(o)),
        rule_response_overrides: (SEED_RESPONSE_OVERRIDES[svc.name] || []).map((o) => JSON.stringify(o)),
      },
    };
  });
}

const state = { fleet: seed(), changes: clone(S.CHANGES), conversations: new Map() };

function parse(raw) { try { return JSON.parse(raw); } catch { return null; } }

// Every recorded change also tells the dashboard to re-read the payload, so a
// change made by the assistant shows up on the other pages too.
const listeners = new Set();
export function onDemoChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function record(action, svc, fields) {
  state.changes.unshift({ ts: Math.floor(Date.now() / 1000), actor: ACTOR, action,
    service: svc ? svc.base.name : "—", plugin_id: svc ? svc.plugin_id : undefined, ...fields });
  listeners.forEach((fn) => fn());
}

// The sample events carry fixed dates; in the demo the newest one is a few
// minutes old and the others keep their spacing.
function recentEvents(events) {
  const times = events.map((ev) => Date.parse(ev.timestamp)).filter(Number.isFinite);
  if (!times.length) return events;
  const shift = Date.now() - 3 * 60 * 1000 - Math.max(...times);
  return events.map((ev) => {
    const t = Date.parse(ev.timestamp);
    return Number.isFinite(t) ? { ...ev, timestamp: new Date(t + shift).toISOString() } : ev;
  });
}

// ---- the dashboard payload, derived like the backend's build_payload ----
export function demoPayload(sampleSrc) {
  const services = [], local = [], secrules = [], actionO = [], responseO = [];
  for (const svc of state.fleet) {
    const { rules_request, custom_secrules, rule_action_overrides, rule_response_overrides, ...config } = svc.config;
    services.push({ ...svc.base, plugin_id: svc.plugin_id,
      config: { ...config, rules_request_count: rules_request.length, custom_secrules_count: custom_secrules.length } });
    rules_request.forEach((raw, index) => {
      const rule = parse(raw);
      if (!rule) return;
      const kind = rule.action && typeof rule.action === "object" ? (Object.keys(rule.action)[0] || "—") : "—";
      local.push({ id: String(rule.id ?? "—"), service: svc.base.name, plugin_id: svc.plugin_id, index, etag: etagOf(raw), rule,
        phase: rule.phase || "access", message: rule.message || "",
        action_kind: kind === "—" && Array.isArray(rule.rule_control) && rule.rule_control.length ? "exclusion" : kind,
        hits: HITS[String(rule.id)] || 0 });
    });
    custom_secrules.forEach((text, index) => {
      const id = (/\bid\s*:\s*["']?(\d+)/i.exec(text) || [])[1] || `${svc.base.name}:${index}`;
      secrules.push({ id, service: svc.base.name, plugin_id: svc.plugin_id, index, etag: etagOf(text), text, hits: HITS[id] || 0 });
    });
    rule_action_overrides.forEach((raw, index) => {
      const o = parse(raw);
      if (!o) return;
      const key = (o.selector?.ids || o.selector?.tags || [])[0];
      actionO.push({ service: svc.base.name, plugin_id: svc.plugin_id, index, etag: etagOf(raw),
        selector: o.selector || {}, action: o.action || {}, note: "", by: "", hits: OVERRIDE_HITS[key] || 0 });
    });
    rule_response_overrides.forEach((raw, index) => {
      const o = parse(raw);
      if (!o) return;
      responseO.push({ service: svc.base.name, plugin_id: svc.plugin_id, index, etag: etagOf(raw),
        selector: o.selector || {}, response: o.response || {}, by: "" });
    });
  }
  const crsPlugins = (sampleSrc.CRS_PLUGINS || []).map((p) => ({ ...p,
    services: state.fleet.filter((svc) => (svc.config.crs_plugins_enabled || []).includes(p.name)).map((svc) => svc.base.name) }));
  return { ...sampleSrc, EVENTS: recentEvents(sampleSrc.EVENTS || []), SERVICES: services, LOCAL_RULES: local, CUSTOM_SECRULES: secrules,
    RULE_ACTION_OVERRIDES: actionO, RULE_RESPONSE_OVERRIDES: responseO, CRS_PLUGINS: crsPlugins,
    CHANGES: clone(state.changes) };
}

// ---- writes ----
function service(pluginId) {
  const svc = state.fleet.find((item) => item.plugin_id === pluginId);
  if (!svc) throw new Error("This service no longer carries a Karna plugin.");
  return svc;
}
const RULE_FIELD = { native: "rules_request", seclang: "custom_secrules" };
const OVERRIDE_FIELD = { action: "rule_action_overrides", response: "rule_response_overrides" };

function checkEntry(list, index, etag, what) {
  const raw = list[Number(index)];
  if (raw === undefined) throw new Error(`This ${what} no longer exists. Refresh and try again.`);
  if (etag && etagOf(raw) !== etag) throw new Error(`This ${what} changed meanwhile. Refresh and try again.`);
  return raw;
}

function ruleText(kind, rule) {
  if (kind === "native") {
    if (!rule || typeof rule !== "object" || !rule.id) throw new Error("A native rule needs an id.");
    return JSON.stringify(rule);
  }
  if (typeof rule !== "string" || !rule.trim().startsWith("SecRule")) throw new Error("A SecLang rule starts with SecRule.");
  return rule.trim();
}

function overrideText(kind, entry) {
  if (!entry || typeof entry !== "object" || !entry.selector || typeof entry.selector !== "object") {
    throw new Error("An override needs a selector.");
  }
  if (kind === "action" && !entry.action?.type) throw new Error("An action override needs action.type.");
  if (kind === "response" && !entry.response) throw new Error("A response override needs a response.");
  return JSON.stringify(entry);
}

function applyEngine(svc, body) {
  const before = {}, after = {};
  for (const [field, value] of Object.entries(body || {})) {
    if (field === "redis_password" || field === "clear_redis_password") continue;
    before[field] = svc.config[field] ?? null;
    after[field] = value;
    svc.config[field] = clone(value);
  }
  record("engine_update", svc, { before, after });
}

function applyAddRule(svc, kind, rule) {
  const field = RULE_FIELD[kind];
  if (!field) throw new Error("Unknown rule kind.");
  const text = ruleText(kind, rule);
  svc.config[field].push(text);
  record("rule_add", svc, { detail: { kind, index: svc.config[field].length - 1, id: kind === "native" ? rule.id : undefined } });
}

function applyAddOverride(svc, kind, entry) {
  const field = OVERRIDE_FIELD[kind];
  if (!field) throw new Error("Unknown override kind.");
  svc.config[field].push(overrideText(kind, entry));
  record(`${kind}_override_add`, svc, { detail: entry });
}

const write = async (fn) => { await sleep(220); fn(); return { ok: true }; };

export const demoApi = {
  patchEngine: (pluginId, body) => write(() => applyEngine(service(pluginId), body)),
  addRule: (pluginId, body) => write(() => applyAddRule(service(pluginId), body?.kind, body?.rule)),
  editRule: (pluginId, kind, index, body, etag) => write(() => {
    const svc = service(pluginId), list = svc.config[RULE_FIELD[kind]];
    checkEntry(list, index, etag, "rule");
    list[Number(index)] = ruleText(kind, body?.rule);
    record("rule_update", svc, { detail: { kind, index: Number(index), id: kind === "native" ? body?.rule?.id : undefined } });
  }),
  deleteRule: (pluginId, kind, index, etag) => write(() => {
    const svc = service(pluginId), list = svc.config[RULE_FIELD[kind]];
    const raw = checkEntry(list, index, etag, "rule");
    list.splice(Number(index), 1);
    record("rule_remove", svc, { detail: { kind, index: Number(index), id: kind === "native" ? parse(raw)?.id : undefined } });
  }),
  addOverride: (pluginId, kind, entry) => write(() => applyAddOverride(service(pluginId), kind, entry)),
  editOverride: (pluginId, kind, index, entry, etag) => write(() => {
    const svc = service(pluginId), list = svc.config[OVERRIDE_FIELD[kind]];
    checkEntry(list, index, etag, "override");
    list[Number(index)] = overrideText(kind, entry);
    record(`${kind}_override_update`, svc, { detail: { index: Number(index), entry } });
  }),
  deleteOverride: (pluginId, kind, index, etag) => write(() => {
    const svc = service(pluginId), list = svc.config[OVERRIDE_FIELD[kind]];
    const raw = checkEntry(list, index, etag, "override");
    list.splice(Number(index), 1);
    record(`${kind}_override_remove`, svc, { detail: { index: Number(index), removed: parse(raw) } });
  }),
  changes: async () => ({ changes: clone(state.changes) }),

  // ---- the scripted assistant ----
  aiProfiles: async () => ({ profiles: [{ id: "demo", name: "Demo assistant", provider: "demo", model: "scripted", is_default: true }] }),
  aiProviders: async () => ({ providers: [{ id: "demo", label: "Scripted demo", local: true }] }),
  conversations: async () => ({ conversations: [...state.conversations.values()]
    .sort((a, b) => b.updated_at - a.updated_at)
    .map((c) => ({ id: c.id, title: c.title, profile_id: c.profile_id,
      last_message: ([...c.messages].reverse().find((m) => m.role === "assistant")?.content || "").replace(/[*`]/g, "").slice(0, 120) })) }),
  conversation: async (id) => {
    const conversation = state.conversations.get(id);
    if (!conversation) throw new Error("Conversation not found.");
    return clone(conversation);
  },
  deleteConversation: async (id) => { state.conversations.delete(id); return { ok: true }; },
  streamAssistant: (body, onEvent, signal) => runAssistant(body, onEvent, signal),
  authorizeAssistantAction: async (id, confirm) => {
    const { action } = findAction(id);
    if (action.status !== "pending") throw new Error(`This action is ${action.status}.`);
    if (Date.now() > action.expires_at) { action.status = "expired"; throw new Error("This action expired. Ask the assistant to propose it again."); }
    if (action.review.risks.length && (confirm || "").trim() !== action.review.confirm_text) {
      throw new Error("This change is risky: type the confirmation text to authorize it.");
    }
    await sleep(300);
    const op = action.review.operation, svc = service(op.plugin_id);
    if (op.type === "update_config") applyEngine(svc, op.changes);
    else if (op.type === "add_rule") applyAddRule(svc, "native", op.rule);
    else if (op.type === "add_override") applyAddOverride(svc, op.kind, op.entry);
    action.status = "executed";
    action.narrated = false;
    record("assistant_action_execute", null, { detail: { action_id: id, tool: action.tool, title: action.review.title } });
    return { ok: true, action: clone(action) };
  },
  rejectAssistantAction: async (id) => {
    const { action } = findAction(id);
    if (action.status !== "pending") throw new Error(`This action is ${action.status}.`);
    action.status = "rejected";
    record("assistant_action_reject", null, { detail: { action_id: id, tool: action.tool, title: action.review.title } });
    return { ok: true, action: clone(action) };
  },
  applyAssistantProposal: async () => { throw new Error("Not available in the demo."); },
  rejectAssistantProposal: async () => { throw new Error("Not available in the demo."); },
};

function findAction(id) {
  for (const conversation of state.conversations.values()) {
    const action = conversation.actions.find((item) => item.id === id);
    if (action) return { conversation, action };
  }
  throw new Error("Action not found.");
}

// ---- the assistant's script ----
const byName = (name) => state.fleet.find((svc) => svc.base.name === name);

function pickTarget(mentions, fallback) {
  const mentioned = (mentions || []).filter((m) => m.type === "service")
    .map((m) => state.fleet.find((svc) => svc.base.id === m.id || svc.base.name === m.id)).find(Boolean);
  return mentioned || fallback;
}

function plan(text, mentions) {
  const t = text.toLowerCase();
  if (/rate|login|brute|password/.test(t)) {
    const svc = pickTarget(mentions, byName("checkout"));
    const rule = { id: "local_login_ratelimit", phase: "access", message: "Rate limit sign-in attempts",
      conditions: [{ variables: ["request.method"], op: "eq", value: "POST" },
                   { variables: ["request.path"], op: "beginsWith", value: "/login" }],
      action: { rate_limit: { key: "%{remote_addr}", limit: 10, window_seconds: 60 } } };
    return {
      reads: [["search_events", { service: svc.base.name, path_contains: "/login", since_minutes: 1440 }], ["get_karna_config", { service: svc.base.name }]],
      text: `Sign-in traffic on **${svc.base.name}** has no limit today: the same few addresses send POST /login dozens of times a minute, and nothing slows them down.\n\nI suggest a rate limit: at most 10 sign-in attempts per minute from one client address. Above that, Karna answers 429 until the minute is over, and regular users never get near it.\n\nThe exact rule is below. Nothing runs until you authorize it.`,
      action: { tool: "karna_add_rule", title: `${svc.base.name}: Add native rule ${rule.id}`, changes: [`Add native rule ${rule.id}`],
        risks: [], operation: { type: "add_rule", plugin_id: svc.plugin_id, kind: "native", rule } },
      done: `Done. **${rule.id}** is live on ${svc.base.name}: the 11th sign-in attempt in a minute from one address now gets a 429. You will find the rule under Rules, Custom rules, and the change in the Audit log.`,
    };
  }
  if (/false positive|noise|fp\b|922100|too many blocks/.test(t)) {
    const svc = pickTarget(mentions, byName("checkout"));
    const entry = { selector: { ids: ["922100"] }, action: { type: "passthrough" } };
    return {
      reads: [["rule_stats", { service: svc.base.name, since_minutes: 1440 }], ["search_events", { rule_id: "922100", limit: 20 }]],
      text: `Rule **922100** (multipart charset mismatch) fired 121 times on **${svc.base.name}** from 96 different addresses, spread evenly through the day. That is not what an attack looks like: it is one client library sending a charset the rule does not expect.\n\nI can stop 922100 from blocking on ${svc.base.name}. Keep in mind that it then stops blocking real attacks of that kind too, so the card asks you to type the service name.`,
      action: { tool: "karna_add_override", title: `${svc.base.name}: Add an action override`,
        changes: [`Add an action override: ${JSON.stringify(entry)}`],
        risks: ["Drops the terminal action of the selected rules (passthrough): they stop blocking."],
        confirm_text: svc.base.name, operation: { type: "add_override", plugin_id: svc.plugin_id, kind: "action", entry } },
      done: `Done. 922100 no longer blocks on ${svc.base.name}. Watch Events for a few days: if real multipart attacks show up, remove the override under Rules, Overrides.`,
    };
  }
  if (/detection|disable|turn off|switch off|stop blocking/.test(t)) {
    const svc = pickTarget(mentions, state.fleet.find((s) => s.config.engine_blocking_mode) || byName("public-api"));
    return {
      reads: [["get_karna_config", { service: svc.base.name }]],
      text: `In detection mode Karna keeps inspecting **${svc.base.name}** and logs every match, but it stops blocking. It is the right mode while you tune a new service, and the wrong one for a service already in production.\n\nIf you still want it, the card is below. It weakens the WAF, so it asks you to type the service name.`,
      action: { tool: "karna_update_config", title: `${svc.base.name}: Set engine_blocking_mode to false`, changes: ["Set engine_blocking_mode to false"],
        risks: ["Turns blocking off: matches are only logged."], confirm_text: svc.base.name,
        operation: { type: "update_config", plugin_id: svc.plugin_id, changes: { engine_blocking_mode: false } } },
      done: `Done. ${svc.base.name} is in detection mode: matches are logged, nothing is blocked. Switch it back from the Services page when you are ready.`,
    };
  }
  const svc = pickTarget(mentions, null) || byName("partner-api");
  if (!svc || svc.config.engine_blocking_mode) {
    const detecting = state.fleet.filter((s) => !s.config.engine_blocking_mode).map((s) => s.base.name);
    return {
      reads: [["rule_stats", { since_minutes: 1440 }], ["list_services", {}]],
      text: detecting.length
        ? `The busiest rules today are 942100 (SQL injection) and 941100 (XSS), and they block everywhere they fire. Still in detection: ${detecting.map((n) => `**${n}**`).join(", ")}. Ask me to look at one of them, or about rate limits and false positives.`
        : "Every service is in blocking mode and the busiest rules, 942100 (SQL injection) and 941100 (XSS), block everywhere they fire. Nothing needs your attention right now. Ask me about rate limits or false positives.",
    };
  }
  return {
    reads: [["rule_stats", { since_minutes: 1440 }], ["search_events", { service: svc.base.name, action: "detect", limit: 20 }], ["get_karna_config", { service: svc.base.name }]],
    text: `I looked at the last 24 hours across your ${state.fleet.length} services.\n\n- **${svc.base.name}** is still in detection mode. Rule 942190 (MSSQL/Oracle SQLi probes) matched 58 times there, from 5 addresses in two short bursts, and none of those requests were blocked.\n- 942100 and 941100 are the busiest rules, and they already block on every service where they fire.\n- 922100 on **checkout** looks like steady noise from one client library: 121 hits from 96 addresses.\n\nThe change that helps most is switching ${svc.base.name} to blocking. The exact change is below; nothing runs until you authorize it.`,
    action: { tool: "karna_update_config", title: `${svc.base.name}: Set engine_blocking_mode to true`, changes: ["Set engine_blocking_mode to true"],
      risks: [], operation: { type: "update_config", plugin_id: svc.plugin_id, changes: { engine_blocking_mode: true } } },
    done: `Done. ${svc.base.name} now blocks matching requests. You can see it on the Services page, and the change is in the Audit log.`,
  };
}

async function streamText(conversation, runId, text, onEvent, signal) {
  for (const piece of text.split(/(\s+)/)) {
    if (!piece) continue;
    await sleep(piece.trim() ? 22 : 0, signal);
    onEvent({ type: "message.delta", run_id: runId, delta: piece });
  }
  const message = { id: uid(), role: "assistant", content: text, created_at: Date.now() };
  conversation.messages.push(message);
  onEvent({ type: "message.completed", run_id: runId, message: clone(message) });
}

async function runAssistant(body, onEvent, signal) {
  const runId = uid();
  if (body.resume) {
    const conversation = state.conversations.get(body.conversation_id);
    const action = conversation?.actions.find((item) => item.status === "executed" && item.narrated === false);
    if (!action) return;
    onEvent({ type: "run.started", run_id: runId, conversation_id: conversation.id });
    action.narrated = true;
    await sleep(400, signal);
    await streamText(conversation, runId, action.done, onEvent, signal);
    conversation.updated_at = Date.now();
    onEvent({ type: "run.completed", run_id: runId });
    return;
  }
  let conversation = body.conversation_id && state.conversations.get(body.conversation_id);
  if (!conversation) {
    conversation = { id: uid(), title: body.message.slice(0, 80), profile_id: "demo", messages: [], activities: [],
      actions: [], proposals: [], created_at: Date.now(), updated_at: Date.now() };
    state.conversations.set(conversation.id, conversation);
  }
  for (const item of conversation.actions) if (item.status === "pending") item.status = "expired";
  const userMessage = { id: uid(), role: "user", content: body.message, created_at: Date.now(), mentions: body.mentions || [] };
  conversation.messages.push(userMessage);
  onEvent({ type: "run.started", run_id: runId, conversation_id: conversation.id, message: clone(userMessage) });

  const script = plan(body.message, body.mentions);
  let seq = 0;
  const activity = (kind, status, label, detail = {}) => {
    const item = { id: uid(), run_id: runId, seq: (seq += 1), kind, status, label, detail, created_at: Date.now() };
    conversation.activities.push(item);
    onEvent({ type: "activity", activity: clone(item) });
  };
  activity("provider_api", "running", "Ask Demo assistant · scripted", { step: 1 });
  for (const [tool, args] of script.reads) {
    await sleep(520, signal);
    activity("tool", "completed", `Read: ${tool}`, args);
  }
  await sleep(380, signal);
  await streamText(conversation, runId, script.text, onEvent, signal);
  if (script.action) {
    const action = { id: uid(), conversation_id: conversation.id, tool: script.action.tool, args: script.action.operation,
      status: "pending", created_at: Date.now(), expires_at: Date.now() + ACTION_TTL_MS, done: script.done,
      review: { title: script.action.title, changes: script.action.changes, risks: script.action.risks,
        confirm_text: script.action.confirm_text, operation: script.action.operation } };
    conversation.actions.push(action);
    activity("tool", "completed", `Proposed: ${script.action.tool}`, { waiting: "your authorization" });
    onEvent({ type: "action.created", action: clone(action) });
  }
  conversation.updated_at = Date.now();
  onEvent({ type: "run.completed", run_id: runId });
}
