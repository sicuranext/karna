/* API client. Bearer token in sessionStorage (per tab, gone when the tab
 * closes); every call carries Authorization. A 401 on a non-auth path means
 * the session expired or was revoked → clear + notify so the app falls back to
 * the login screen. No cookies → no CSRF surface. */
const TOKEN_KEY = "karna.token";
const store = (() => { try { return window.sessionStorage; } catch { return null; } })();
try { window.localStorage.removeItem(TOKEN_KEY); } catch { /* storage blocked */ }  // tokens used to live here
let _token = (store && store.getItem(TOKEN_KEY)) || null;
let _onUnauthorized = null;

export function getToken() { return _token; }
export function setToken(t) {
  _token = t || null;
  try {
    if (t) store?.setItem(TOKEN_KEY, t);
    else store?.removeItem(TOKEN_KEY);
  } catch { /* storage blocked: the token lives in memory only */ }
}
export function onUnauthorized(fn) { _onUnauthorized = fn; }

// every value interpolated into an API path goes through this
const seg = (value) => encodeURIComponent(String(value ?? ""));

async function apiFetch(path, opts = {}) {
  const headers = { accept: "application/json", ...(opts.headers || {}) };
  if (_token) headers.authorization = `Bearer ${_token}`;
  if (opts.body && !headers["content-type"]) headers["content-type"] = "application/json";

  const res = await fetch(path, { ...opts, headers });
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = text; } }

  if (res.status === 401) {
    const isAuthPath = path.startsWith("/api/auth/");
    if (!isAuthPath) {
      setToken(null);
      if (_onUnauthorized) _onUnauthorized();
    }
    const e = new Error((data && data.detail) || "Authentication required");
    e.status = 401;
    throw e;
  }
  if (!res.ok) {
    const e = new Error((data && data.detail) || `Error ${res.status}`);
    e.status = res.status;
    throw e;
  }
  return data;
}

async function streamNdjson(path, body, onEvent, signal) {
  const headers = { accept: "application/x-ndjson", "content-type": "application/json" };
  if (_token) headers.authorization = `Bearer ${_token}`;
  const res = await fetch(path, { method: "POST", headers, body: JSON.stringify(body), signal });
  if (res.status === 401) {
    setToken(null);
    if (_onUnauthorized) _onUnauthorized();
  }
  if (!res.ok) {
    let detail = `Error ${res.status}`;
    try { detail = (await res.json()).detail || detail; } catch { /* keep generic detail */ }
    const error = new Error(detail); error.status = res.status; throw error;
  }
  if (!res.body) throw new Error("Streaming is not supported by this browser");
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";
    for (const line of lines) {
      if (!line.trim()) continue;
      onEvent(JSON.parse(line));
    }
    if (done) break;
  }
  if (buffer.trim()) onEvent(JSON.parse(buffer));
}

export const api = {
  status: () => apiFetch("/api/auth/status"),
  logout: () => apiFetch("/api/auth/logout", { method: "POST" }),
  changePassword: (currentPassword, newPassword) => apiFetch("/api/auth/password", {
    method: "POST", body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  }),
  register: (email, password, setupToken) => apiFetch("/api/auth/register", { method: "POST", body: JSON.stringify({ email, password, setup_token: setupToken }) }),
  login: (email, password) => apiFetch("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  me: () => apiFetch("/api/auth/me"),
  setupState: () => apiFetch("/api/setup"),
  completeSetup: (skipped = false) => apiFetch("/api/setup/complete", { method: "POST", body: JSON.stringify({ skipped }) }),
  dashboard: () => apiFetch("/api/dashboard"),
  refreshKongInventory: () => apiFetch("/api/kong/inventory/refresh", { method: "POST" }),
  changes: () => apiFetch("/api/changes"),
  aiProviders: () => apiFetch("/api/ai/providers"),
  aiProfiles: () => apiFetch("/api/ai/profiles"),
  saveAiProfile: (body) => apiFetch("/api/ai/profiles", { method: "POST", body: JSON.stringify(body) }),
  testAiProfile: (body) => apiFetch("/api/ai/profiles/test", { method: "POST", body: JSON.stringify(body) }),
  deleteAiProfile: (id) => apiFetch(`/api/ai/profiles/${seg(id)}`, { method: "DELETE" }),
  conversations: () => apiFetch("/api/assistant/conversations"),
  conversation: (id) => apiFetch(`/api/assistant/conversations/${seg(id)}`),
  deleteConversation: (id) => apiFetch(`/api/assistant/conversations/${seg(id)}`, { method: "DELETE" }),
  streamAssistant: (body, onEvent, signal) => streamNdjson("/api/assistant/chat", body, onEvent, signal),
  applyAssistantProposal: (id, confirmService) => apiFetch(`/api/assistant/proposals/${seg(id)}/apply`, {
    method: "POST", body: JSON.stringify(confirmService ? { confirm_service: confirmService } : {}),
  }),
  rejectAssistantProposal: (id) => apiFetch(`/api/assistant/proposals/${seg(id)}/reject`, { method: "POST" }),
  authorizeAssistantAction: (id, confirm) => apiFetch(`/api/assistant/actions/${seg(id)}/authorize`, {
    method: "POST", body: JSON.stringify(confirm ? { confirm } : {}),
  }),
  rejectAssistantAction: (id) => apiFetch(`/api/assistant/actions/${seg(id)}/reject`, { method: "POST" }),
  kongConnection: () => apiFetch("/api/kong/connection"),
  kongConnections: () => apiFetch("/api/kong/connections"),
  saveKongConnection: (body) => apiFetch("/api/kong/connections", { method: "POST", body: JSON.stringify(body) }),
  testKongConnection: (body) => apiFetch("/api/kong/connections/test-activate", { method: "POST", body: JSON.stringify(body) }),
  activateKongConnection: (id) => apiFetch(`/api/kong/connections/${seg(id)}/activate`, { method: "POST" }),
  deleteKongConnection: (id) => apiFetch(`/api/kong/connections/${seg(id)}`, { method: "DELETE" }),
  setKongConnection: (body) => apiFetch("/api/kong/connection", { method: "PATCH", body: JSON.stringify(body) }),
  logConfig: () => apiFetch("/api/logs/config"),
  setLogTtl: (ttl_days) => apiFetch("/api/logs/config", { method: "PATCH", body: JSON.stringify({ ttl_days }) }),
  purgeLogs: () => apiFetch("/api/logs/purge", { method: "POST", body: JSON.stringify({ confirm: true }) }),
  patchEngine: (pluginId, body) => apiFetch(`/api/plugins/${seg(pluginId)}/engine`, { method: "PATCH", body: JSON.stringify(body) }),
  addOverride: (pluginId, kind, entry) => apiFetch(`/api/plugins/${seg(pluginId)}/overrides/${seg(kind)}`, { method: "POST", body: JSON.stringify(entry) }),
  // edit / delete by position carry the entry's content tag (etag from the
  // dashboard payload): the server refuses with 409 if the entry changed meanwhile
  editOverride: (pluginId, kind, index, entry, etag) => apiFetch(`/api/plugins/${seg(pluginId)}/overrides/${seg(kind)}/${seg(index)}?expected=${seg(etag)}`, { method: "PATCH", body: JSON.stringify(entry) }),
  deleteOverride: (pluginId, kind, index, etag) => apiFetch(`/api/plugins/${seg(pluginId)}/overrides/${seg(kind)}/${seg(index)}?expected=${seg(etag)}`, { method: "DELETE" }),
  addRule: (pluginId, body) => apiFetch(`/api/plugins/${seg(pluginId)}/rules`, { method: "POST", body: JSON.stringify(body) }),
  editRule: (pluginId, kind, index, body, etag) => apiFetch(`/api/plugins/${seg(pluginId)}/rules/${seg(kind)}/${seg(index)}?expected=${seg(etag)}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteRule: (pluginId, kind, index, etag) => apiFetch(`/api/plugins/${seg(pluginId)}/rules/${seg(kind)}/${seg(index)}?expected=${seg(etag)}`, { method: "DELETE" }),
};
