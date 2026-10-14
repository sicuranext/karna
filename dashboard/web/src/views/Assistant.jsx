import React from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Icon } from "../components/icons.jsx";
import { api } from "../data/api.js";

/* Links are shown as text, never as anchors: a model steered by what it read
 * could put data into a URL, and one click would send it out. The address
 * stays visible, so it can still be copied on purpose. */
function LinkAsText({ href, children: label }) {
  const text = React.Children.toArray(label).join("");
  return <span className="assistant-link-text">{label}{href && href !== text ? <span className="mono"> ({href})</span> : null}</span>;
}

function Markdown({ children }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml components={{
      a: LinkAsText,
      img: ({ alt }) => <span className="assistant-image-blocked">[Remote image blocked{alt ? `: ${alt}` : ""}]</span>,
    }}>{children}</ReactMarkdown>
  );
}

function ActivityTimeline({ activities }) {
  if (!activities.length) return null;
  return (
    <details className="assistant-activities" open={activities.some((item) => item.status === "running")}>
      <summary><Icon name="pulse" size={13} /><span>{activities.length} {activities.length === 1 ? "activity" : "activities"}</span><span className="spacer" /><Icon name="chevd" size={11} /></summary>
      <div className="assistant-activity-list">
        {activities.map((item) => (
          <div key={item.id || `${item.run_id}:${item.seq}`} className={`assistant-activity ${item.status}`}>
            <span className="assistant-activity-mark">{item.status === "completed" ? <Icon name="check" size={11} /> : item.status === "failed" ? <Icon name="x" size={11} /> : <span className="system-dot online" />}</span>
            <div><strong>{item.label}</strong>{item.detail && Object.keys(item.detail).length > 0 && <pre>{JSON.stringify(item.detail, null, 2)}</pre>}</div>
          </div>
        ))}
      </div>
    </details>
  );
}

/* Seconds left until `expiresAt` (ms), ticking once a second; null without a deadline. */
function useSecondsLeft(expiresAt, active) {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    if (!active || !expiresAt) return undefined;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [active, expiresAt]);
  if (!expiresAt) return null;
  return Math.max(Math.ceil((expiresAt - now) / 1000), 0);
}

function ExpiryNote({ secondsLeft }) {
  if (secondsLeft == null) return null;
  const m = Math.floor(secondsLeft / 60), sec = String(secondsLeft % 60).padStart(2, "0");
  return (
    <span className={`assistant-expiry${secondsLeft <= 60 ? " soon" : ""}`} role="timer" aria-live="off">
      <Icon name="clock" size={11} />{secondsLeft > 0 ? `Expires in ${m}:${sec}` : "Expired"}
    </span>
  );
}

/* The server's review leads: what the operation changes and what it weakens,
 * written from the operation itself. The model's own summary is shown as its
 * note, because it can be wrong or steered by what the model read. A change
 * that weakens the WAF needs the service name typed back (checked server-side). */
function ProposalCard({ proposal, confirmId, setConfirmId, busyId, onApply, onReject }) {
  const secondsLeft = useSecondsLeft(proposal.expires_at, proposal.status === "pending");
  const status = proposal.status === "pending" && secondsLeft === 0 ? "expired" : proposal.status;
  const pending = status === "pending";
  const review = proposal.review || { changes: [], risks: [] };
  const risky = review.risks.length > 0;
  const [typed, setTyped] = React.useState("");
  const confirmed = !risky || (review.confirm_service && typed.trim() === review.confirm_service);
  return (
    <section className={`assistant-proposal ${status}`}>
      <header><span><Icon name="edit" size={13} />Change proposal</span><span className="assistant-proposal-status">{pending && <ExpiryNote secondsLeft={secondsLeft} />}<span className={`tag ${status === "applied" ? "success" : status === "pending" ? "warning" : ""}`}>{status}</span></span></header>
      {review.changes.length > 0 && (
        <ul className="assistant-proposal-changes">{review.changes.map((line) => <li key={line}>{line}</li>)}</ul>
      )}
      {risky && (
        <div className="assistant-proposal-risks" role="alert">
          <strong><Icon name="flame" size={13} /> This weakens the WAF</strong>
          <ul>{review.risks.map((line) => <li key={line}>{line}</li>)}</ul>
        </div>
      )}
      <p className="assistant-proposal-note"><span>Assistant's note</span>{proposal.summary}</p>
      <details className="assistant-proposal-raw">
        <summary>Exact operation <code>{proposal.operation.type}</code> → <code>{proposal.operation.plugin_id}</code></summary>
        <pre>{JSON.stringify(proposal.operation, null, 2)}</pre>
      </details>
      {proposal.error && <p className="assistant-error">Last apply attempt: {proposal.error}</p>}
      {status === "expired" && proposal.status === "pending" && <p className="hint">This proposal expired. Ask the assistant to propose it again.</p>}
      {pending && confirmId !== proposal.id && <div className="assistant-proposal-actions"><button className="btn primary sm" onClick={() => { setTyped(""); setConfirmId(proposal.id); }} disabled={Boolean(busyId)}>Review &amp; apply</button><button className="btn sm" onClick={() => onReject(proposal.id)} disabled={Boolean(busyId)}>Dismiss</button></div>}
      {pending && confirmId === proposal.id && (
        <div className="assistant-proposal-confirm">
          <p><strong>Apply this exact change to Kong?</strong> The action is audited and cannot be undone from this chat.</p>
          {risky && (
            <label className="assistant-proposal-typed">
              <span>Type the service name <code>{review.confirm_service || "?"}</code> to confirm</span>
              <input className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
            </label>
          )}
          <div><button className="btn danger sm" onClick={() => onApply(proposal.id, risky ? typed.trim() : undefined)} disabled={Boolean(busyId) || !confirmed}>{busyId === proposal.id ? "Applying…" : "Confirm apply"}</button><button className="btn sm" onClick={() => setConfirmId(null)} disabled={Boolean(busyId)}>Cancel</button></div>
        </div>
      )}
    </section>
  );
}

const ACTION_STATUS = {
  pending: ["warning", "waiting for you"], executing: ["", "running…"], executed: ["success", "done"],
  rejected: ["", "rejected"], expired: ["", "expired"], failed: ["danger", "failed"],
};

/* A change the assistant wants to make. Nothing has run: the server wrote this
 * review from the exact operation (current state, result preview, risks), and
 * only Authorize runs it. A risky one needs the confirmation text typed back. */
function ActionCard({ action, busyId, onAuthorize, onReject }) {
  const review = action.review || {};
  const risks = review.risks || [];
  const secondsLeft = useSecondsLeft(action.expires_at, action.status === "pending");
  const status = action.status === "pending" && secondsLeft === 0 ? "expired" : action.status;
  const pending = status === "pending";
  const [typed, setTyped] = React.useState("");
  const confirmed = !risks.length || (review.confirm_text && typed.trim() === review.confirm_text);
  const [tag, label] = ACTION_STATUS[status] || ["", status];
  const busy = busyId === action.id;
  return (
    <section className={`assistant-proposal assistant-action ${status}`}>
      <header><span><Icon name="edit" size={13} />{pending ? "The assistant wants to make a change" : "Change"}</span><span className="assistant-proposal-status">{pending && <ExpiryNote secondsLeft={secondsLeft} />}<span className={`tag ${tag}`}>{label}</span></span></header>
      <p className="assistant-action-title mono">{review.title || action.tool}</p>
      {(review.changes || []).length > 1 && <ul className="assistant-proposal-changes">{review.changes.map((line) => <li key={line}>{line}</li>)}</ul>}
      {risks.length > 0 && (
        <div className="assistant-proposal-risks" role="alert">
          <strong><Icon name="flame" size={13} /> Read this before authorizing</strong>
          <ul>{risks.map((line) => <li key={line}>{line}</li>)}</ul>
        </div>
      )}
      {(review.content || []).map((item) => (
        <div className="assistant-action-content" key={item.label}>
          <span className="eyebrow">{item.label}</span>
          <pre>{item.text}</pre>
        </div>
      ))}
      {(review.before || review.after || review.body || review.operation) && (
        <details className="assistant-proposal-raw" open={pending && Boolean(review.before || review.after)}>
          <summary>{review.before || review.after ? "Before and after" : "Exact operation"}</summary>
          {review.before || review.after ? (
            <div className="assistant-action-diff">
              <div><span className="eyebrow">Now</span><pre>{review.before ? JSON.stringify(review.before, null, 2) : "— (does not exist)"}</pre></div>
              <div><span className="eyebrow">After</span><pre>{review.after ? JSON.stringify(review.after, null, 2) : "— (deleted)"}</pre></div>
            </div>
          ) : <pre>{JSON.stringify(review.operation || review.body, null, 2)}</pre>}
        </details>
      )}
      {action.error && <p className="assistant-error">{action.error}</p>}
      {status === "expired" && action.status === "pending" && <p className="hint">This request expired. Ask the assistant to propose it again.</p>}
      {pending && (
        <div className="assistant-proposal-confirm">
          {risks.length > 0 && (
            <label className="assistant-proposal-typed">
              <span>Type <code>{review.confirm_text || "?"}</code> to authorize</span>
              <input className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
            </label>
          )}
          <div>
            <button className="btn primary sm" onClick={() => onAuthorize(action.id, risks.length ? typed.trim() : undefined)} disabled={Boolean(busyId) || !confirmed}>{busy ? "Running…" : "Authorize"}</button>
            <button className="btn sm" onClick={() => onReject(action.id)} disabled={Boolean(busyId)}>Reject</button>
          </div>
          <p className="hint">Nothing runs until you authorize it, and the request expires after 10 minutes. Every change is recorded on the Audit page.</p>
        </div>
      )}
    </section>
  );
}

function ConversationContent({ messages, activities, proposals, actions, running, bottomRef, confirmId, setConfirmId, busyId, onApply, onReject, onAuthorize, onRejectAction }) {
  const receiving = messages.some((message) => message.streaming);
  return (
    <div className="assistant-thread">
      {messages.length === 0 && (
        <div className="assistant-empty">
          <span className="assistant-empty-mark"><Icon name="shield" size={26} /></span>
          <span className="eyebrow">Karna Configuration Copilot</span>
          <h2>Describe the policy you need.</h2>
          <p>Ask about what Karna blocked, why, and how to change it. The assistant reads events and configuration on its own; any change waits for your Authorize click.</p>
        </div>
      )}
      {messages.map((message, index) => {
        const nextMessage = messages[index + 1];
        const related = message.role === "user" ? activities.filter((item) =>
          item.created_at >= message.created_at && (!nextMessage || item.created_at <= nextMessage.created_at)) : [];
        return (
          <React.Fragment key={message.id || index}>
            <article className={`assistant-message ${message.role}${message.streaming ? " streaming" : ""}`}>
              <div className="assistant-message-role">{message.role === "user" ? "You" : `Karna assistant${message.streaming ? " · streaming" : ""}`}</div>
              <div className="assistant-message-body">{message.role === "assistant" ? <Markdown>{message.content}</Markdown> : <p>{message.content}</p>}</div>
            </article>
            {proposals.filter((proposal) => proposal.message_id === message.id).map((proposal) => <ProposalCard key={proposal.id} proposal={proposal} confirmId={confirmId} setConfirmId={setConfirmId} busyId={busyId} onApply={onApply} onReject={onReject} />)}
            {actions.filter((action) => action.created_at >= (message.created_at || 0) && (!nextMessage || action.created_at < (nextMessage.created_at || Infinity))).map((action) => <ActionCard key={action.id} action={action} busyId={busyId} onAuthorize={onAuthorize} onReject={onRejectAction} />)}
            {message.role === "user" && <ActivityTimeline activities={related} />}
          </React.Fragment>
        );
      })}
      {running && !receiving && <div className="assistant-thinking"><span className="system-dot online" />Working…</div>}
      <div ref={bottomRef} />
    </div>
  );
}

function mentionCatalog(data) {
  const items = [];
  const configuredIds = new Set([...data.localRules, ...data.customSecrules].map((rule) => String(rule.id)));
  data.localRules.forEach((rule) => items.push({
    type: "rule", id: `native:${rule.plugin_id}:${rule.index}`, label: `rule:${rule.id}`,
    description: `${rule.service} · ${rule.message || "native rule"}`,
    search: `${rule.id} ${rule.service} ${rule.message || ""} native`,
  }));
  data.customSecrules.forEach((rule) => items.push({
    type: "rule", id: `seclang:${rule.plugin_id}:${rule.index}`, label: `rule:${rule.id}`,
    description: `${rule.service} · SecLang`, search: `${rule.id} ${rule.service} seclang`,
  }));
  const observed = new Map();
  const addObserved = (rule) => {
    const id = String(rule?.rule_id || "").trim();
    if (!id || configuredIds.has(id)) return;
    const current = observed.get(id) || { id, message: "", hits: 0, tags: [] };
    current.message ||= String(rule.message || "");
    current.hits = Math.max(current.hits, Number(rule.hits) || 0);
    current.tags = [...new Set([...current.tags, ...(Array.isArray(rule.tags) ? rule.tags : [])])];
    observed.set(id, current);
  };
  data.topRules.forEach(addObserved);
  data.events.forEach((event) => (event.matches || []).forEach((match) => addObserved({ ...match, hits: 1 })));
  [...observed.values()].sort((a, b) => b.hits - a.hits || a.id.localeCompare(b.id)).forEach((rule) => items.push({
    type: "rule", id: `observed:${rule.id}`, label: `rule:${rule.id}`,
    description: `${rule.message || "Observed Karna / CRS rule"}${rule.hits ? ` · ${rule.hits} hits` : ""}`,
    search: `${rule.id} ${rule.message} ${rule.tags.join(" ")} crs observed`,
  }));
  data.services.forEach((service) => {
    items.push({ type: "service", id: service.id, label: `service:${service.name}`, description: service.host, search: `${service.name} ${service.host || ""}` });
    items.push({ type: "config", id: service.id, label: `config:${service.name}`, description: "Karna service configuration", search: service.name });
    items.push({ type: "rules", id: service.id, label: `rules:${service.name}`, description: "All local rules for this service", search: service.name });
  });
  return items;
}

export default function Assistant({ data, param, nav, navReplace }) {
  const [profiles, setProfiles] = React.useState([]);
  const [providers, setProviders] = React.useState([]);
  const [profileId, setProfileId] = React.useState("");
  const [conversations, setConversations] = React.useState([]);
  const [conversation, setConversation] = React.useState(null);
  const [message, setMessage] = React.useState("");
  const [mentions, setMentions] = React.useState([]);
  const [activities, setActivities] = React.useState([]);
  const [proposals, setProposals] = React.useState([]);
  const [actions, setActions] = React.useState([]);
  const [running, setRunning] = React.useState(false);
  const [error, setError] = React.useState("");
  const [removeTarget, setRemoveTarget] = React.useState(null);
  const [confirmId, setConfirmId] = React.useState(null);
  const [busyId, setBusyId] = React.useState(null);
  const controllerRef = React.useRef(null);
  const runIdRef = React.useRef(null);
  const bottomRef = React.useRef(null);
  const catalog = React.useMemo(() => mentionCatalog(data), [data]);

  const loadIndex = React.useCallback(async () => {
    const [profileResponse, providerResponse, conversationResponse] = await Promise.all([
      api.aiProfiles(), api.aiProviders(), api.conversations(),
    ]);
    const nextProfiles = profileResponse.profiles || [];
    setProfiles(nextProfiles); setProviders(providerResponse.providers || []);
    setConversations(conversationResponse.conversations || []);
    setProfileId((current) => current || nextProfiles.find((item) => item.is_default)?.id || nextProfiles[0]?.id || "");
  }, []);

  React.useEffect(() => { loadIndex().catch((err) => setError(err.message)); }, [loadIndex]);
  React.useEffect(() => {
    if (!param) { setConversation(null); setActivities([]); setProposals([]); setActions([]); return; }
    api.conversation(param).then((item) => {
      setConversation(item); setActivities(item.activities || []); setProposals(item.proposals || []); setActions(item.actions || []); setProfileId(item.profile_id);
    }).catch((err) => { setError(err.message); navReplace("assistant"); });
  }, [param, navReplace]);
  React.useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" }); }, [conversation?.messages, activities, running]);

  const mentionMatch = message.match(/(?:^|\s)@([^\s@]*)$/);
  const mentionNeedle = (mentionMatch?.[1] || "").toLocaleLowerCase();
  const suggestions = mentionMatch ? catalog
    .filter((item) => `${item.label} ${item.search || ""}`.toLocaleLowerCase().includes(mentionNeedle))
    .sort((a, b) => {
      const rank = (item) => (item.label.toLocaleLowerCase().startsWith(mentionNeedle) ? 0 : 2) + (item.type === "rule" ? 0 : 1);
      return rank(a) - rank(b) || a.label.localeCompare(b.label);
    }).slice(0, 12) : [];
  const addMention = (resource) => {
    setMessage((current) => current.replace(/@[^\s@]*$/, `@${resource.label} `));
    setMentions((current) => current.some((item) => item.type === resource.type && item.id === resource.id) ? current : [...current, resource]);
  };

  const onEvent = (event) => {
    if (event.type === "run.started") {
      runIdRef.current = event.run_id;
      if (!param) nav("assistant", event.conversation_id);
      if (event.message) setConversation((current) => ({
        ...(current || { id: event.conversation_id, title: event.message.content.slice(0, 80), profile_id: profileId }),
        messages: [...(current?.messages || []), event.message],
      }));
    } else if (event.type === "activity") {
      setActivities((current) => [...current, event.activity]);
    } else if (event.type === "message.delta") {
      const transientId = `stream:${event.run_id}`;
      setConversation((current) => {
        const messages = current?.messages || [];
        const index = messages.findIndex((item) => item.id === transientId);
        if (index < 0) return { ...current, messages: [...messages, { id: transientId, role: "assistant", content: event.delta, streaming: true, created_at: Date.now() }] };
        return { ...current, messages: messages.map((item, itemIndex) => itemIndex === index ? { ...item, content: item.content + event.delta } : item) };
      });
    } else if (event.type === "message.completed") {
      const transientId = `stream:${event.run_id}`;
      setConversation((current) => {
        const messages = current?.messages || [];
        return { ...current, messages: messages.some((item) => item.id === transientId)
          ? messages.map((item) => item.id === transientId ? event.message : item)
          : [...messages, event.message] };
      });
    } else if (event.type === "action.created") {
      setActions((current) => [...current, event.action]);
    } else if (event.type === "proposal.created") {
      setProposals((current) => [...current, event.proposal]);
    } else if (event.type === "run.failed") {
      setConversation((current) => ({ ...current, messages: (current?.messages || []).filter((item) => item.id !== `stream:${event.run_id}`) }));
      setError(event.error || "Assistant run failed");
    }
  };

  const runStream = async (body) => {
    setError(""); setRunning(true);
    const controller = new AbortController(); controllerRef.current = controller;
    try {
      await api.streamAssistant(body, onEvent, controller.signal);
      await loadIndex();
    } catch (err) {
      if (err.name !== "AbortError") setError(err.message);
      const interruptedRun = runIdRef.current;
      if (interruptedRun) setConversation((current) => ({ ...current, messages: (current?.messages || []).filter((item) => item.id !== `stream:${interruptedRun}`) }));
    } finally { setRunning(false); controllerRef.current = null; runIdRef.current = null; }
  };

  const send = async (event) => {
    event.preventDefault();
    if (!message.trim() || !profileId || running) return;
    const text = message.trim();
    setMessage(""); setMentions([]);
    // a new message leaves pending changes unauthorized (the server expires them)
    setActions((current) => current.map((item) => item.status === "pending" ? { ...item, status: "expired" } : item));
    await runStream({ conversation_id: conversation?.id || null, profile_id: profileId, message: text,
      mentions: mentions.map(({ type, id }) => ({ type, id })) });
  };

  const updateAction = (next) => next && setActions((current) => current.map((item) => item.id === next.id ? next : item));
  const authorizeAction = async (id, confirm) => {
    setBusyId(id); setError("");
    try {
      const response = await api.authorizeAssistantAction(id, confirm);
      updateAction(response.action);
      if (!response.ok && response.action?.error) setError(response.action.error);
    } catch (err) {
      setError(err.message);
      if (conversation?.id) await api.conversation(conversation.id).then((item) => setActions(item.actions || []));
      setBusyId(null);
      return;
    }
    setBusyId(null);
    // let the assistant see the result and carry on
    await runStream({ conversation_id: conversation.id, profile_id: profileId, resume: true });
  };
  const rejectAction = async (id) => {
    setBusyId(id); setError("");
    try { const response = await api.rejectAssistantAction(id); updateAction(response.action); }
    catch (err) { setError(err.message); }
    finally { setBusyId(null); }
  };

  const removeConversation = async (item) => {
    await api.deleteConversation(item.id);
    if (conversation?.id === item.id) nav("assistant");
    setRemoveTarget(null); await loadIndex();
  };
  const updateProposal = (next) => setProposals((current) => current.map((item) => item.id === next.id ? next : item));
  const applyProposal = async (id, confirmService) => {
    setBusyId(id); setError("");
    try {
      const response = await api.applyAssistantProposal(id, confirmService);
      updateProposal(response.proposal); setConfirmId(null);
    } catch (err) {
      setError(err.message);
      if (conversation?.id) await api.conversation(conversation.id).then((item) => setProposals(item.proposals || []));
    } finally { setBusyId(null); }
  };
  const rejectProposal = async (id) => {
    setBusyId(id); setError("");
    try { const response = await api.rejectAssistantProposal(id); updateProposal(response.proposal); }
    catch (err) { setError(err.message); }
    finally { setBusyId(null); }
  };
  const selectedProfile = profiles.find((item) => item.id === profileId);
  const selectedProvider = providers.find((item) => item.id === selectedProfile?.provider);

  if (!profiles.length) return (
    <div className="view-inner"><div className="assistant-unconfigured card"><Icon name="chat" size={28} /><h1>Configure an AI profile</h1><p>The Karna assistant appears after at least one local or remote model profile is saved.</p><button className="btn primary" onClick={() => nav("settings")}>Open AI profile settings</button></div></div>
  );

  return (
    <div className="assistant-shell">
      <aside className="assistant-history">
        <div className="assistant-history-head"><span className="eyebrow">Conversations</span><button className="icon-btn" title="New conversation" aria-label="New conversation" onClick={() => nav("assistant")}><Icon name="plus" size={14} /></button></div>
        <div className="assistant-history-list">
          {conversations.map((item) => <div key={item.id} className={`assistant-history-item ${conversation?.id === item.id ? "active" : ""}`}><button onClick={() => nav("assistant", item.id)}><strong>{item.title}</strong><span>{item.last_message || "No response yet"}</span></button><button className="icon-btn" aria-label={`Delete ${item.title}`} onClick={() => setRemoveTarget(item)}><Icon name="x" size={11} /></button></div>)}
          {!conversations.length && <p className="hint">No saved conversations.</p>}
        </div>
      </aside>
      <section className="assistant-workspace">
        <header className="assistant-toolbar">
          <div><span className="eyebrow">Assistant · changes need your authorization</span><strong>{conversation?.title || "New conversation"}</strong></div>
          <span className={`tag dot ${selectedProvider?.local ? "success" : "warning"}`}>{selectedProvider?.local ? "local" : "remote"}</span>
          <select className="input sel" value={profileId} onChange={(event) => setProfileId(event.target.value)} aria-label="AI profile">{profiles.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.model}</option>)}</select>
        </header>
        <ConversationContent messages={conversation?.messages || []} activities={activities} proposals={proposals} actions={actions} onAuthorize={authorizeAction} onRejectAction={rejectAction} running={running} bottomRef={bottomRef} confirmId={confirmId} setConfirmId={setConfirmId} busyId={busyId} onApply={applyProposal} onReject={rejectProposal} />
        <form className="assistant-composer" onSubmit={send}>
          {suggestions.length > 0 && <div className="assistant-mentions-menu">{suggestions.map((item) => <button type="button" key={`${item.type}:${item.id}`} onClick={() => addMention(item)}><span><strong>@{item.label}</strong><small>{item.description}</small></span><span className="tag">{item.type}</span></button>)}</div>}
          {mentions.length > 0 && <div className="assistant-context-chips">{mentions.map((item) => <button type="button" key={`${item.type}:${item.id}`} onClick={() => setMentions((current) => current.filter((candidate) => candidate !== item))}>@{item.label}<Icon name="x" size={10} /></button>)}</div>}
          <div className="assistant-compose-box"><textarea value={message} onChange={(event) => setMessage(event.target.value)} placeholder="Ask about events, rules or configuration… Type @ to point at a service or rule" rows={3} disabled={running} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); send(event); } }} /><div className="assistant-compose-foot"><span className="hint">Enter to send · Shift+Enter for a new line</span>{running ? <button type="button" className="btn danger sm" onClick={() => controllerRef.current?.abort()}>Stop</button> : <button type="submit" className="btn primary sm" disabled={!message.trim()}>Send <Icon name="arrowr" size={12} /></button>}</div></div>
          {error && <div className="assistant-error">{error}</div>}
        </form>
      </section>
      {removeTarget && <div className="assistant-delete-toast"><span>Delete “{removeTarget.title}”?</span><button className="btn danger sm" onClick={() => removeConversation(removeTarget)}>Delete</button><button className="btn sm" onClick={() => setRemoveTarget(null)}>Cancel</button></div>}
    </div>
  );
}
