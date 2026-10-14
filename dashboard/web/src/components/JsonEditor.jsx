import React from "react";
import { EditorView, placeholder as cmPlaceholder } from "@codemirror/view";
import { EditorState } from "@codemirror/state";
import { basicSetup } from "codemirror";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { autocompletion } from "@codemirror/autocomplete";
import { linter } from "@codemirror/lint";
import { tags as t } from "@lezer/highlight";

/* ---- Karna native-rule schema (drives the completions) ---- */
const TOP_KEYS = {
  id: "Unique rule id", phase: "access | header_filter | body_filter | mcp_event",
  message: "Human-readable description", log: "Emit an audit entry (default true)",
  tags: "Array of tags", paranoia_level: "1–4", conditions: "Array of match conditions",
  action: "What to do on match", rule_control: "Per-request rule controls",
};
const COND_KEYS = {
  variables: "Array of variable names to inspect", op: "Operator", value: "Operator value / pattern",
  transform: "Array of transforms applied before the operator", negated: "Invert the operator",
  multi_match: "Collect all matching values",
};
const ACTION_KEYS = {
  fixed_response: "Terminate with a fixed response (block)", fix_matched_parts: "Sanitize matched chars, pass upstream",
  setvar: "Set a tx.* variable", set_variable: "Write into kong.ctx.plugin / .shared",
  rate_limit: "Redis fixed-window rate limit", redis_set: "Write a Redis key",
  redis_sadd: "Add to a Redis set", redis_del: "Delete a Redis key", set_log_fields: "Add custom audit fields",
};
const FIXED_RESPONSE_KEYS = { status_code: "HTTP status (default 403)", body: "Response body (static text)", headers: "Response headers object" };
const RATE_LIMIT_KEYS = { key: "Macro key, default %{remote_addr}", limit: "Max requests", window_seconds: "Window size", response: "Response when exceeded" };
const FIX_KEYS = { remove_chars_pattern: "Chars to strip, e.g. [<>\"'&;|`$()]" };

const PHASES = ["access", "header_filter", "body_filter", "mcp_event"];
const OPS = ["rx", "eq", "ge", "gt", "lt", "le", "beginsWith", "endsWith", "contains", "isSet",
  "pm", "pmFromFile", "within", "ipMatch", "libinjection_sqli", "libinjection_xss",
  "validateUrlEncoding", "validateByteRange", "validateUtf8Encoding", "unconditionalMatch",
  "mcp_method_in", "mcp_jsonrpc_valid"];
const TRANSFORMS = ["none", "lowercase", "uppercase", "urlDecode", "urlDecodeUni", "htmlEntityDecode",
  "removeWhitespace", "compressWhitespace", "removeNulls", "replaceNulls", "normalizePath",
  "base64Decode", "base64Encode", "hexDecode", "cssDecode", "jsDecode", "cmdLine", "length", "sha1", "md5"];
const VARIABLES = ["request.arg.value", "request.arg.name", "request.uri.path", "request.method",
  "request.body", "request.header.value:user-agent", "request.header.value:content-type",
  "request.header.name", "request.cookie.value", "request.cookie.name", "request.query.value",
  "request.remote_addr", "request.line", "geoip.country_code", "asn.id"];

const BOOL = [true, false];
const RULE_VALUES = {
  phase: PHASES, op: OPS, transform: TRANSFORMS, variables: VARIABLES,
  negated: BOOL, multi_match: BOOL, log: BOOL,
  status_code: [403, 401, 429, 400, 200], paranoia_level: [1, 2, 3, 4],
  limit: [10, 50, 100, 1000], window_seconds: [10, 60, 300],
};

// rule_action_overrides / rule_response_overrides schema
const SELECTOR_KEYS = {
  ids: "Rule ids to match (array)", id_ranges: "Ranges e.g. 942000-942999",
  tags: "Match rules by tag", except_ids: "Exclude these ids",
  except_tags: "Exclude these tags", any: "Match every rule (true)",
};
const OVR_ACTION_KEYS = { type: "fix | passthrough | block", remove_chars_pattern: "Chars to strip (type=fix)" };
const OVR_RESPONSE_KEYS = { status_code: "HTTP status", body: "Body (static text)", headers: "Headers object" };

const SCHEMAS = {
  rule: {
    roles: { root: TOP_KEYS, conditions: COND_KEYS, action: ACTION_KEYS, fixed_response: FIXED_RESPONSE_KEYS,
      response: FIXED_RESPONSE_KEYS, rate_limit: RATE_LIMIT_KEYS, fix_matched_parts: FIX_KEYS },
    values: RULE_VALUES,
  },
  "override-action": {
    roles: { root: { selector: "Which rules this targets", action: "What to do on a match" }, selector: SELECTOR_KEYS, action: OVR_ACTION_KEYS },
    values: { type: ["fix", "passthrough", "block"], any: BOOL },
  },
  "override-response": {
    roles: { root: { selector: "Which rules this targets", response: "Custom block response" }, selector: SELECTOR_KEYS, response: OVR_RESPONSE_KEYS },
    values: { any: BOOL, status_code: [403, 401, 429, 400, 200] },
  },
};

// Forward scan from the document start to the cursor, tracking string state and
// a container stack. Robust to incomplete JSON (an unterminated trailing string
// is just `inStr` at the end) — the common case while typing. Each frame knows
// its role (the key it belongs to), the current property key, and whether we're
// past a ':' (value position).
function scan(text, pos) {
  const st = [];
  let inStr = false, esc = false, openAt = -1;
  for (let i = 0; i < pos; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') {
        inStr = false;
        const top = st[st.length - 1];
        if (top && top.type === "{" && !top.expectValue) top.curKey = text.slice(top.strStart + 1, i);
      }
      continue;
    }
    if (ch === '"') { inStr = true; openAt = i; const top = st[st.length - 1]; if (top) top.strStart = i; continue; }
    if (ch === "{" || ch === "[") {
      const parent = st[st.length - 1];
      let role;
      if (!parent) role = "root";
      else if (parent.type === "{") role = parent.expectValue ? parent.curKey : "root";
      else role = parent.role; // array element inherits the array's key as its role
      st.push({ type: ch, role, curKey: null, expectValue: false, strStart: -1 });
    } else if (ch === "}" || ch === "]") {
      st.pop();
    } else if (ch === ":") {
      const top = st[st.length - 1]; if (top && top.type === "{") top.expectValue = true;
    } else if (ch === ",") {
      const top = st[st.length - 1]; if (top && top.type === "{") { top.expectValue = false; top.curKey = null; }
    }
  }
  return { top: st[st.length - 1], inStr, strStart: openAt };
}

function optsFromValues(values) {
  return values.map((v) => {
    if (v === true || v === false) return { label: String(v), type: "keyword", apply: String(v) };
    if (typeof v === "number") return { label: String(v), type: "number", apply: String(v) };
    return { label: v, type: "enum", apply: `"${v}"` };
  });
}

// End of the string body at/after `to` (the closing quote position, or EOL).
// Computed against the LIVE doc at apply time — the closing quote shifts as the
// user keeps typing after the completion popped, so request-time offsets go stale.
function endOfString(doc, to) {
  let end = to;
  while (end < doc.length && doc[end] !== "\n" && !(doc[end] === '"' && doc[end - 1] !== "\\")) end++;
  return end;
}

function makeComplete(schema) {
  return function karnaComplete(ctx) {
  const full = ctx.state.doc.toString();
  const { top, inStr, strStart } = scan(full, ctx.pos);
  if (!top) return null;

  // --- value contexts: array element, or object property value ---
  let valueKey = null;
  if (top.type === "[") valueKey = top.role;
  else if (top.type === "{" && top.expectValue) valueKey = top.curKey;
  if (valueKey !== null) {
    const values = schema.values[valueKey];
    if (!values) return null;
    if (inStr) {
      // Inside "…": filter on the bare content, replace the whole string body.
      const contentStart = strStart + 1;
      const strVals = values.filter((v) => typeof v === "string");
      if (!strVals.length) return null;
      const options = strVals.map((v) => ({
        label: v, type: "enum",
        apply: (view, c, from, to) => {
          const end = endOfString(view.state.doc.toString(), to);
          view.dispatch({ changes: { from, to: end, insert: v }, selection: { anchor: from + v.length } });
        },
      }));
      return { from: contentStart, options, validFor: /^[\w./:@\-]*$/ };
    }
    // Not yet in a string → insert a full quoted (or bare bool/number) value.
    const word = ctx.matchBefore(/[\w./:@\-]*/);
    return { from: word ? word.from : ctx.pos, options: optsFromValues(values), validFor: /^[\w./:@\-]*$/ };
  }

  // --- object key context ---
  if (top.type !== "{") return null;
  const keys = schema.roles[top.role];
  if (!keys) return null;
  const entries = Object.entries(keys);
  if (inStr) {
    const contentStart = strStart + 1;
    const options = entries.map(([k, detail]) => ({
      label: k, type: "property", detail,
      apply: (view, c, from, to) => {
        const d = view.state.doc.toString();
        const end = endOfString(d, to);
        const afterClosing = d[end] === '"' ? end + 1 : end;
        const ins = `"${k}": `;
        view.dispatch({ changes: { from: from - 1, to: afterClosing, insert: ins }, selection: { anchor: from - 1 + ins.length } });
      },
    }));
    return { from: contentStart, options, validFor: /^[\w]*$/ };
  }
  const word = ctx.matchBefore(/[\w]*/);
  const options = entries.map(([k, detail]) => ({ label: k, type: "property", detail, apply: `"${k}": ` }));
  return { from: word ? word.from : ctx.pos, options, validFor: /^[\w]*$/ };
  };
}

const karnaHighlight = HighlightStyle.define([
  { tag: t.propertyName, color: "var(--accent)" },
  { tag: t.string, color: "var(--success)" },
  { tag: t.number, color: "var(--info)" },
  { tag: [t.bool, t.null], color: "var(--warning)" },
  { tag: [t.punctuation, t.separator, t.brace, t.bracket], color: "var(--fg-3)" },
]);

const karnaTheme = EditorView.theme({
  "&": { color: "var(--fg-1)", backgroundColor: "var(--inset)", fontSize: "12.5px", borderRadius: "var(--r-sm)", border: "1px solid var(--border-1)" },
  "&.cm-focused": { outline: "none", borderColor: "var(--border-3)" },
  ".cm-scroller": { fontFamily: "var(--font-mono)", lineHeight: "1.55" },
  ".cm-content": { padding: "10px 0", caretColor: "var(--accent)" },
  ".cm-gutters": { backgroundColor: "transparent", color: "var(--fg-4)", border: "none" },
  ".cm-activeLine": { backgroundColor: "var(--hover)" },
  ".cm-activeLineGutter": { backgroundColor: "transparent", color: "var(--fg-3)" },
  ".cm-cursor": { borderLeftColor: "var(--accent)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "rgba(23,26,30,0.10)" },
  ".cm-tooltip": { backgroundColor: "var(--surface-2)", border: "1px solid var(--border-2)", borderRadius: "var(--r-sm)", boxShadow: "var(--shadow-2)" },
  ".cm-tooltip.cm-tooltip-autocomplete > ul": { fontFamily: "var(--font-mono)", fontSize: "12px", maxHeight: "16em" },
  ".cm-tooltip-autocomplete > ul > li": { padding: "4px 9px", color: "var(--fg-2)" },
  ".cm-tooltip-autocomplete > ul > li[aria-selected]": { backgroundColor: "var(--accent-soft)", color: "var(--accent)" },
  ".cm-completionDetail": { color: "var(--fg-4)", fontStyle: "normal", marginLeft: "10px" },
  ".cm-completionIcon": { display: "none" },
}, { dark: false });

export default function JsonEditor({ value, onChange, placeholder = "", minHeight = 280, schema = "rule" }) {
  const host = React.useRef(null);
  const view = React.useRef(null);
  const onChangeRef = React.useRef(onChange);
  onChangeRef.current = onChange;
  const completeSource = React.useRef(makeComplete(SCHEMAS[schema] || SCHEMAS.rule)).current;

  React.useEffect(() => {
    const state = EditorState.create({
      doc: value || "",
      extensions: [
        basicSetup,
        json(),
        syntaxHighlighting(karnaHighlight),
        autocompletion({ override: [completeSource], activateOnTyping: true, defaultKeymap: true }),
        linter(jsonParseLinter()),
        karnaTheme,
        EditorView.lineWrapping,
        cmPlaceholder(placeholder),
        EditorView.theme({ "&": { minHeight: `${minHeight}px` }, ".cm-scroller": { minHeight: `${minHeight}px` } }),
        EditorView.updateListener.of((u) => {
          if (u.docChanged && onChangeRef.current) onChangeRef.current(u.state.doc.toString());
        }),
      ],
    });
    const v = new EditorView({ state, parent: host.current });
    view.current = v;
    return () => v.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // External value changes (e.g. opening the modal prefilled) → sync into the editor.
  React.useEffect(() => {
    const v = view.current;
    if (v && value != null && value !== v.state.doc.toString()) {
      v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value } });
    }
  }, [value]);

  return <div ref={host} className="json-editor" />;
}
