/* Tiny hash router. Routes look like #/events, #/events/<request_id>,
 * #/rules, #/rules/overrides, #/services/<service_id>. The hash is the single source of
 * truth for navigation, so deep links and the back button just work. */
import { useCallback, useEffect, useState } from "react";

export const VIEWS = new Set(["overview", "events", "services", "rules", "assistant", "audit", "settings"]);

// Old localStorage view ids from the pre-router console.
const LEGACY = { mode: { view: "services" }, customrules: { view: "rules", param: "custom" } };

export function parseHash() {
  const h = window.location.hash.replace(/^#\/?/, "");
  if (!h) return null;
  const [view, ...rest] = h.split("/");
  if (!VIEWS.has(view)) return null;
  return { view, param: rest.length ? decodeURIComponent(rest.join("/")) : null };
}

export function toHash(view, param) {
  return "#/" + view + (param ? "/" + encodeURIComponent(param) : "");
}

function initialRoute() {
  const fromHash = parseHash();
  if (fromHash) return fromHash;
  const stored = localStorage.getItem("karna.view");
  if (stored && LEGACY[stored]) return LEGACY[stored];
  if (stored && VIEWS.has(stored)) return { view: stored, param: null };
  return { view: "overview", param: null };
}

export function useRoute() {
  const [route, setRoute] = useState(initialRoute);

  useEffect(() => {
    // Normalize the address bar on first load (covers the no-hash case).
    const want = toHash(route.view, route.param);
    if (window.location.hash !== want) window.history.replaceState(null, "", want);
    const onChange = () => {
      const r = parseHash();
      if (r) setRoute(r);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const nav = useCallback((view, param) => {
    if (!VIEWS.has(view)) return;
    localStorage.setItem("karna.view", view);
    window.location.hash = toHash(view, param || null);
  }, []);

  // Swap the param without adding a history entry (e.g. closing a modal).
  const navReplace = useCallback((view, param) => {
    if (!VIEWS.has(view)) return;
    window.history.replaceState(null, "", toHash(view, param || null));
    setRoute({ view, param: param || null });
  }, []);

  return { route, nav, navReplace };
}
