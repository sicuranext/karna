import React from "react";
import { api, getToken, setToken, onUnauthorized } from "../data/api.js";
import { MODE } from "../data/mode.js";

const AuthCtx = React.createContext(null);
export const useAuth = () => React.useContext(AuthCtx);

export function AuthProvider({ children }) {
  const [ready, setReady] = React.useState(false);
  const [registered, setRegistered] = React.useState(false);
  const [email, setEmail] = React.useState(null);

  const boot = React.useCallback(async () => {
    if (MODE !== "live") { setReady(true); return; }   // sample and demo have no backend
    try {
      const st = await api.status();
      setRegistered(!!st.registered);
      if (getToken()) {
        try {
          const me = await api.me();
          setEmail(me.email);
        } catch {
          setToken(null);
          setEmail(null);
        }
      }
    } catch {
      // backend unreachable — leave unauthenticated; the screens surface it
    } finally {
      setReady(true);
    }
  }, []);

  React.useEffect(() => {
    onUnauthorized(() => setEmail(null));
    boot();
  }, [boot]);

  const register = async (e, p, setupToken) => {
    const r = await api.register(e, p, setupToken);
    setToken(r.token);
    setEmail(r.email);
    setRegistered(true);
  };
  const login = async (e, p) => {
    const r = await api.login(e, p);
    setToken(r.token);
    setEmail(r.email);
  };
  // Signing out revokes every session on the server (single admin), then
  // clears this tab even when the server is unreachable.
  const logout = async () => {
    try { await api.logout(); } catch { /* already expired or offline */ }
    setToken(null);
    setEmail(null);
  };
  const changePassword = async (current, next) => {
    const r = await api.changePassword(current, next);
    setToken(r.token);          // the old token was revoked with the old password
  };

  return (
    <AuthCtx.Provider value={{ ready, registered, email, authed: !!email, register, login, logout, changePassword }}>
      {children}
    </AuthCtx.Provider>
  );
}
