import React from "react";
import { Brand } from "../components/brand.jsx";
import { Icon } from "../components/icons.jsx";
import { useAuth } from "../auth/AuthProvider.jsx";
import { CopyBtn } from "../components/ui.jsx";

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const LOG_CMD = "docker compose logs dashboard-api";
// Plain HTTP is fine on the machine itself; from anywhere else the password
// and the session token cross the network readable by anyone on the path.
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const insecure = window.location.protocol === "http:" && !LOCAL_HOSTS.has(window.location.hostname);

export default function Login() {
  const { registered, register, login } = useAuth();
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [setupToken, setSetupToken] = React.useState("");
  const [pending, setPending] = React.useState(false);
  const [error, setError] = React.useState(null);

  const isRegister = !registered;
  const emailOk = EMAIL_RE.test(email.trim());
  const pwOk = password.length >= 10;
  const tokenOk = !isRegister || setupToken.trim().length > 0;
  const canSubmit = emailOk && pwOk && tokenOk && !pending;

  const submit = async (e) => {
    e.preventDefault();
    if (!canSubmit) return;
    setPending(true);
    setError(null);
    try {
      if (isRegister) await register(email.trim().toLowerCase(), password, setupToken.trim());
      else await login(email.trim().toLowerCase(), password);
    } catch (err) {
      setError(err.message || "Something went wrong");
      setPending(false);
    }
  };

  return (
    <div data-theme="dark" data-accent="gold" data-density="airy"
      style={{ display: "grid", placeItems: "center", minHeight: "100vh", padding: 24, background: "var(--page)" }}>
      <div style={{ width: 360, maxWidth: "100%" }}>
        <div className="row" style={{ gap: 12, marginBottom: 22, justifyContent: "center" }}>
          <Brand size={34} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 18, letterSpacing: "-0.01em" }}>Karna</div>
            <div className="mono" style={{ fontSize: 11, color: "var(--fg-3)" }}>WAF Console</div>
          </div>
        </div>

        {insecure && (
          <div role="alert" style={{ marginBottom: 14, padding: "12px 14px", border: "1px solid color-mix(in srgb, var(--danger) 40%, transparent)", background: "var(--danger-soft)", fontSize: 12.5, lineHeight: 1.5 }}>
            <strong style={{ color: "var(--danger)" }}>This connection is not encrypted.</strong>{" "}
            The console is open over plain HTTP from another machine, so your password and session can be read on
            the network. Put it behind an HTTPS reverse proxy or reach it through an SSH tunnel (see the README).
          </div>
        )}

        <div className="card">
          <div style={{ marginBottom: 16 }}>
            <h1 style={{ fontSize: 19, margin: 0 }}>{isRegister ? "Create the admin account" : "Sign in"}</h1>
            <p className="hint" style={{ marginTop: 6, marginBottom: 0 }}>
              {isRegister
                ? "First run: create the single administrator for this console. This can only be done once."
                : "Enter your administrator credentials."}
            </p>
          </div>

          {isRegister && (
            <div style={{ marginBottom: 16, padding: "12px 14px", border: "1px solid var(--border-1)", background: "var(--inset)" }}>
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6 }}>Why a setup token?</div>
              <p className="hint" style={{ margin: "0 0 8px", fontSize: 12.5, lineHeight: 1.5 }}>
                Until an admin exists, anyone who can reach this page could claim the console. The setup
                token proves you also control the server: the API printed it in its log when it started,
                and it stops working once the admin is created.
              </p>
              <p className="hint" style={{ margin: "0 0 6px", fontSize: 12.5 }}>On the server running the console:</p>
              <div className="row" style={{ gap: 6, alignItems: "center" }}>
                <code className="mono" style={{ flex: 1, fontSize: 11.5, padding: "6px 8px", background: "var(--surface)", border: "1px solid var(--border-1)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{LOG_CMD}</code>
                <CopyBtn text={LOG_CMD} label="Copy command" />
              </div>
              <p className="hint" style={{ margin: "8px 0 0", fontSize: 11.5 }}>
                Set <span className="mono">KARNA_DASH_SETUP_TOKEN</span> on the API container to choose the token yourself.
              </p>
            </div>
          )}

          <form onSubmit={submit}>
            {isRegister && (
              <div className="field" style={{ marginBottom: 12 }}>
                <label>Setup token</label>
                <input className="input mono" type="text" autoComplete="off" spellCheck={false} value={setupToken}
                  onChange={(e) => setSetupToken(e.target.value)} placeholder="from the API container log" />
              </div>
            )}
            <div className="field" style={{ marginBottom: 12 }}>
              <label>Email</label>
              <input className="input" type="email" autoComplete="username" value={email}
                onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
            </div>
            <div className="field" style={{ marginBottom: 6 }}>
              <label>Password</label>
              <input className="input" type="password" autoComplete={isRegister ? "new-password" : "current-password"}
                value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••••" />
              {isRegister && (
                <span className="desc" style={{ color: pwOk ? "var(--success)" : "var(--fg-4)" }}>
                  At least 10 characters.
                </span>
              )}
            </div>

            {error && (
              <div className="row" style={{ gap: 8, color: "var(--danger)", fontSize: 12.5, margin: "10px 0" }}>
                <Icon name="flame" size={14} />{error}
              </div>
            )}

            <button type="submit" className="btn primary" disabled={!canSubmit}
              style={{ width: "100%", justifyContent: "center", marginTop: 14, opacity: canSubmit ? 1 : 0.55 }}>
              {pending ? "…" : isRegister ? "Create account" : "Sign in"}
            </button>
          </form>
        </div>

        <p className="hint" style={{ textAlign: "center", marginTop: 16, fontSize: 11 }}>
          Every change is recorded in the audit trail
        </p>
      </div>
    </div>
  );
}
