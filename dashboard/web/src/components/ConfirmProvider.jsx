/* In-app confirmation dialog, replacing window.confirm. useConfirm() returns
 * a promise-based confirm(message, opts) that renders in the console's own
 * Modal — consistent styling, a real danger variant, and explanatory copy. */
import React from "react";
import { Modal } from "./modal.jsx";

const ConfirmCtx = React.createContext(null);

export function useConfirm() {
  const ctx = React.useContext(ConfirmCtx);
  // Fallback keeps things working if a caller ever renders outside the provider.
  return ctx || ((message) => Promise.resolve(window.confirm(message)));
}

export function ConfirmProvider({ children }) {
  const [req, setReq] = React.useState(null); // {message, title, danger, confirmLabel, resolve}

  const confirm = React.useCallback((message, opts = {}) => {
    return new Promise((resolve) => setReq({ message, ...opts, resolve }));
  }, []);

  const answer = (ok) => {
    if (req) req.resolve(ok);
    setReq(null);
  };

  return (
    <ConfirmCtx.Provider value={confirm}>
      {children}
      <Modal
        open={!!req}
        size="sm"
        onClose={() => answer(false)}
        title={<div className="ct" style={{ fontSize: 15.5, fontWeight: 600 }}>{req?.title || "Please confirm"}</div>}
        foot={
          <div className="row" style={{ gap: 8 }}>
            <button
              className={"btn primary" + (req?.danger ? " confirm-danger" : "")}
              autoFocus
              onClick={() => answer(true)}
            >
              {req?.confirmLabel || "Confirm"}
            </button>
            <button className="btn" onClick={() => answer(false)}>Cancel</button>
          </div>
        }
      >
        <p style={{ margin: 0, fontSize: 13.5, lineHeight: 1.65, color: "var(--fg-2)", whiteSpace: "pre-line" }}>
          {req?.message}
        </p>
      </Modal>
    </ConfirmCtx.Provider>
  );
}
