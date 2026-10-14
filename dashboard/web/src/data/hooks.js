import { useState } from "react";
import { useConfirm } from "../components/ConfirmProvider.jsx";

/* Small wrapper for write actions: optional in-app confirm, pending + error
 * state, and a refresh on success. Keeps the views free of repeated
 * try/catch. confirmMsg may be a string or {message, title, danger,
 * confirmLabel} for the dialog. */
export function useMutation(refresh) {
  const confirm = useConfirm();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(null);

  const run = async (fn, confirmMsg) => {
    if (confirmMsg) {
      const opts = typeof confirmMsg === "string" ? { message: confirmMsg } : confirmMsg;
      const ok = await confirm(opts.message, opts);
      if (!ok) return false;
    }
    setPending(true);
    setError(null);
    try {
      await fn();
      if (refresh) refresh();
      return true;
    } catch (e) {
      setError(e.message || String(e));
      return false;
    } finally {
      setPending(false);
    }
  };

  return { run, pending, error, clearError: () => setError(null) };
}
