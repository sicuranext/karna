import React from "react";
import { Icon } from "./icons.jsx";

const FOCUSABLE = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

/* Centered modal. Closes on scrim click, Esc, or the X. `head` renders next
 * to the title (e.g. tabs); `foot` is an optional sticky footer. Traps Tab
 * inside the dialog and restores focus to the opener on close. size="sm"
 * renders a narrow dialog (confirmations). */
export function Modal({ open, onClose, title, head, foot, size, className = "", children }) {
  const ref = React.useRef(null);
  const onCloseRef = React.useRef(onClose);
  onCloseRef.current = onClose;

  React.useEffect(() => {
    if (!open) return;
    const opener = document.activeElement;
    // Focus the dialog itself so Esc/Tab work immediately, unless a child
    // (e.g. an autoFocus button) already took focus.
    const t = setTimeout(() => {
      if (ref.current && !ref.current.contains(document.activeElement)) ref.current.focus();
    }, 0);

    const onKey = (e) => {
      if (e.key === "Escape") { onCloseRef.current(); return; }
      if (e.key !== "Tab" || !ref.current) return;
      const items = [...ref.current.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null);
      if (!items.length) return;
      const first = items[0], last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      clearTimeout(t);
      window.removeEventListener("keydown", onKey);
      if (opener && opener.focus) opener.focus();
    };
    // The focus lifecycle belongs to the open/closed state. Callers often
    // create a fresh onClose callback during live-data refreshes; depending on
    // that callback would run this cleanup while the dialog is still open and
    // steal focus from whichever input the operator is editing.
  }, [open]);

  if (!open) return null;
  return (
    <div className="modal-scrim" onClick={onClose}>
      <div
        className={`modal${size === "sm" ? " sm" : ""}${className ? ` ${className}` : ""}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        ref={ref}
      >
        <div className="modal-head">
          {title}
          <span className="spacer" style={{ flex: 1 }} />
          {head}
          <button className="icon-btn" onClick={onClose} aria-label="Close"><Icon name="x" size={16} /></button>
        </div>
        <div className="modal-body">{children}</div>
        {foot && <div className="modal-foot">{foot}</div>}
      </div>
    </div>
  );
}
