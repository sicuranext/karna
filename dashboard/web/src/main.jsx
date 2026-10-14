import React from "react";
import ReactDOM from "react-dom/client";

// Self-hosted fonts — vendored at build time, never fetched from a CDN.
import "./styles/fonts.css";

import "./styles/karna-dash.css";
import App from "./App.jsx";

const boot = document.querySelector("#app .boot");
if (boot) boot.remove();

ReactDOM.createRoot(document.getElementById("app")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
