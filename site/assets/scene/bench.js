/* Benchmark page: the lead chart is a lead.js scene, the per-scenario charts
 * are bars.js scenes. A scene is built when its
 * box comes near the viewport and disposed when it scrolls far away, so the
 * page never holds more than a few WebGL contexts. Without WebGL each box
 * shows the same numbers as a plain table. */
import { Stage, webglAvailable } from "./kit.js";
import { barsScene } from "./bars.js";
import { leadScene } from "./lead.js";

const COLUMNS = ["same req", "random fields", "big form", "deep JSON", "multipart", "attack", "mixed", "API+attacks"];
const WAF = {
  karna:  { name: "Karna",          short: "Karna",  fill: "#3b4148", edge: "#171a1e", karna: true },
  nginx:  { name: "Nginx+ModSec3",  short: "Nginx",  fill: "#9aa3ad", edge: "#4f5a65" },
  apache: { name: "Apache+ModSec2", short: "Apache", fill: "#cfd4da", edge: "#7d8994" },
  coraza: { name: "Caddy+Coraza",   short: "Coraza", fill: "#eceff2", edge: "#9aa3ad" },
};
const RPS = {
  karna:  [1541.6, 1309.5, 20.1, 227.8, 540.7, 3325.5, 1568.5, 815.3],
  nginx:  [1262.8, 1138.6, 14.4, 219.8, 580, 1622.5, 1269.6, 687.7],
  apache: [642.8, 391.9, 1.9, 200.7, 485.6, 852.2, 611.9, 190.0],
  coraza: [376.8, 319.2, 1.8, 107.4, 276.8, 570.0, 337.3, 183.5],
};

const CONFIGS = {
  // Karna's lead per scenario against every other WAF, one row each
  lead: () => ({
    scene: leadScene, columns: COLUMNS, karna: RPS.karna,
    others: ["nginx", "apache", "coraza"].map((k) => ({ ...WAF[k], values: RPS[k] })),
  }),
  scn: (el) => {
    const v = el.dataset.values.split(",").map(Number);
    return {
      layout: "row", unit: "rps", values: true, hmax: 2.2, el: 20, az: -16,
      series: ["karna", "nginx", "apache", "coraza"].map((k, i) => ({ ...WAF[k], values: [v[i]] })),
    };
  },
};

function shell(el) {
  el.innerHTML = `<div class="k3d-viewport">
      <div class="k3d-canvas" aria-hidden="true"></div>
      <div class="k3d-labels" aria-hidden="true"></div>
      <div class="k3d-frame" aria-hidden="true"><i class="tl"></i><i class="tr"></i><i class="bl"></i><i class="br"></i></div>
    </div>`;
  return el.querySelector(".k3d-viewport");
}

function leadTable(cfg) {
  const pct = (o) => cfg.karna.map((k, i) => { const p = Math.round((k / o.values[i] - 1) * 100); return (p >= 0 ? "+" : "−") + Math.abs(p) + "%"; });
  return `<table><tr><th>Karna lead</th>${cfg.columns.map((c) => `<th>${c}</th>`).join("")}</tr>${cfg.others.map((o) => `<tr><td>vs ${o.short}</td>${pct(o).map((v) => `<td>${v}</td>`).join("")}</tr>`).join("")}</table>`;
}

function fallbackTable(el, cfg) {
  const fmtv = (v) => (cfg.unit === "×" ? v.toFixed(2) + "×" : v.toLocaleString("en-US"));
  const head = cfg.layout === "row" ? "" : `<tr><th></th>${cfg.columns.map((c) => `<th>${c}</th>`).join("")}</tr>`;
  if (cfg.scene === leadScene) { el.innerHTML = `<div class="k3d-fallback">${leadTable(cfg)}</div>`; return; }
  const rows = [...cfg.series].reverse().map((s) => `<tr><td>${s.name}</td>${s.values.map((v) => `<td>${fmtv(v)}</td>`).join("")}</tr>`).join("");
  el.innerHTML = `<div class="k3d-fallback"><table>${head}${rows}</table></div>`;
}

function setup(el) {
  const cfg = CONFIGS[el.dataset.scene](el);
  if (!webglAvailable()) { fallbackTable(el, cfg); return; }
  let stage = null;
  const viewport = shell(el);
  const scene = cfg.scene || barsScene;
  // small screens: the numbers under each group would collide, so they go in a table
  if (scene === leadScene) el.insertAdjacentHTML("beforeend", `<div class="k3d-fallback lead-table">${leadTable(cfg)}</div>`);
  const io = new IntersectionObserver(([e]) => {
    if (e.isIntersecting && !stage) {
      try {
        stage = new Stage(viewport.querySelector(".k3d-canvas"), viewport.querySelector(".k3d-labels"));
        stage.mount(scene, cfg);
        el.classList.add("is-live"); el.closest(".k3d")?.classList.add("is-live");
      } catch (err) { fallbackTable(el, cfg); io.disconnect(); }
    } else if (!e.isIntersecting && stage) {
      stage.dispose(); stage = null;
    }
  }, { rootMargin: "400px 0px" });
  io.observe(el);
}

document.querySelectorAll("[data-scene]").forEach(setup);
