/* Landing hero: the console's 24h traffic scene (traffic.js, unchanged) on
 * the console's sample data, with the same status card, focus stages and
 * Replay. Loaded as a module only when the hero is on screen; without WebGL
 * the static still in the markup stays. */
import { Stage, webglAvailable, clamp } from "./kit.js";
import { trafficScene } from "./traffic.js";

const REQ = [3.1, 2.4, 1.9, 1.6, 1.4, 1.7, 2.6, 4.2, 6.8, 8.9, 9.6, 9.1, 8.4, 8.8, 9.3, 9.7, 9.2, 8.1, 7.0, 6.2, 5.4, 4.6, 3.9, 3.3];
const BLK = [41, 33, 28, 22, 19, 24, 38, 61, 96, 142, 168, 151, 133, 147, 188, 214, 176, 129, 104, 88, 71, 60, 52, 44];
const TRAFFIC = REQ.map((r, i) => ({ label: String(i).padStart(2, "0") + ":00", requests: Math.round(r * 1000), blocked: BLK[i] }));

const fmt = (n) => n.toLocaleString("en-US");
const peak = TRAFFIC.reduce((m, t) => (t.blocked > m.blocked ? t : m));
const STAGES = [
  { title: "Traffic and blocks", desc: "Every hour Karna inspected, what it stopped, and the share of traffic that was hostile." },
  { title: "What Karna stopped", desc: "Requests blocked, sanitized or rate-limited per hour, on their own scale." },
  { title: "Peak blocking hour", desc: `${fmt(peak.blocked)} requests stopped at ${peak.label}, the busiest hour for Karna in the window.` },
];

export function mountHero(root) {
  if (!webglAvailable()) return;
  const viewport = root.querySelector(".k3d-viewport");
  // the hero viewport is less wide than the console's, so pull the camera
  // back as the aspect narrows (the kit only ever brings it closer)
  const zoom = () => { const r = viewport.getBoundingClientRect(); return clamp(2.15 / (r.width / Math.max(r.height, 1)), 1, 1.6); };
  let stage;
  try {
    stage = new Stage(viewport.querySelector(".k3d-canvas"), viewport.querySelector(".k3d-labels"), { cam: { R: 12 * zoom() } });
  } catch (e) {
    return;
  }
  const setGoal = stage.setGoal.bind(stage);
  stage.setGoal = (g) => setGoal(g.R ? { ...g, R: g.R * zoom() } : g);
  root.classList.add("is-live");
  stage.mount(trafficScene, TRAFFIC);

  const step = root.querySelector(".k3d-step"), title = root.querySelector(".k3d-status strong"), desc = root.querySelector(".k3d-status > span:last-child");
  const buttons = [...root.querySelectorAll(".k3d-phases button")];
  const show = (n) => {
    trafficScene.setStage(stage, stage.built, n);
    buttons.forEach((b, i) => b.setAttribute("aria-pressed", String(i === n)));
    step.textContent = `0${n + 1} / 0${STAGES.length}`;
    title.textContent = STAGES[n].title;
    desc.textContent = STAGES[n].desc;
  };
  buttons.forEach((b, i) => b.addEventListener("click", () => show(i)));
  root.querySelector(".k3d-replay").addEventListener("click", () => {
    show(0);
    stage.t = 0; stage.user = { az: 0, el: 0 }; stage.kick();
  });
  show(0);
}
