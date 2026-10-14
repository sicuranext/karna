/* Overview rule timeline: the ten rules that matched most in the last 24 hours,
 * one row each (most matched at the back), hours along the floor, a ribbon whose
 * height is the matches in that hour. The shape tells how a rule fires: a
 * narrow spike is a burst or a scan, a flat band is steady background noise,
 * rules lighting up in the same hour are one campaign.
 * Heights share one square-root scale so a rule with few matches still shows
 * its shape next to one with hundreds.
 * Hover reads one rule at one hour; the focus is shared with the detections
 * list (the scene emits { rule }, the list sets it through setFocus). */
import { THREE, PAL, clamp, ease, esc } from "./kit.js";

const TOP = 10, X0 = -4.6, X1 = 4.6, GAP = 0.62, HMAX = 1.25, LABEL = 30;
const fmt = (n) => Number(n).toLocaleString("en-US");
const short = (s) => (s.length > LABEL ? s.slice(0, LABEL - 1).trimEnd() + "…" : s);

export const rulesScene = {
  build(stage, { rules, labels }) {
    const items = [...rules].filter((r) => r.hits > 0).sort((a, b) => b.hits - a.hits).slice(0, TOP);
    const n = Math.max(items.length, 1);
    const H = 24;
    const xOf = (i) => X0 + ((X1 - X0) * i) / (H - 1);
    const zOf = (k) => (k - (n - 1) / 2) * GAP;
    const peakAll = Math.max(1, ...items.flatMap((r) => r.hourly || []));
    const yOf = (v) => (Math.sqrt(Math.max(v, 0)) / Math.sqrt(peakAll)) * HMAX;
    const b = { rows: [], xOf, zOf, n, H, hover: null, focus: null, emitted: "", labels };

    stage.floor(X1 - X0 + 1.2, n * GAP + 0.6);
    const grid = [];
    for (let k = 0; k < n; k++) grid.push(new THREE.Vector3(X0 - 0.2, 0, zOf(k)), new THREE.Vector3(X1 + 0.2, 0, zOf(k)));
    b.ticks = [];
    for (let i = 0; i < H; i++) {
      if (i % 6 === 0 || i === H - 1) {
        grid.push(new THREE.Vector3(xOf(i), 0, zOf(0) - 0.35), new THREE.Vector3(xOf(i), 0, zOf(n - 1) + 0.35));
        b.ticks.push({ i, tag: stage.label("k3d-axis", esc(labels?.[i] || "")) });
      }
    }
    stage.segments(grid, PAL.grid, 0.75);

    items.forEach((r, k) => {
      const z = zOf(k);
      const hot = k === 0;
      const blocking = (r.blocked_pct ?? (r.action === "block" ? 100 : 0)) >= 50;
      const hourly = (r.hourly || []).slice(0, H);
      while (hourly.length < H) hourly.push(0);
      const pts = hourly.map((v, i) => new THREE.Vector3(xOf(i), yOf(v), z));
      const color = hot ? PAL.hot : blocking ? PAL.enc : PAL.slate;
      const line = stage.line(pts, color, 0.95, 4, !blocking);
      const ap = [], ai = [];
      pts.forEach((p) => ap.push(p.x, 0, z, p.x, p.y, z));
      for (let i = 0; i < pts.length - 1; i++) { const a = i * 2; ai.push(a, a + 1, a + 2, a + 1, a + 3, a + 2); }
      const ag = new THREE.BufferGeometry();
      ag.setAttribute("position", new THREE.Float32BufferAttribute(ap, 3)); ag.setIndex(ai);
      const area = new THREE.Mesh(ag, stage.fillMat(hot ? PAL.hot : PAL.slate, 0));
      area.renderOrder = 2; area.frustumCulled = false; stage.root.add(area);
      // peak hour of the row
      const pk = hourly.indexOf(Math.max(...hourly));
      const dot = new THREE.Mesh(new THREE.SphereGeometry(0.04, 12, 8), new THREE.MeshBasicMaterial({ color, depthTest: false, transparent: true }));
      dot.position.copy(pts[pk]); dot.renderOrder = 6; stage.root.add(dot);
      const tag = stage.label("anno anno-row" + (hot ? " is-hot" : ""), `<span><b>${esc(short(r.message || r.rule_id))}</b></span><i></i>`);
      const val = stage.label("k3d-val" + (hot ? " is-hot" : ""), fmt(r.hits));
      b.rows.push({ r, k, z, pts, hourly, line, area, dot, tag, val, hot, fillOp: hot ? 0.12 : 0.07 });
    });

    // hover: crosshair at the hour, a dot on the row
    b.cross = stage.segments([new THREE.Vector3(0, 0, zOf(0) - 0.4), new THREE.Vector3(0, 0, zOf(n - 1) + 0.4)], PAL.hot, 0.7, 6);
    b.cross.visible = false;
    b.cursor = new THREE.Mesh(new THREE.SphereGeometry(0.06, 14, 10), new THREE.MeshBasicMaterial({ color: PAL.hot, depthTest: false, transparent: true }));
    b.cursor.renderOrder = 8; b.cursor.visible = false; stage.root.add(b.cursor);
    b.card = stage.label("k3d-tip", "");

    stage.setGoal({ tx: -0.6, ty: 0.25, R: Math.max(10.5, n * 1.15), el: 36, az: -10 });
    if (!stage.camPlaced) { Object.assign(stage.cam, stage.goal); stage.camPlaced = true; }   // no swing-in

    stage.onPointer = (e) => {
      const hit = stage.floorHit(e);
      const half = (n * GAP) / 2 + 0.3;
      if (!hit || hit.x < X0 - 0.3 || hit.x > X1 + 0.3 || Math.abs(hit.z) > half) { b.hover = null; stage.host.classList.remove("is-reading"); return; }
      const k = clamp(Math.round(hit.z / GAP + (n - 1) / 2), 0, n - 1);
      const i = clamp(Math.round(((hit.x - X0) / (X1 - X0)) * (H - 1)), 0, H - 1);
      b.hover = b.rows[k] ? { row: b.rows[k], i } : null;
      stage.host.classList.toggle("is-reading", !!b.hover);
    };
    stage.onHover = () => { b.hover = null; stage.host.classList.remove("is-reading"); };
    return b;
  },

  setFocus(stage, b, focus) {
    b.focus = focus;
    stage.kick();
  },

  frame(stage, b, t) {
    const hov = b.hover;
    const active = hov ? hov.row : (b.focus && b.rows.find((row) => row.r.rule_id === b.focus.rule)) || null;
    const out = hov ? hov.row.r.rule_id : "";
    if (out !== b.emitted) {
      b.emitted = out;
      stage.emit?.(hov ? { rule: hov.row.r.rule_id } : null);
    }

    b.rows.forEach((row) => {
      const p = ease((t - 0.1 - row.k * 0.09) / 1.4);
      const cnt = Math.max(2, Math.ceil(p * b.H));
      row.line.geometry.setDrawRange(0, p > 0 ? cnt : 0);
      row.area.geometry.setDrawRange(0, Math.max(0, (cnt - 1) * 6));
      const on = active === row;
      const dim = active != null && !on ? 0.25 : 1;
      row.line.material.opacity = 0.95 * dim;
      row.area.material.opacity = (on ? 0.2 : row.fillOp) * p * dim;
      row.dot.material.opacity = p > 0.98 ? dim : 0;
      row.tag.classList.toggle("is-focus", on);
      const op = ease((t - 0.3 - row.k * 0.05) / 0.6) * (dim < 1 ? 0.4 : 1);
      stage.place(row.tag, X0 - 0.25, 0, row.z, op, -6, 0, -100, -50);   // pinned to the left edge rather than hidden
      stage.place(row.val, X1 + 0.2, 0, row.z, op, 6, 0, 0, -50, false);
    });
    b.ticks.forEach(({ i, tag }) => stage.place(tag, b.xOf(i), 0, b.zOf(b.n - 1) + 0.45, ease((t - 0.4) / 0.8), 0, 4, -50, 0, false));

    b.cross.visible = !!hov && t > 1.4;
    b.cursor.visible = b.cross.visible;
    if (b.cross.visible) {
      b.cross.position.x = b.xOf(hov.i);
      b.cursor.position.copy(hov.row.pts[hov.i]);
    }

    // card: the hovered rule at the hovered hour, or the focused rule's summary
    if (active && t > 1.4) {
      const r = active.r;
      const at = hov ? `<span class="k3d-tip-hour"><b>${fmt(active.hourly[hov.i])}</b> at ${esc(b.labels?.[hov.i] || "")}</span>` : "";
      const facts = [`${fmt(r.hits)} in 24h`, r.ips != null && `${fmt(r.ips)} IP${r.ips === 1 ? "" : "s"}`,
        r.services != null && `${esc(r.services)} service${r.services === 1 ? "" : "s"}`, r.blocked_pct != null && `${esc(r.blocked_pct)}% blocked`].filter(Boolean).join(" · ");
      const html = `<span class="k3d-tag-id">${esc(r.rule_id)}${r.top_service ? " · " + esc(r.top_service) : ""}</span>${at}<span class="k3d-tip-msg">${esc(r.message || "Unnamed detection")}</span><span class="k3d-tip-facts">${facts}</span>`;
      if (b.card._html !== html) { b.card.innerHTML = html; b.card._html = html; b.card._w = undefined; }
      const i = hov ? hov.i : active.hourly.indexOf(Math.max(...active.hourly));
      stage.place(b.card, b.xOf(i), active.pts[i].y + 0.15, active.z, 1, 0, -10, -50, -100);
    } else stage.place(b.card, 0, 0, 0, 0);
  },
};
