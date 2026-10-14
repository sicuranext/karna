/* Overview traffic scene: the last 24 hours as stacked ribbons on a tilted
 * floor, one row per series (inspected, blocked, block rate). A beacon marks
 * the peak blocking hour; hovering
 * the floor reads one hour across all rows. */
import { THREE, PAL, clamp, ease, esc } from "./kit.js";

const X0 = -5.2, X1 = 5.2, HMAX = 1.45, GAP = 1.15;
const fmt = (n) => Number(n).toLocaleString("en-US");


function rows(traffic) {
  return [
    { key: "requests", name: "inspected", values: traffic.map((d) => d.requests), unit: "/h", color: PAL.enc, fill: PAL.slate, fillOp: 0.06 },
    { key: "blocked", name: "blocked", values: traffic.map((d) => d.blocked), unit: "/h", color: PAL.hot, fill: PAL.hot, fillOp: 0.08, hot: true },
    { key: "rate", name: "block rate", values: traffic.map((d) => (d.requests ? (d.blocked / d.requests) * 100 : 0)), unit: "%", color: PAL.slate, fill: PAL.slate, fillOp: 0.03, dashed: true },
  ];
}

export const trafficScene = {
  build(stage, traffic) {
    const N = traffic.length;
    const series = rows(traffic);
    const xOf = (i) => X0 + ((X1 - X0) * i) / Math.max(N - 1, 1);
    const zOf = (k) => (k - (series.length - 1) / 2) * GAP;
    const b = { N, xOf, zOf, series, traffic, rows: [], stage: 0, hover: null };

    stage.floor(X1 - X0 + 1.2, series.length * GAP + 0.6);
    // grid: one line per row, one per 6 hours
    const grid = [];
    series.forEach((_, k) => grid.push(new THREE.Vector3(X0 - 0.2, 0, zOf(k)), new THREE.Vector3(X1 + 0.2, 0, zOf(k))));
    b.ticks = [];
    traffic.forEach((d, i) => {
      if (i % 6 === 0 || i === N - 1) {
        grid.push(new THREE.Vector3(xOf(i), 0, zOf(0) - 0.45), new THREE.Vector3(xOf(i), 0, zOf(series.length - 1) + 0.45));
        b.ticks.push({ i, tag: stage.label("k3d-axis", esc(d.label)) });
      }
    });
    stage.segments(grid, PAL.grid, 0.8);

    series.forEach((s, k) => {
      const z = zOf(k);
      const max = Math.max(...s.values, 1e-9) * 1.18;
      const pts = s.values.map((v, i) => new THREE.Vector3(xOf(i), (v / max) * HMAX, z));
      const row = { ...s, z, max, pts };
      row.line = stage.line(pts, s.color, s.hot ? 1 : 0.9, 4, s.dashed);
      const ap = [], ai = [];
      pts.forEach((p) => ap.push(p.x, 0, z, p.x, p.y, z));
      for (let i = 0; i < pts.length - 1; i++) { const a = i * 2; ai.push(a, a + 1, a + 2, a + 1, a + 3, a + 2); }
      const ag = new THREE.BufferGeometry();
      ag.setAttribute("position", new THREE.Float32BufferAttribute(ap, 3)); ag.setIndex(ai);
      row.area = new THREE.Mesh(ag, stage.fillMat(s.fill, 0));
      row.area.renderOrder = 2; row.area.frustumCulled = false; stage.root.add(row.area);
      const peakV = Math.max(...s.values);
      row.tag = stage.label("anno anno-row" + (s.hot ? " is-hot" : ""),
        `<span><b>${s.name}</b><small>max ${s.unit === "%" ? peakV.toFixed(2) + "%" : fmt(peakV) + s.unit}</small></span><i></i>`);
      b.rows.push(row);
    });

    // peak beacon on the blocked row
    const blk = b.rows[1];
    const pi = blk.values.indexOf(Math.max(...blk.values));
    const px = xOf(pi), py = blk.pts[pi].y, pz = blk.z;
    // no blocks in the window: no beacon, no card (an empty peak would read "0 blocked")
    b.peak = { i: pi, x: px, y: py, z: pz, none: blk.values[pi] <= 0 };
    b.mast = stage.segments([new THREE.Vector3(px, 0, pz), new THREE.Vector3(px, py + 0.55, pz)], PAL.hit, 0, 5);
    const circle = [];
    for (let a = 0; a <= 48; a++) circle.push(new THREE.Vector3(Math.cos((a / 48) * Math.PI * 2), 0, Math.sin((a / 48) * Math.PI * 2)));
    b.rings = [0, 1, 2].map(() => {
      const r = new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(circle), stage.mat(PAL.hit, 0));
      r.position.set(px, 0.002, pz); r.renderOrder = 5; r.frustumCulled = false; stage.root.add(r); return r;
    });
    b.peakTag = stage.label("k3d-tag",
      `<span class="k3d-tag-id">peak · ${esc(traffic[pi].label)}</span><b>${fmt(blk.values[pi])} blocked</b><small>${fmt(traffic[pi].requests)} inspected that hour</small>`);

    // hover: crosshair across the rows, one dot per row, a readout card
    b.cross = stage.segments([
      new THREE.Vector3(0, 0, zOf(0) - 0.5), new THREE.Vector3(0, 0, zOf(series.length - 1) + 0.5),
    ], PAL.hot, 0.8, 6);
    b.cross.visible = false;
    b.dots = b.rows.map((r) => {
      const d = new THREE.Mesh(new THREE.SphereGeometry(0.045, 12, 8), new THREE.MeshBasicMaterial({ color: r.hot ? PAL.hot : PAL.ink, depthTest: false, transparent: true }));
      d.renderOrder = 7; d.visible = false; stage.root.add(d); return d;
    });
    b.tip = stage.label("k3d-tip", "");

    stage.onPointer = (e) => {
      if (b.stage === 2) return;
      const hit = stage.floorHit(e);
      const inside = hit && hit.x >= X0 - 0.1 && hit.x <= X1 + 0.1 && Math.abs(hit.z) <= (series.length * GAP) / 2 + 0.4;
      b.hover = inside ? clamp(Math.round(((hit.x - X0) / (X1 - X0)) * (N - 1)), 0, N - 1) : null;
      stage.host.classList.toggle("is-reading", b.hover != null);
    };
    stage.onHover = (v) => { b.hover = v; stage.host.classList.remove("is-reading"); };
    return b;
  },

  frame(stage, b, t, now) {
    const { rows: R, N } = b;
    const focusBlocked = b.stage >= 1;
    R.forEach((row, k) => {
      const p = ease((t - 0.15 - k * 0.22) / 1.6);
      const n = Math.max(2, Math.ceil(p * N));
      row.line.geometry.setDrawRange(0, p > 0 ? n : 0);
      row.area.geometry.setDrawRange(0, Math.max(0, (n - 1) * 6));
      const dim = focusBlocked && !row.hot ? 0.28 : 1;
      row.line.material.opacity = (row.hot ? 1 : 0.9) * dim;
      row.area.material.opacity = row.fillOp * 1.6 * p * dim;
      stage.place(row.tag, b.xOf(0) - 0.25, 0, row.z, ease(t / 0.8) * (dim < 1 ? 0.45 : 1), -6, 0, -100, -50, false);
    });
    b.ticks.forEach(({ i, tag }) => stage.place(tag, b.xOf(i), 0, b.zOf(R.length - 1) + 0.55, ease((t - 0.4) / 0.8), 0, 4, -50, 0, false));

    // beacon: appears after the reveal, pulses
    const a = b.peak.none ? 0 : ease((t - 1.9) / 0.7);
    const pk = b.peak;
    b.mast.material.opacity = 0.9 * a;
    b.mast.scale.y = Math.max(a, 0.001);
    b.rings.forEach((r, j) => {
      const u = (now * 0.7 + j / 3) % 1;
      const sc = 0.1 + u * 0.5;
      r.scale.set(sc, 1, sc);
      r.material.opacity = (1 - u) * 0.75 * a;
    });
    stage.place(b.peakTag, pk.x, pk.y + 0.58, pk.z, a, 10, 0, 0, -50);

    // hover readout
    const h = b.hover;
    b.cross.visible = h != null && t > 1.8;
    b.dots.forEach((d, k) => {
      d.visible = b.cross.visible;
      if (d.visible) d.position.copy(R[k].pts[h]);
    });
    if (b.cross.visible) {
      b.cross.position.x = b.xOf(h);
      const d = b.traffic[h];
      const html = `<span class="k3d-tag-id">${esc(d.label)}</span><b>${fmt(d.requests)}</b> inspected<br><b>${fmt(d.blocked)}</b> blocked · ${R[2].values[h].toFixed(2)}%`;
      if (b.tip._html !== html) { b.tip.innerHTML = html; b.tip._html = html; b.tip._w = undefined; }
      stage.place(b.tip, b.xOf(h), R[0].pts[h].y + 0.15, R[0].z, 1, 0, -8, -50, -100);
    } else stage.place(b.tip, 0, 0, 0, 0);
  },

  setStage(stage, b, n) {
    b.stage = n;
    b.hover = null;
    if (n === 0) stage.setGoal({ tx: 0.2, ty: 0.35, R: 11, el: 34, az: -18 });
    if (n === 1) stage.setGoal({ tx: 0, ty: 0.45, R: 10.5, el: 24, az: -8 });
    if (n === 2 && !b.peak.none) stage.setGoal({ tx: b.peak.x * 0.8, ty: 0.5, R: 7, el: 26, az: -14 });
  },
};
