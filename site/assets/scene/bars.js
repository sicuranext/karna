/* Benchmark bars in the Karna Console's 3D grammar: shaded boxes with thin
 * edges on a pale floor, mono labels projected from 3D, blue on hover.
 *
 * One scene, three uses:
 *   grouped   columns (scenarios) along x, one row per series along z
 *   row       a single row of bars along x (one scenario, four WAFs)
 * Options:
 *   series    [{ name, values[], fill, edge }]  (row layout: one value each)
 *   columns   column labels (grouped layout)
 *   unit      suffix in the readouts ("rps", "×")
 *   parity    draw a translucent plane at this value (ratio charts)
 *   colorOf   (value, series, col) => { fill, edge } overrides per bar
 *   values    show the value on top of every bar (small scenes) */
import { THREE, PAL, clamp, ease } from "./kit.js";

const fmt = (v, unit) => {
  const n = Number(v);
  const s = unit === "×" ? n.toFixed(2) : n >= 100 ? Math.round(n).toLocaleString("en-US") : n.toLocaleString("en-US", { maximumFractionDigits: 1 });
  return unit === "×" ? s + "×" : `${s} ${unit}`;
};
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

// a unit box standing on y = 0, per-face shading baked into vertex colours
function shadedBox(w, d) {
  const g = new THREE.BoxGeometry(w, 1, d);
  g.translate(0, 0.5, 0);
  const n = g.attributes.normal, c = [];
  for (let i = 0; i < n.count; i++) {
    const nx = n.getX(i), ny = n.getY(i);
    const k = ny > 0.5 ? 1 : ny < -0.5 ? 0.7 : Math.abs(nx) > 0.5 ? 0.84 : 0.93;
    c.push(k, k, k);
  }
  g.setAttribute("color", new THREE.Float32BufferAttribute(c, 3));
  return g;
}

export const barsScene = {
  build(stage, o) {
    const grouped = o.layout !== "row";
    const S = o.series;
    const nCols = grouped ? o.columns.length : S.length;
    const nRows = grouped ? S.length : 1;
    const STEPX = grouped ? 1.25 : 1.35, STEPZ = 1.0, W = grouped ? 0.5 : 0.62, HMAX = o.hmax || 2.6;
    const all = S.flatMap((s) => s.values);
    const max = Math.max(...all, o.parity || 0) * 1.08;
    const hOf = (v) => Math.max((v / max) * HMAX, 0.02);
    const xOf = (c) => (c - (nCols - 1) / 2) * STEPX;
    const zOf = (r) => (r - (nRows - 1) / 2) * STEPZ;
    const width = nCols * STEPX, depth = nRows * STEPZ;
    const b = { bars: [], hover: null, o, HMAX };

    stage.floor(width + 0.5, depth + 0.6);
    const grid = [];
    for (let r = 0; r < nRows; r++) grid.push(new THREE.Vector3(-width / 2, 0, zOf(r)), new THREE.Vector3(width / 2, 0, zOf(r)));
    for (let c = 0; c < nCols; c++) grid.push(new THREE.Vector3(xOf(c), 0, -depth / 2), new THREE.Vector3(xOf(c), 0, depth / 2));
    stage.segments(grid, PAL.grid, 0.7);

    const body = shadedBox(W, grouped ? 0.5 : 0.62);
    const edges = new THREE.EdgesGeometry(body);
    // transparent (at full opacity) so the bars join the floor in the
    // renderOrder-sorted pass instead of being drawn before it and covered
    const solid = (color) => new THREE.MeshBasicMaterial({ color, vertexColors: true, transparent: true, opacity: 1, depthWrite: true, polygonOffset: true, polygonOffsetFactor: 1, polygonOffsetUnits: 1 });

    S.forEach((s, si) => s.values.forEach((v, ci) => {
      const col = grouped ? ci : si, row = grouped ? si : 0;
      const x = xOf(col), z = zOf(row);
      const look = { fill: s.fill, edge: s.edge, ...(o.colorOf ? o.colorOf(v, s, ci) : null) };
      const mesh = new THREE.Mesh(body, solid(look.fill));
      mesh.position.set(x, 0, z); mesh.renderOrder = 2; stage.root.add(mesh);
      const edge = new THREE.LineSegments(edges, stage.mat(look.edge, 0.9));
      edge.material.depthTest = true; edge.position.set(x, 0, z); edge.renderOrder = 3; stage.root.add(edge);
      const bar = { s, v, ci, col, row, x, z, h: hOf(v), mesh, edge, look, delay: 0.15 + col * 0.07 + row * 0.05 };
      if (o.values) bar.tag = stage.label("k3d-value" + (s.karna ? " is-karna" : ""), esc(fmt(v, o.unit).replace(/ rps$/, "")));
      mesh.userData.bar = bar;
      b.bars.push(bar);
    }));

    // labels: series names along the left edge, columns along the front
    b.rowTags = grouped ? S.map((s, r) => ({ r, tag: stage.label("anno anno-row" + (s.karna ? " is-hot" : ""), `<span><b>${esc(s.name)}</b></span><i></i>`) })) : [];
    b.colTags = (grouped ? o.columns : S.map((s) => s.short || s.name)).map((name, c) => ({ c, tag: stage.label("k3d-axis" + (!grouped && S[c].karna ? " is-karna" : ""), esc(name)) }));

    if (o.parity) {
      const y = hOf(o.parity);
      const plane = new THREE.Mesh(new THREE.PlaneGeometry(width + 0.5, depth + 0.6), stage.fillMat(PAL.hot, 0.07));
      plane.material.depthTest = true;   // bars above parity hide the plane behind them
      plane.rotation.x = -Math.PI / 2; plane.position.y = y; plane.renderOrder = 5; stage.root.add(plane);
      const hw = (width + 0.5) / 2, hd = (depth + 0.6) / 2;
      b.parity = stage.line([[-hw, -hd], [hw, -hd], [hw, hd], [-hw, hd], [-hw, -hd]].map(([a, c]) => new THREE.Vector3(a, y, c)), PAL.hot, 0.55, 6, true);
      b.parityPlane = plane;
      b.parityY = y; b.parityX = hw; b.parityZ = hd;
      b.parityTag = stage.label("k3d-axis is-hot", `parity ${o.parity.toFixed(1)}×`);
    }

    b.tip = stage.label("k3d-tip", "");
    const ray = new THREE.Raycaster(), ndc = new THREE.Vector2();
    const meshes = b.bars.map((x) => x.mesh);
    stage.onPointer = (e) => {
      const r = stage.renderer.domElement.getBoundingClientRect();
      ndc.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
      ray.setFromCamera(ndc, stage.camera);
      const hit = ray.intersectObjects(meshes, false)[0];
      b.hover = hit ? hit.object.userData.bar : null;
      stage.host.classList.toggle("is-reading", !!b.hover);
    };
    stage.onHover = () => { b.hover = null; };

    const span = Math.max(width, depth * 1.8);
    stage.setGoal({ tx: 0, ty: grouped ? 0.9 : 0.85, R: o.R || span * (grouped ? 1.2 : 0.85), el: o.el || 34, az: o.az ?? -18 });
    Object.assign(stage.cam, stage.goal);
    return b;
  },

  frame(stage, b, t) {
    const o = b.o, grouped = o.layout !== "row";
    b.bars.forEach((x) => {
      const p = ease((t - x.delay) / 0.9);
      const h = Math.max(x.h * p, 0.001);
      x.mesh.scale.y = h; x.edge.scale.y = h;
      const hot = b.hover === x;
      x.mesh.material.color.set(hot ? "#c9d6f7" : x.look.fill);
      x.edge.material.color.set(hot ? PAL.hot : x.look.edge);
      if (x.tag) stage.place(x.tag, x.x, h + 0.08, x.z, ease((t - x.delay - 0.6) / 0.5), 0, -2, -50, -100);
    });
    const a = ease(t / 0.8);
    const front = (b.bars.reduce((m, x) => Math.max(m, x.z), 0)) + 0.55;
    b.rowTags.forEach(({ r, tag }) => {
      const z = b.bars.find((x) => x.row === r).z;
      stage.place(tag, -(b.bars.reduce((m, x) => Math.max(m, Math.abs(x.x)), 0)) - 0.6, 0, z, a, -4, 0, -100, -50);
    });
    b.colTags.forEach(({ c, tag }) => {
      const bar = b.bars.find((x) => x.col === c);
      stage.place(tag, bar.x, 0, front, ease((t - 0.3) / 0.8), 0, 4, -50, 0);
    });
    if (b.parityTag) {
      const pa = ease((t - 1.2) / 0.6);
      b.parity.material.opacity = 0.55 * pa; b.parityPlane.material.opacity = 0.07 * pa;
      stage.place(b.parityTag, -b.parityX, b.parityY, -b.parityZ, pa, -6, 0, -100, -50);
    }
    const h = b.hover;
    if (h && t > 1) {
      const html = `<span class="k3d-tag-id">${esc(grouped ? o.columns[h.ci] : "")}</span><b>${esc(h.s.name)}</b> ${esc(fmt(h.v, o.unit))}`;
      if (b.tip._html !== html) { b.tip.innerHTML = html; b.tip._html = html; b.tip._w = undefined; }
      stage.place(b.tip, h.x, h.h + 0.15, h.z, 1, 0, -8, -50, -100);
    } else stage.place(b.tip, 0, 0, 0, 0);
  },
};
