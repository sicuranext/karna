/* Benchmark "lead" scene: how much more throughput Karna has, per scenario,
 * against every other WAF at once.
 *   groups    one per scenario, four towers side by side: Karna, then each
 *             other WAF
 *   Karna     the dark tower, always the same height: the scenario's
 *             reference (100%)
 *   others    grey towers in proportion (other rps / Karna rps)
 *   lead      a dashed blue ghost from each grey tower up to Karna's level
 *   trailing  where another WAF is faster, its part above Karna's level is red
 * Under each group, the scenario and Karna's lead over each WAF (+24% / −7%).
 * Hover a tower to read its requests per second. */
import { THREE, PAL, ease } from "./kit.js";

const H = 2.0, STEPX = 1.7, TW = 0.36, W = 0.3;
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const rps = (v) => (v >= 100 ? Math.round(v).toLocaleString("en-US") : v.toLocaleString("en-US", { maximumFractionDigits: 1 })) + " rps";

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

export const leadScene = {
  build(stage, d) {
    const n = d.columns.length, per = 1 + d.others.length;
    const xOf = (c) => (c - (n - 1) / 2) * STEPX;
    const width = n * STEPX;
    const b = { d, towers: [], hover: null, xOf };

    stage.floor(width + 0.2, 1.2);
    const grid = [];
    for (let c = 0; c <= n; c++) grid.push(new THREE.Vector3(xOf(c) - STEPX / 2, 0, -0.5), new THREE.Vector3(xOf(c) - STEPX / 2, 0, 0.5));
    stage.segments(grid, PAL.grid, 0.6);

    const box = shadedBox(W, W), edges = new THREE.EdgesGeometry(box);
    const mat = (color, opacity = 1) => new THREE.MeshBasicMaterial({ color, vertexColors: true, transparent: true, opacity, depthWrite: opacity >= 1, polygonOffset: true, polygonOffsetFactor: 1, polygonOffsetUnits: 1 });
    const add = (o, order) => { o.renderOrder = order; o.frustumCulled = false; stage.root.add(o); return o; };
    const lines = (color, opacity, dashed) => {
      const l = new THREE.LineSegments(edges, stage.mat(color, opacity, dashed));
      l.material.depthTest = true;
      if (dashed) l.computeLineDistances();
      return l;
    };
    const piece = (x, y, h, fill, edge, opacity, dashed, order) => {
      const m = add(new THREE.Mesh(box, mat(fill, opacity)), order), e = add(lines(edge, 0.9, dashed), order + 1);
      m.position.set(x, y, 0); e.position.set(x, y, 0);
      m.scale.y = e.scale.y = Math.max(h, 0.001);
      return { m, e };
    };

    b.groupTags = [];
    d.columns.forEach((name, c) => {
      const k = d.karna[c], gx = xOf(c), x0 = gx - ((per - 1) / 2) * TW;
      const kt = { c, x: x0, h: H, who: "Karna", v: k, karna: true, fill: "#3b4148", delay: 0.15 + c * 0.06 };
      Object.assign(kt, piece(kt.x, 0, H, "#3b4148", PAL.ink, 1, false, 2));
      kt.m.userData.t = kt;
      b.towers.push(kt);
      const lines_ = [];
      d.others.forEach((o, i) => {
        const v = o.values[c], h = (v / k) * H, x = x0 + (i + 1) * TW;
        const t = { c, x, h, who: o.name, v, fill: o.fill, delay: 0.25 + c * 0.06 + i * 0.05 };
        Object.assign(t, piece(x, 0, Math.min(h, H), o.fill, o.edge, 1, false, 2));
        if (h < H) t.ghost = piece(x, h, H - h, PAL.hot, PAL.hot, 0.1, true, 4);
        else t.over = piece(x, H, h - H, "#f4c4b8", PAL.hit, 1, false, 2);
        t.m.userData.t = t;
        b.towers.push(t);
        const pct = Math.round((k / v - 1) * 100);
        lines_.push(`<span class="${pct < 0 ? "is-behind" : ""}"><em>${esc(o.short)}</em> ${pct < 0 ? "−" : "+"}${Math.abs(pct)}%</span>`);
      });
      b.groupTags.push({ x: gx, tag: stage.label("k3d-group", `<b>${esc(name)}</b>${lines_.join("")}`) });
    });

    // Karna's level across the whole row
    b.level = stage.line([new THREE.Vector3(-width / 2, H, 0), new THREE.Vector3(width / 2, H, 0)], PAL.ink, 0.22, 1, true);
    b.levelTag = stage.label("k3d-axis is-karna", "Karna = 100%");

    b.tip = stage.label("k3d-tip", "");
    const ray = new THREE.Raycaster(), ndc = new THREE.Vector2();
    const meshes = b.towers.map((t) => t.m);
    stage.onPointer = (e) => {
      const r = stage.renderer.domElement.getBoundingClientRect();
      ndc.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
      ray.setFromCamera(ndc, stage.camera);
      const hit = ray.intersectObjects(meshes, false)[0];
      b.hover = hit ? hit.object.userData.t : null;
      stage.host.classList.toggle("is-reading", !!b.hover);
    };
    stage.onHover = () => { b.hover = null; };

    // the kit pulls the camera back 1.6x on narrow screens; this row needs it closer
    stage.setGoal({ tx: 0, ty: 0.55, R: width * (stage.narrow ? 0.98 : 0.86), el: 12, az: -8 });
    Object.assign(stage.cam, stage.goal);
    return b;
  },

  frame(stage, b, t) {
    b.towers.forEach((x) => {
      const g = ease((t - x.delay) / 0.9);
      const solid = Math.min(x.h, H) * g;
      x.m.scale.y = x.e.scale.y = Math.max(solid, 0.001);
      if (x.ghost) {
        x.ghost.m.position.y = x.ghost.e.position.y = solid;
        x.ghost.m.scale.y = x.ghost.e.scale.y = Math.max(H * g - solid, 0.001);
      }
      if (x.over) {
        x.over.m.position.y = x.over.e.position.y = H * g;
        x.over.m.scale.y = x.over.e.scale.y = Math.max((x.h - H) * g, 0.001);
      }
      x.m.material.color.set(b.hover === x ? "#c9d6f7" : x.fill);
    });
    b.groupTags.forEach(({ x, tag }, c) => stage.place(tag, x, 0, 0.55, ease((t - 0.9 - c * 0.06) / 0.6), 0, 6, -50, 0));
    b.level.material.opacity = 0.22 * ease((t - 1.1) / 0.5);
    stage.place(b.levelTag, b.xOf(b.d.columns.length - 1) + STEPX / 2, H, 0, ease((t - 1.1) / 0.5), 6, 0, 0, -50);

    const h = b.hover;
    if (h && t > 1) {
      const html = `<span class="k3d-tag-id">${esc(b.d.columns[h.c])}</span><b>${esc(h.who)}</b> ${rps(h.v)}`;
      if (b.tip._html !== html) { b.tip.innerHTML = html; b.tip._html = html; b.tip._w = undefined; }
      stage.place(b.tip, h.x, Math.max(h.h, H) + 0.3, 0, 1, 0, -8, -50, -100);
    } else stage.place(b.tip, 0, 0, 0, 0);
  },
};
