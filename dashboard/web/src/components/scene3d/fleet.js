/* Services fleet map: every protected service as a tower on a platform, in two
 * districts (blocking, detection) so the posture of the whole fleet reads at a
 * glance.
 *   height     requests in the last 24h (square-root scale)
 *   base band  the matched share of that traffic, at the foot of the tower:
 *              red where Karna blocked it (blocking services), amber where it
 *              was only seen (detection)
 *   edges      solid ink = blocking, dashed slate = detection
 *   floor ring detection services only, same rule as the table's readiness:
 *              blue = low match rate, ready to block; amber, pulsing = match
 *              rate > 4%, review the matches before blocking
 *   blue       hovered
 * Faces are shaded per side (vertex colours, no lights) and each tower casts a
 * soft floor shadow, so the volumes read without a lighting rig.
 * Hover shows an animated card; a click opens the service (stage.pick).
 * Labels are permanent only for small fleets (<= 4 services). */
import { THREE, PAL, clamp, ease, esc } from "./kit.js";

const STEP = 1.45, SIDE = 0.78, HMAX = 2.4, AMBER = "#c27c1e", TUNE = 4, LABEL_MAX = 4;
const COL = { block: "#e6eaef", detect: "#f5f7f9", hover: "#c9d6f7", dim: "#f7f8fa", blocked: "#d8402c", seen: "#e0a23e" };
const fmt = (n) => Number(n).toLocaleString("en-US");
const compact = (n) => (n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M" : n >= 1e4 ? Math.round(n / 1e3) + "k" : fmt(Math.round(n)));

// a unit box standing on y = 0, with per-face shading baked into vertex colours
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

function grid(count) {
  const cols = Math.max(1, Math.ceil(Math.sqrt(count * 1.4)));
  return { cols, rows: Math.max(1, Math.ceil(count / cols)) };
}

function cardHtml(s, tw) {
  const matched = s.reqs * (s.matchRate / 100);
  const readiness = s.blocking ? `<span class="fc-chip is-ok">enforcing</span>`
    : tw.tune ? `<span class="fc-chip is-tune">review before blocking</span>` : `<span class="fc-chip is-ready">ready to block</span>`;
  const pct = clamp(s.matchRate / 10, 0, 1) * 100;
  const feats = [s.crs && "CRS", s.mcp && "MCP", s.redis && "Redis", s.localRules > 0 && `${s.localRules} local rule${s.localRules === 1 ? "" : "s"}`].filter(Boolean);
  return `<div class="fc-card">
    <div class="fc-head">
      <div><b>${esc(s.name)}</b><span class="mono">${esc(s.host)}</span></div>
      <span class="fc-mode ${s.blocking ? "is-block" : ""}">${s.blocking ? "blocking" : "detection"}</span>
    </div>
    <div class="fc-grid">
      <div><span>requests 24h</span><b data-count="${esc(s.reqs)}" data-fmt="compact">0</b></div>
      <div><span>${s.blocking ? "blocked" : "would block"}</span><b data-count="${esc(matched)}" data-fmt="compact">0</b></div>
      <div><span>match rate</span><b data-count="${esc(s.matchRate)}" data-fmt="pct">0</b></div>
      <div><span>p95</span><b data-count="${esc(s.p95 || 0)}" data-fmt="ms">0</b></div>
      <div><span>paranoia</span><b>PL${esc(s.pl)}</b></div>
      <div><span>routes</span><b>${esc(s.routes)}</b></div>
    </div>
    <div class="fc-bar"><i class="${s.blocking ? "is-block" : tw.tune ? "is-tune" : ""}" style="--w:${pct.toFixed(1)}%"></i><span>0%</span><span>10%</span></div>
    <div class="fc-foot">${readiness}<span class="fc-feats">${feats.map(esc).join(" · ")}</span></div>
    <div class="fc-cta">click to ${s.writable ? "manage" : "view"} <span aria-hidden="true">→</span></div>
  </div>`;
}

export const fleetScene = {
  build(stage, { services }) {
    const b = { towers: [], hover: null, shownFor: null, shownAt: 0, labelled: new Set() };
    const districts = [
      { key: "blocking", title: "blocking", items: services.filter((s) => s.blocking) },
      { key: "detection", title: "detection", items: services.filter((s) => !s.blocking) },
    ].filter((d) => d.items.length);
    const maxReq = Math.max(1, ...services.map((s) => s.reqs));
    const hOf = (v) => Math.max((Math.sqrt(Math.max(v, 0)) / Math.sqrt(maxReq)) * HMAX, 0.06);

    const sizes = districts.map((d) => grid(d.items.length));
    const widths = sizes.map((g) => g.cols * STEP);
    const GAPX = 1.5;
    const total = widths.reduce((a, w) => a + w, 0) + GAPX * (districts.length - 1);
    let x0 = -total / 2;
    const depthMax = Math.max(...sizes.map((g) => g.rows * STEP));

    const body = shadedBox(SIDE, SIDE);
    const bodyEdges = new THREE.EdgesGeometry(body);
    const pad = shadedBox(SIDE + 0.32, SIDE + 0.32);
    const padEdges = new THREE.EdgesGeometry(pad);
    const shadowGeo = new THREE.PlaneGeometry(1, 1);
    shadowGeo.rotateX(-Math.PI / 2);
    // shadow texture: dark at the tower, fading out along +x
    const cv = document.createElement("canvas"); cv.width = 64; cv.height = 4;
    const cx2 = cv.getContext("2d"), gr = cx2.createLinearGradient(0, 0, 64, 0);
    gr.addColorStop(0, "rgba(23,26,30,1)"); gr.addColorStop(1, "rgba(23,26,30,0)");
    cx2.fillStyle = gr; cx2.fillRect(0, 0, 64, 4);
    const shadowTex = new THREE.CanvasTexture(cv);
    const circle = [];
    for (let a = 0; a <= 48; a++) circle.push(new THREE.Vector3(Math.cos((a / 48) * Math.PI * 2), 0, Math.sin((a / 48) * Math.PI * 2)));
    const ringGeo = new THREE.BufferGeometry().setFromPoints(circle);
    const solid = (color) => new THREE.MeshBasicMaterial({ color, vertexColors: true, polygonOffset: true, polygonOffsetFactor: 1, polygonOffsetUnits: 1 });

    b.districtTags = [];
    districts.forEach((d, di) => {
      const g = sizes[di], w = widths[di], depth = g.rows * STEP;
      const cx = x0 + w / 2;
      stage.floor(w + 0.4, depthMax + 0.6, cx, 0);
      b.districtTags.push({ tag: stage.label("k3d-district", `${esc(d.title)} <em>${esc(d.items.length)}</em>`), x: x0, z: depthMax / 2 + 0.3 });
      [...d.items].sort((p, q) => q.reqs - p.reqs).forEach((s, i) => {
        const col = i % g.cols, row = Math.floor(i / g.cols);
        const x = x0 + (col + 0.5) * STEP, z = -depth / 2 + (row + 0.5) * STEP;
        const tune = !s.blocking && s.matchRate > TUNE;
        const ready = !s.blocking && !tune;
        const padMesh = new THREE.Mesh(pad, solid("#f3f5f7"));
        padMesh.position.set(x, 0, z); padMesh.scale.y = 0.05; padMesh.renderOrder = 1; stage.root.add(padMesh);
        const padLine = new THREE.LineSegments(padEdges, stage.mat(PAL.grid, 0.9));
        padLine.material.depthTest = true; padLine.position.set(x, 0, z); padLine.scale.y = 0.05; stage.root.add(padLine);
        // soft shadow cast towards +x, longer for taller towers
        const shadow = new THREE.Mesh(shadowGeo, new THREE.MeshBasicMaterial({ map: shadowTex, transparent: true, opacity: 0.12, depthWrite: false, depthTest: false }));
        shadow.renderOrder = 1; stage.root.add(shadow);
        const mesh = new THREE.Mesh(body, solid(s.blocking ? COL.block : COL.detect));
        mesh.position.set(x, 0.05, z); mesh.renderOrder = 2; stage.root.add(mesh);
        const edge = new THREE.LineSegments(bodyEdges, stage.mat(s.blocking ? PAL.ink : PAL.slate, 0.9, !s.blocking));
        edge.material.depthTest = true; edge.position.set(x, 0.05, z); edge.renderOrder = 3; stage.root.add(edge);
        if (!s.blocking) edge.computeLineDistances();
        // matched share at the foot of the tower
        const band = new THREE.Mesh(body, solid(s.blocking ? COL.blocked : COL.seen));
        band.position.set(x, 0, z); band.renderOrder = 2; stage.root.add(band);
        const bandEdge = new THREE.LineSegments(bodyEdges, stage.mat(s.blocking ? "#9c2a1c" : "#a8661a", 0.9));
        bandEdge.material.depthTest = true; bandEdge.position.set(x, 0, z); bandEdge.renderOrder = 3; stage.root.add(bandEdge);
        const ring = new THREE.LineLoop(ringGeo, stage.mat(tune ? AMBER : PAL.hot, 0.8));
        ring.visible = tune || ready;
        ring.position.set(x, 0.006, z); ring.renderOrder = 4; stage.root.add(ring);
        const tag = stage.label("anno" + (tune ? " is-tune" : ""),
          `<i></i><span><b>${esc(s.name)}</b><small>PL${esc(s.pl)}${s.mcp ? " · MCP" : ""} · ${esc(s.matchRate)}%</small></span>`);
        const h = hOf(s.reqs);
        const share = s.matchRate > 0 ? clamp(s.matchRate / 100, 0.06, 0.6) : 0;   // thin but visible
        const tw = { s, x, z, h, share, mesh, edge, band, bandEdge, shadow, ring, r: 0.66, tag, tune, ready, i: b.towers.length };
        mesh.userData.tower = tw; band.userData.tower = tw;
        b.towers.push(tw);
      });
      x0 += w + GAPX;
    });

    if (b.towers.length <= LABEL_MAX) b.towers.forEach((tw) => b.labelled.add(tw));
    b.card = stage.label("k3d-tip k3d-fleet-card", "");

    const span = Math.max(total, depthMax * 1.6);
    stage.setGoal({ tx: 0, ty: 0.6, R: Math.max(8, span * 1.15), el: 32, az: -20 });
    if (!stage.camPlaced) { Object.assign(stage.cam, stage.goal); stage.camPlaced = true; }

    const pickAt = (e) => {
      const rc = stage.renderer.domElement.getBoundingClientRect();
      const ndc = new THREE.Vector2(((e.clientX - rc.left) / rc.width) * 2 - 1, -((e.clientY - rc.top) / rc.height) * 2 + 1);
      const ray = new THREE.Raycaster(); ray.setFromCamera(ndc, stage.camera);
      const hit = ray.intersectObjects(b.towers.flatMap((t) => [t.mesh, t.band]))[0];
      return hit ? hit.object.userData.tower : null;
    };
    stage.onPointer = (e) => {
      b.hover = pickAt(e);
      stage.host.classList.toggle("is-picking", !!b.hover);
    };
    stage.onHover = () => { b.hover = null; stage.host.classList.remove("is-picking"); };
    stage.onClickScene = (e) => { const tw = pickAt(e); if (tw) stage.pick?.(tw.s.id); };
    return b;
  },

  frame(stage, b, t, now) {
    const active = b.hover;
    b.towers.forEach((tw) => {
      const p = ease((t - 0.1 - tw.i * 0.03) / 1.1);
      const total = Math.max(tw.h * p, 0.001);
      const low = total * tw.share, rest = total - low;
      tw.band.visible = tw.bandEdge.visible = low > 0.002;
      tw.band.position.y = tw.bandEdge.position.y = 0.05;
      tw.band.scale.y = tw.bandEdge.scale.y = Math.max(low, 0.001);
      tw.mesh.position.y = tw.edge.position.y = 0.05 + low;
      tw.mesh.scale.y = Math.max(rest, 0.001); tw.edge.scale.y = tw.mesh.scale.y;
      const len = 0.25 + total * 0.6;
      tw.shadow.scale.set(len, 1, SIDE * 0.92);
      tw.shadow.position.set(tw.x + SIDE / 2 + len / 2 - 0.02, 0.06, tw.z - 0.04);
      const on = active === tw;
      const dim = active != null && !on;
      tw.mesh.material.color.set(on ? COL.hover : dim ? COL.dim : tw.s.blocking ? COL.block : COL.detect);
      tw.edge.material.color.set(on ? PAL.hot : tw.s.blocking ? PAL.ink : PAL.slate);
      tw.edge.material.opacity = dim ? 0.3 : 0.9;
      tw.band.material.transparent = dim; tw.band.material.opacity = dim ? 0.35 : 1;
      tw.bandEdge.material.opacity = dim ? 0.3 : 0.9;
      tw.shadow.material.opacity = 0.12 * p * (dim ? 0.5 : 1);
      const pulse = tw.tune && !stage.reduced ? 1 + ((now * 0.8 + tw.i * 0.13) % 1) * 0.35 : 1;
      tw.ring.scale.set(tw.r * pulse, 1, tw.r * pulse);
      tw.ring.material.opacity = (tw.tune ? 0.9 * (2 - pulse) * 0.75 : 0.6) * p * (dim ? 0.4 : 1);
      const show = b.labelled.has(tw) && !on;
      stage.place(tw.tag, tw.x - SIDE / 2, total + 0.12, tw.z - SIDE / 2, show ? ease((t - 0.6 - tw.i * 0.02) / 0.6) * (dim ? 0.35 : 1) : 0, 0, 0, 0, -100);
    });
    if (b.labelled.size) stage.declutter([...b.labelled].map((tw) => tw.tag), [stage.host.parentNode.querySelector(".k3d-telemetry")]);
    b.districtTags.forEach((d) => stage.place(d.tag, d.x, 0, d.z, ease((t - 0.3) / 0.6), 0, 6, 0, 0, false));

    // card: rebuilt (and re-animated) when the hovered tower changes
    const el = b.card;
    if (active && t > 0.8) {
      if (b.shownFor !== active) {
        b.shownFor = active; b.shownAt = now;
        el.innerHTML = cardHtml(active.s, active);
        el._w = undefined;
        el.classList.remove("is-in"); void el.offsetWidth; el.classList.add("is-in");
      }
      // numbers count up during the first 0.6 s
      const k = stage.reduced ? 1 : ease((now - b.shownAt) / 0.6);
      el.querySelectorAll("[data-count]").forEach((n) => {
        const v = Number(n.dataset.count) * k, f = n.dataset.fmt;
        n.textContent = f === "pct" ? v.toFixed(1) + "%" : f === "ms" ? v.toFixed(1) + " ms" : compact(v);
      });
      const right = stage.screenOf(active.x, 0, active.z)[0] < stage.vw * 0.62;
      stage.place(el, active.x + (right ? SIDE / 2 : -SIDE / 2), (active.mesh.position.y + active.mesh.scale.y) * 0.6, active.z, 1, right ? 18 : -18, 0, right ? 0 : -100, -50);
    } else {
      if (b.shownFor) { b.shownFor = null; el.classList.remove("is-in"); }
      stage.place(el, 0, 0, 0, 0);
    }
  },
};
