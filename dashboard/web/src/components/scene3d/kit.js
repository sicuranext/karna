/* Shared Three.js runtime for the console's 3D scenes: pale floor, thin edges,
 * mono labels with diamond markers projected from 3D, one blue "hot" accent.
 * Everything is bundled by Vite: no CDN. */
import * as THREE from "three";

export { THREE };

export const PAL = {
  bg: "#fbfcfd", fill: "#eaeff3", edge: "#7d8994", grid: "#d3d9df",
  enc: "#4f5a65", slate: "#5a6b7d", ink: "#171a1e", hot: "#315ee8", hit: "#d8402c",
};

export const clamp = (v, a = 0, b = 1) => Math.max(a, Math.min(b, v));
// Labels are HTML: every value interpolated into one goes through esc().
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
export const ease = (v) => { const t = clamp(v); return t * t * (3 - 2 * t); };

export function webglAvailable() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
  } catch {
    return false;
  }
}

/* A Stage owns renderer, camera orbit, the DOM label layer and the frame loop.
 * A scene plugs in with build(stage) once per data set and frame(stage, t, dt)
 * every frame; t is seconds since the last (re)build, so the reveal is a pure
 * function of time. */
export class Stage {
  constructor(host, labelHost, opts = {}) {
    this.host = host;
    this.labelHost = labelHost;
    this.reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    this.cam = { tx: 0, ty: 0.3, R: 12, el: 38, az: -22, ...opts.cam };
    this.goal = { ...this.cam };
    this.user = { az: 0, el: 0 };          // drag offset, eased back to 0 when released
    this.proj = new THREE.Vector3();
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(PAL.bg);
    this.camera = new THREE.PerspectiveCamera(36, 1, 0.1, 200);
    this.renderer = new THREE.WebGLRenderer({ antialias: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.outputColorSpace = THREE.SRGBColorSpace;
    host.appendChild(this.renderer.domElement);
    this.root = new THREE.Group();
    this.scene.add(this.root);
    this.t = 0;
    this.visible = true;
    this.dragging = null;

    this.ro = new ResizeObserver(() => this.resize());
    this.ro.observe(host);
    this.io = new IntersectionObserver(([e]) => { this.visible = e.isIntersecting; this.kick(); });
    this.io.observe(host);
    const el = this.renderer.domElement;
    el.addEventListener("pointerdown", (e) => this.onDown(e));
    el.addEventListener("pointermove", (e) => this.onMove(e));
    el.addEventListener("pointerup", (e) => this.onUp(e));
    el.addEventListener("pointercancel", (e) => this.onUp(e));
    el.addEventListener("pointerleave", () => { this.onHover?.(null); this.kick(); });
    this.resize();
    this.last = performance.now();
    this.raf = 0;
    this.kick();
  }

  // ---------- primitives
  mat(color, opacity, dashed = false) {
    const o = { color, transparent: true, opacity, depthWrite: false, depthTest: false };
    const m = dashed ? new THREE.LineDashedMaterial({ ...o, dashSize: 0.08, gapSize: 0.06 }) : new THREE.LineBasicMaterial(o);
    return m;
  }
  fillMat(color, opacity) {
    return new THREE.MeshBasicMaterial({ color, transparent: true, opacity, side: THREE.DoubleSide, depthWrite: false, depthTest: false });
  }
  line(points, color, opacity, order = 4, dashed = false) {
    const l = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), this.mat(color, opacity, dashed));
    if (dashed) l.computeLineDistances();
    l.renderOrder = order; l.frustumCulled = false; this.root.add(l); return l;
  }
  segments(points, color, opacity, order = 1, dashed = false) {
    const l = new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(points), this.mat(color, opacity, dashed));
    if (dashed) l.computeLineDistances();
    l.renderOrder = order; l.frustumCulled = false; this.root.add(l); return l;
  }
  floor(w, d, cx = 0, cz = 0) {
    const plane = new THREE.Mesh(new THREE.PlaneGeometry(w, d), this.fillMat(PAL.fill, 0.5));
    plane.rotation.x = -Math.PI / 2; plane.position.set(cx, 0, cz); plane.renderOrder = 0;
    this.root.add(plane);
    const hw = w / 2, hd = d / 2;
    const loop = new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(
      [[-hw, -hd], [hw, -hd], [hw, hd], [-hw, hd]].map(([a, b]) => new THREE.Vector3(cx + a, 0, cz + b))), this.mat(PAL.edge, 0.5));
    loop.renderOrder = 0; this.root.add(loop);
    return plane;
  }
  label(cls, html) {
    const e = document.createElement("span");
    e.className = cls; e.innerHTML = html || "";
    this.labelHost.appendChild(e);
    return e;
  }
  // project a 3D anchor to the label layer; ax/ay = anchor offset in % of the label box
  // clampIt=false hides a label whose anchor leaves the viewport instead of pinning it to the edge
  place(e, x, y, z, opacity, dx = 0, dy = 0, ax = -50, ay = -100, clampIt = true) {
    if (opacity < 0.01) { if (e.style.opacity !== "0") e.style.opacity = "0"; return; }
    this.proj.set(x, y, z).project(this.camera);
    const px = (this.proj.x * 0.5 + 0.5) * this.vw + dx, py = (-this.proj.y * 0.5 + 0.5) * this.vh + dy;
    if (e._w === undefined) { e._w = e.offsetWidth; e._h = e.offsetHeight; }
    let tx = px + (ax / 100) * e._w, ty = py + (ay / 100) * e._h;
    if (!clampIt && (tx < 0 || ty < 0 || tx + e._w > this.vw || ty + e._h > this.vh)) { e.style.opacity = "0"; return; }
    tx = clamp(tx, 6, this.vw - e._w - 6); ty = clamp(ty, 6, this.vh - e._h - 6);
    e.style.transform = `translate3d(${tx.toFixed(1)}px,${ty.toFixed(1)}px,0)`;
    e.style.opacity = opacity.toFixed(3);
    e._x = tx; e._y = ty;
  }
  // screen-space labels can collide: in the given order (most important
  // first), push each one up past the boxes already placed
  declutter(tags, obstacles = []) {
    const host = this.labelHost.getBoundingClientRect();
    const boxes = obstacles.filter(Boolean).map((el) => {
      const r = el.getBoundingClientRect();
      return { x: r.left - host.left, y: r.top - host.top, w: r.width, h: r.height };
    });
    tags.forEach((e) => {
      if (e.style.opacity === "0" || e._x === undefined) return;
      const x = e._x, w = e._w, h = e._h;
      let y = e._y;
      for (let guard = 0; guard < 14; guard++) {
        const hit = boxes.find((b) => x < b.x + b.w + 4 && x + w + 4 > b.x && y < b.y + b.h + 3 && y + h + 3 > b.y);
        if (!hit) break;
        y = hit.y - h - 4;
      }
      boxes.push({ x, y, w, h });
      e.style.transform = `translate3d(${x.toFixed(1)}px,${y.toFixed(1)}px,0)`;
    });
  }
  screenOf(x, y, z) {
    this.proj.set(x, y, z).project(this.camera);
    return [(this.proj.x * 0.5 + 0.5) * this.vw, (-this.proj.y * 0.5 + 0.5) * this.vh];
  }
  // ray from the pointer onto the floor plane (y = 0)
  floorHit(e) {
    const r = this.renderer.domElement.getBoundingClientRect();
    const ndc = new THREE.Vector2(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
    const ray = new THREE.Raycaster(); ray.setFromCamera(ndc, this.camera);
    const hit = new THREE.Vector3();
    return ray.ray.intersectPlane(new THREE.Plane(new THREE.Vector3(0, 1, 0), 0), hit) ? hit : null;
  }

  // ---------- scene lifecycle
  mount(scene, data) {
    const first = !this.sceneDef;
    this.clear();
    this.sceneDef = scene;
    this.built = scene.build(this, data);
    if (first) this.t = 0;                  // the reveal plays once; a data refresh redraws in place
    this.kick();
  }
  clear() {
    this.root.traverse((o) => { o.geometry?.dispose?.(); o.material?.dispose?.(); });
    this.root.clear();
    this.labelHost.replaceChildren();
    this.built = null;
  }
  setGoal(goal) { this.goal = { ...this.goal, ...goal }; this.kick(); }

  // ---------- input: drag to orbit, hover handled by the scene
  onDown(e) {
    this.dragging = { x: e.clientX, y: e.clientY, az: this.user.az, el: this.user.el };
    this.renderer.domElement.setPointerCapture?.(e.pointerId);
    this.host.classList.add("is-dragging");
  }
  onMove(e) {
    if (this.dragging) {
      this.user.az = clamp(this.dragging.az - (e.clientX - this.dragging.x) * 0.25, -60, 60);
      this.user.el = clamp(this.dragging.el + (e.clientY - this.dragging.y) * 0.18, -26, 34);
      this.onHover?.(null);
    } else if (this.onPointer) this.onPointer(e);
    this.kick();
  }
  onUp(e) {
    // a press that barely moved is a click, not a drag
    const d = this.dragging;
    if (d && e && Math.hypot(e.clientX - d.x, e.clientY - d.y) < 5) this.onClickScene?.(e);
    this.dragging = null;
    this.host.classList.remove("is-dragging");
    this.kick();
  }

  // ---------- frame loop: runs while visible, ~60fps during motion
  kick() {
    if (!this.raf && this.visible && !document.hidden) this.raf = requestAnimationFrame((n) => this.frame(n));
  }
  frame(now) {
    this.raf = 0;
    const dt = Math.min((now - this.last) / 1000, 0.1);
    this.last = now;
    this.t += this.reduced ? 99 : dt;
    const k = 1 - Math.exp(-dt * 3);
    for (const key of Object.keys(this.cam)) this.cam[key] += (this.goal[key] - this.cam[key]) * k;
    const c = this.cam;
    const sway = this.reduced ? 0 : Math.sin(now / 1000 * 0.25) * 0.8;
    const el = THREE.MathUtils.degToRad(clamp(c.el + this.user.el, 8, 80));
    const az = THREE.MathUtils.degToRad(c.az + this.user.az + sway);
    // closer on very wide, short viewports (the horizontal field grows with the aspect)
    const R = this.narrow ? c.R * 1.6 : c.R * clamp(2.2 / this.camera.aspect, 0.88, 1);
    this.camera.position.set(c.tx + R * Math.cos(el) * Math.sin(az), c.ty + R * Math.sin(el), R * Math.cos(el) * Math.cos(az));
    this.camera.lookAt(c.tx, c.ty, 0);
    this.camera.updateMatrixWorld();
    if (this.built) this.sceneDef.frame(this, this.built, this.t, now / 1000);
    this.renderer.render(this.scene, this.camera);
    if (!this.visible || document.hidden) return;
    if (this.reduced && !this.dragging && Object.keys(this.cam).every((key) => Math.abs(this.goal[key] - this.cam[key]) < 0.01)) return;
    this.kick();
  }
  resize() {
    const { width, height } = this.host.getBoundingClientRect();
    const w = Math.max(width, 1), h = Math.max(height, 1);
    this.narrow = w < 640;
    this.camera.aspect = w / h; this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h, false);
    this.labelHost.querySelectorAll("*").forEach((e) => { e._w = undefined; });
    this.vw = w; this.vh = h;
    this.kick();
  }
  dispose() {
    cancelAnimationFrame(this.raf);
    this.ro.disconnect(); this.io.disconnect();
    this.clear();
    this.renderer.dispose();
    this.renderer.domElement.remove();
  }
}
