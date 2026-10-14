import React from "react";

/* React host for a scene3d scene. Three.js and the scene module load lazily
 * (own chunk), so views without 3D never pay for it. Overlay chrome (status
 * card, telemetry, hints) is passed as children and sits above the canvas.
 * Without WebGL the `fallback` (a 2D chart) renders instead. */
export function Scene3D({ load, data, stageIndex = 0, replay = 0, focus = null, onHover, onPick, fallback = null, children }) {
  const canvasRef = React.useRef(null);
  const labelRef = React.useRef(null);
  const ref = React.useRef({ stage: null, scene: null });
  const [failed, setFailed] = React.useState(false);
  const [ready, setReady] = React.useState(0);
  const onHoverRef = React.useRef(onHover);
  onHoverRef.current = onHover;
  const onPickRef = React.useRef(onPick);
  onPickRef.current = onPick;

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const kit = await import("./scene3d/kit.js");
        if (!kit.webglAvailable()) throw new Error("no webgl");
        const scene = await load();
        if (cancelled) return;
        const stage = new kit.Stage(canvasRef.current, labelRef.current);
        stage.emit = (v) => onHoverRef.current?.(v);   // scene -> React (shared hover)
        stage.pick = (v) => onPickRef.current?.(v);    // scene -> React (click on an object)
        ref.current = { stage, scene };
      } catch (e) {
        console.warn("3D view unavailable", e);
        if (!cancelled) setFailed(true);
        return;
      }
      if (!cancelled) setReady((n) => n + 1);
    })();
    return () => {
      cancelled = true;
      ref.current.stage?.dispose();
      ref.current = { stage: null, scene: null };
    };
  }, [load]);

  const key = React.useMemo(() => JSON.stringify(data), [data]);

  React.useEffect(() => {
    const { stage, scene } = ref.current;
    if (stage && scene) {
      stage.mount(scene, data);
      if (scene.setStage) scene.setStage(stage, stage.built, stageIndex);
    }
    // stageIndex is applied by the next effect; data identity is tracked by key
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, key]);

  React.useEffect(() => {
    const { stage, scene } = ref.current;
    if (stage?.built && scene?.setStage) scene.setStage(stage, stage.built, stageIndex);
  }, [stageIndex, ready]);

  const focusKey = JSON.stringify(focus);
  React.useEffect(() => {
    const { stage, scene } = ref.current;
    if (stage?.built && scene?.setFocus) scene.setFocus(stage, stage.built, focus);
    // focus identity is tracked by focusKey
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusKey, ready, key]);

  React.useEffect(() => {
    const { stage } = ref.current;
    if (stage && replay) { stage.t = 0; stage.user = { az: 0, el: 0 }; stage.kick(); }
  }, [replay]);

  if (failed) return fallback;
  return (
    <div className="k3d-viewport">
      <div className="k3d-canvas" ref={canvasRef} aria-hidden="true" />
      <div className="k3d-labels" ref={labelRef} aria-hidden="true" />
      <div className="k3d-frame" aria-hidden="true"><i className="tl" /><i className="tr" /><i className="bl" /><i className="br" /></div>
      {children}
    </div>
  );
}
