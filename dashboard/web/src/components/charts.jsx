/* Hand-drawn SVG charts — no chart library. */

function smoothPath(pts) {
  if (pts.length < 2) return "";
  let d = `M ${pts[0][0]} ${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const [x0, y0] = pts[i];
    const [x1, y1] = pts[i + 1];
    const cx = (x0 + x1) / 2;
    d += ` C ${cx} ${y0} ${cx} ${y1} ${x1} ${y1}`;
  }
  return d;
}

export function Sparkline({ data, w = 92, h = 28, color = "var(--accent)", fillOpacity }) {
  const max = Math.max(...data), min = Math.min(...data);
  const rng = max - min || 1;
  const pts = data.map((v, i) => [
    (i / Math.max(data.length - 1, 1)) * w,
    h - 3 - ((v - min) / rng) * (h - 6),
  ]);
  const line = smoothPath(pts);
  const area = `${line} L ${w} ${h} L 0 ${h} Z`;
  const fo = fillOpacity != null ? fillOpacity : 0.16;
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ display: "block" }}>
      <path d={area} fill={color} opacity={`calc(${fo} * var(--chart-fill))`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.6" />
    </svg>
  );
}

export function AreaChart({ data, height = 248, yKey = "requests", y2Key = "blocked",
                            c1 = "var(--chart-a)", c2 = "var(--chart-b)", labelEvery = 3 }) {
  const W = 920, H = height, padL = 4, padR = 4, padB = 26, padT = 12;
  const iw = W - padL - padR, ih = H - padB - padT;
  // empty windows (all zeros) or a single point would divide 0 by 0 and draw NaN paths
  const max1 = Math.max(1, ...data.map(d => d[yKey] || 0));
  const max2 = Math.max(1, ...data.map(d => d[y2Key] || 0));
  const x = i => padL + (i / Math.max(data.length - 1, 1)) * iw;
  const y1 = v => padT + ih - (v / max1) * ih;
  const y2 = v => padT + ih - (v / max2) * (ih * 0.62);

  const pts1 = data.map((d, i) => [x(i), y1(d[yKey])]);
  const pts2 = data.map((d, i) => [x(i), y2(d[y2Key])]);
  const line1 = smoothPath(pts1);
  const line2 = smoothPath(pts2);
  const area1 = `${line1} L ${x(data.length - 1)} ${padT + ih} L ${x(0)} ${padT + ih} Z`;
  const area2 = `${line2} L ${x(data.length - 1)} ${padT + ih} L ${x(0)} ${padT + ih} Z`;
  const gid = "ag-" + yKey;

  const grids = [0, 0.25, 0.5, 0.75, 1];
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ display: "block" }}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={c1} stopOpacity="0.26" />
          <stop offset="100%" stopColor={c1} stopOpacity="0.01" />
        </linearGradient>
      </defs>
      {grids.map((g, i) => (
        <line key={i} x1={padL} x2={W - padR} y1={padT + g * ih} y2={padT + g * ih}
          stroke="var(--border-1)" strokeWidth="1" />
      ))}
      <path d={area1} fill={`url(#${gid})`} opacity="var(--chart-fill)" />
      <path d={area2} fill={c2} opacity={`calc(0.10 * var(--chart-fill))`} />
      <path d={line1} fill="none" stroke={c1} strokeWidth="2" />
      <path d={line2} fill="none" stroke={c2} strokeWidth="1.8" strokeDasharray="0" />
      {data.map((d, i) => i % labelEvery === 0 && (
        <text key={i} x={x(i)} y={H - 8} fill="var(--fg-4)" fontSize="11"
          fontFamily="var(--font-mono)" textAnchor={i === 0 ? "start" : "middle"}>{d.label}</text>
      ))}
    </svg>
  );
}

export function BarRows({ items, max, valueFmt = v => v.toLocaleString() }) {
  const m = max || Math.max(...items.map(i => i.count));
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "13px" }}>
      {items.map(it => (
        <div key={it.id || it.name} className="barrow">
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px", gap: "10px" }}>
            <span style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13px", minWidth: 0 }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: it.color || "var(--accent)", flex: "0 0 auto" }} />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{it.name}</span>
              {it.via && <span className="mono" style={{ fontSize: 10.5, color: "var(--fg-4)" }}>{it.via}</span>}
            </span>
            <span className="mono tnum" style={{ fontSize: 12.5, color: "var(--fg-2)", flex: "0 0 auto" }}>{valueFmt(it.count)}</span>
          </div>
          <div className="meter">
            <span style={{ width: `${(it.count / m) * 100}%`, background: it.color || "var(--accent)", opacity: `calc(0.45 + 0.55*var(--chart-fill))` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function VBars({ data, yKey = "blocked", height = 120, color = "var(--chart-b)" }) {
  const max = Math.max(...data.map(d => d[yKey])) || 1;
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: "3px", height }}>
      {data.map((d, i) => (
        <div key={i} title={`${d.label} · ${d[yKey]}`} style={{
          flex: 1, height: `${Math.max(3, (d[yKey] / max) * 100)}%`,
          background: color, opacity: `calc(0.32 + 0.5*var(--chart-fill))`,
          borderRadius: "2px 2px 0 0",
        }} />
      ))}
    </div>
  );
}

export function Donut({ value, size = 132, stroke = 14, color = "var(--accent)", track = "var(--inset)", label, sub }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const off = c * (1 - value / 100);
  return (
    <div style={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={track} strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke}
          strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round" />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", textAlign: "center" }}>
        <div>
          <div className="tnum" style={{ fontSize: 24, fontWeight: 600, letterSpacing: "-0.02em" }}>{label}</div>
          {sub && <div className="mono" style={{ fontSize: 10, color: "var(--fg-3)", textTransform: "uppercase", letterSpacing: "0.08em", marginTop: 2 }}>{sub}</div>}
        </div>
      </div>
    </div>
  );
}
