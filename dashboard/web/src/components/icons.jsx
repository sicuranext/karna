/* Inline SVG icon set — single-path glyphs, stroked. */
const I = {
  grid:    "M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z",
  pulse:   "M3 12h4l2 6 4-14 2 8h6",
  shield:  "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  layers:  "M12 3 3 8l9 5 9-5zM3 13l9 5 9-5M3 17l9 5 9-5",
  toggle:  "M7 8h10a4 4 0 0 1 0 8H7a4 4 0 0 1 0-8z",
  cube:    "M21 7.5 12 3 3 7.5v9L12 21l9-4.5zM3 7.5 12 12m0 9V12m9-4.5L12 12",
  gear:    "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 13a7.9 7.9 0 0 0 0-2l2-1.5-2-3.5-2.4 1a7.9 7.9 0 0 0-1.7-1l-.4-2.5h-4l-.4 2.5a7.9 7.9 0 0 0-1.7 1l-2.4-1-2 3.5L4.6 11a7.9 7.9 0 0 0 0 2l-2 1.5 2 3.5 2.4-1a7.9 7.9 0 0 0 1.7 1l.4 2.5h4l.4-2.5a7.9 7.9 0 0 0 1.7-1l2.4 1 2-3.5z",
  key:     "M14 7a4 4 0 1 0-3.9 5l1.4 1.4 2 2 1.6-1.6-2-2L11.5 11A4 4 0 0 0 14 7z",
  search:  "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3",
  bell:    "M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0",
  chev:    "M9 6l6 6-6 6",
  chevd:   "M6 9l6 6 6-6",
  plus:    "M12 5v14M5 12h14",
  x:       "M18 6 6 18M6 6l12 12",
  arrowr:  "M5 12h14M13 6l6 6-6 6",
  up:      "M12 19V5M5 12l7-7 7 7",
  down:    "M12 5v14M5 12l7 7 7-7",
  dl:      "M12 3v12M7 10l5 5 5-5M5 21h14",
  copy:    "M9 9h11v11H9zM5 15H4V4h11v1",
  filter:  "M3 4h18l-7 8v6l-4 2v-8z",
  refresh: "M21 12a9 9 0 1 1-3-6.7M21 4v4h-4",
  dot:     "M12 12h.01",
  check:   "M5 12l5 5 9-12",
  ext:     "M14 4h6v6M20 4l-9 9M10 5H5v14h14v-5",
  doc:     "M6 2h8l4 4v16H6zM14 2v4h4",
  flame:   "M12 2s4 4 4 8a4 4 0 0 1-8 0c0-1 .5-2 1-3 0 2 1 3 2 3 0-3-1-5 1-8z",
  globe:   "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18",
  clock:   "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  history: "M3 12a9 9 0 1 0 3-6.7M3 4v5h5M12 7v5l4 2",
  server:  "M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01",
  route:   "M6 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM18 15a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM6 9v3a4 4 0 0 0 4 4h5",
  sun:     "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon:    "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  link:    "M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1",
  chat:    "M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4zM8 9h8M8 13h5",
};

export function Icon({ name, size = 18, stroke = 1.6, fill = false, style }) {
  const d = I[name] || I.dot;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24"
      fill={fill ? "currentColor" : "none"} stroke={fill ? "none" : "currentColor"}
      strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round"
      style={style} aria-hidden="true">
      {d.split("M").filter(Boolean).map((seg, i) => <path key={i} d={"M" + seg} />)}
    </svg>
  );
}
