/** A small area chart for live metrics. Values are drawn left (oldest) to right. */
export function AreaChart({
  values,
  max,
  color = "var(--hos-accent)",
  height = 64,
  label,
  secondary,
  secondaryColor = "var(--hos-violet)",
}: {
  values: number[];
  max?: number;
  color?: string;
  height?: number;
  label: string;
  secondary?: number[];
  secondaryColor?: string;
}) {
  const w = 300;
  const all = [...values, ...(secondary ?? [])];
  const top = max ?? Math.max(1, ...all) * 1.15;
  const path = (vals: number[]) => {
    if (vals.length < 2) return "";
    const step = w / (vals.length - 1);
    const pts = vals.map((v, i) => `${(i * step).toFixed(1)},${(height - (Math.min(v, top) / top) * height).toFixed(1)}`);
    return `M${pts.join(" L")}`;
  };
  const line = path(values);
  const line2 = secondary ? path(secondary) : "";
  return (
    <svg className="area-chart" viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" role="img" aria-label={label} style={{ height }}>
      <line x1="0" x2={w} y1={height - 0.5} y2={height - 0.5} stroke="var(--hos-glass-border)" />
      {line && (
        <>
          <path d={`${line} L${w},${height} L0,${height} Z`} fill={color} fillOpacity="0.16" />
          <path d={line} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
        </>
      )}
      {line2 && <path d={line2} fill="none" stroke={secondaryColor} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />}
    </svg>
  );
}

/** Bars like the reference stat cards: the last N values as columns. */
export function BarSpark({ values, max = 100, label }: { values: number[]; max?: number; label: string }) {
  const last = values.slice(-24);
  return (
    <div className="bar-spark" role="img" aria-label={label}>
      {last.map((v, i) => (
        <span key={i} style={{ height: `${Math.max(4, (Math.min(v, max) / max) * 100)}%` }} />
      ))}
    </div>
  );
}
