import { type KeyboardEvent, type PointerEvent, useEffect, useMemo, useRef, useState } from "react";
import { bytes, duration } from "../format";

/** Categorical colors for several series, in this order and never cycled
 * (checked for colour-blind separation and contrast on the window surface).
 * A single series uses the accent. */
export const SERIES_COLORS = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];

export interface ChartSeries {
  key: string;
  label: string;
  values: (number | null)[];
}

/** Formats a value of a unit for axes and tooltips. */
export function formatUnit(v: number, unit: string, short = false): string {
  switch (unit) {
    case "percent":
      return `${v >= 10 || short ? Math.round(v) : v.toFixed(1)}%`;
    case "bytes":
      return bytes(v, short ? 0 : 1);
    case "bytes/s":
      return `${bytes(v, short ? 0 : 1)}/s`;
    case "celsius":
      return `${Math.round(v)} °C`;
    case "seconds":
      return duration(v);
    case "volts":
      return `${Math.round(v)} V`;
    case "watts":
      return `${Math.round(v)} W`;
    default:
      return Math.abs(v) >= 1000 ? `${(v / 1000).toFixed(1)}K` : v.toFixed(v < 10 ? 2 : 0);
  }
}

/** Keeps the largest series and sums the rest into "Other" (at most
 * SERIES_COLORS.length lines). */
export function foldSeries(series: ChartSeries[], max = SERIES_COLORS.length): ChartSeries[] {
  if (series.length <= max) return series;
  const avg = (s: ChartSeries) => s.values.reduce<number>((a, v) => a + (v ?? 0), 0) / Math.max(1, s.values.length);
  const sorted = [...series].sort((a, b) => avg(b) - avg(a));
  const keep = sorted.slice(0, max - 1);
  const rest = sorted.slice(max - 1);
  const n = Math.max(...rest.map((s) => s.values.length));
  const other: (number | null)[] = Array.from({ length: n }, (_, i) => {
    let sum = 0;
    let any = false;
    for (const s of rest) {
      const v = s.values[i];
      if (v != null) {
        sum += v;
        any = true;
      }
    }
    return any ? sum : null;
  });
  // Keep the original order of what's kept so colors follow the entity.
  return [...series.filter((s) => keep.includes(s)), { key: "__other", label: `Other (${rest.length})`, values: other }];
}

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function niceBytesMax(v: number): number {
  if (v <= 0) return 1024;
  const p = 1024 ** Math.floor(Math.log(v) / Math.log(1024));
  return niceMax(v / p) * p;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const dayFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });
const fullFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

/** A time-series line chart: hairline grid, 2px lines with gaps where
 * there's no data, a crosshair with every series' value at that moment,
 * a legend for two or more series and a table view. */
export function TimeChart({
  from,
  step,
  series,
  unit,
  max,
  height = 150,
  label,
}: {
  from: string; // ISO time of the first value
  step: number; // seconds between values
  series: ChartSeries[];
  unit: string;
  max?: number;
  height?: number;
  label: string;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  useEffect(() => {
    const el = wrap.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((e) => setWidth(Math.max(200, Math.floor(e[0]?.contentRect.width ?? 600))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const n = Math.max(0, ...series.map((s) => s.values.length));
  const start = new Date(from).getTime();
  const span = n * step * 1000;
  const top = useMemo(() => {
    if (max != null) return max;
    let m = 0;
    for (const s of series) for (const v of s.values) if (v != null && v > m) m = v;
    return unit === "bytes" || unit === "bytes/s" ? niceBytesMax(m * 1.08) : niceMax(m * 1.08);
  }, [series, max, unit]);

  const padL = 64;
  const padR = 12;
  const padT = 8;
  const padB = 22;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;
  const x = (i: number) => padL + (n <= 1 ? 0 : (i / (n - 1)) * plotW);
  const y = (v: number) => padT + plotH - (Math.min(v, top) / top) * plotH;
  const single = series.length === 1;
  const color = (i: number) => (single ? "var(--hos-accent)" : SERIES_COLORS[i % SERIES_COLORS.length]);

  const paths = series.map((s) => {
    let d = "";
    let pen = false;
    s.values.forEach((v, i) => {
      if (v == null) {
        pen = false;
        return;
      }
      d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
      pen = true;
    });
    return d;
  });
  const vals0 = series[0]?.values ?? [];
  // Area wash for one series: each run of values closes to the baseline.
  const area = single
    ? (() => {
        let d = "";
        let run: number[] = [];
        const flush = () => {
          const first = run[0];
          const last = run[run.length - 1];
          if (run.length > 1 && first != null && last != null) {
            d += `M${x(first).toFixed(1)},${(padT + plotH).toFixed(1)}`;
            for (const i of run) d += `L${x(i).toFixed(1)},${y(vals0[i] ?? 0).toFixed(1)}`;
            d += `L${x(last).toFixed(1)},${(padT + plotH).toFixed(1)}Z`;
          }
          run = [];
        };
        vals0.forEach((v, i) => (v == null ? flush() : run.push(i)));
        flush();
        return d;
      })()
    : "";

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * top);
  const xTickCount = Math.max(2, Math.min(6, Math.floor(plotW / 110)));
  const xTicks = Array.from({ length: xTickCount }, (_, k) => Math.round((k / (xTickCount - 1)) * (n - 1)));
  const tfmt = span > 2 * 86400_000 ? dayFmt : timeFmt;
  const at = (i: number) => new Date(start + i * step * 1000);

  const pick = (e: PointerEvent<SVGRectElement>) => {
    const r = (e.currentTarget as SVGRectElement).getBoundingClientRect();
    const f = (e.clientX - r.left) / r.width;
    setHover(Math.max(0, Math.min(n - 1, Math.round(f * (n - 1)))));
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowLeft") setHover((h) => Math.max(0, (h ?? n) - 1));
    else if (e.key === "ArrowRight") setHover((h) => Math.min(n - 1, (h ?? -1) + 1));
    else if (e.key === "Escape") setHover(null);
  };
  const empty = n === 0 || series.every((s) => s.values.every((v) => v == null));

  return (
    <div className="tchart" ref={wrap}>
      {empty ? (
        <div className="tchart__empty" style={{ height }}>
          No data for this range yet.
        </div>
      ) : (
        <div className="tchart__plot" tabIndex={0} role="img" aria-label={label} onKeyDown={onKey} onBlur={() => setHover(null)}>
          <svg width={width} height={height} aria-hidden="true">
            {yTicks.map((t, i) => (
              <g key={i}>
                <line x1={padL} x2={width - padR} y1={y(t)} y2={y(t)} className="tchart__grid" />
                <text x={padL - 8} y={y(t) + 4} className="tchart__tick" textAnchor="end">
                  {formatUnit(t, unit, true)}
                </text>
              </g>
            ))}
            {xTicks.map((i, k) => (
              <text key={k} x={x(i)} y={height - 6} className="tchart__tick" textAnchor={k === 0 ? "start" : k === xTicks.length - 1 ? "end" : "middle"}>
                {tfmt.format(at(i))}
              </text>
            ))}
            {area && <path d={area} fill="var(--hos-accent)" fillOpacity={0.1} />}
            {paths.map((d, i) => (
              <path key={series[i]?.key ?? i} d={d} fill="none" stroke={color(i)} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
            ))}
            {hover != null && (
              <>
                <line x1={x(hover)} x2={x(hover)} y1={padT} y2={padT + plotH} className="tchart__cross" />
                {series.map((s, i) =>
                  s.values[hover] != null ? (
                    <circle key={s.key} cx={x(hover)} cy={y(s.values[hover] ?? 0)} r={4} fill={color(i)} stroke="var(--hos-chart-surface)" strokeWidth={2} />
                  ) : null,
                )}
              </>
            )}
            <rect x={padL} y={padT} width={Math.max(1, plotW)} height={plotH} fill="transparent" onPointerMove={pick} onPointerLeave={() => setHover(null)} />
          </svg>
          {hover != null && (
            <div className="tchart__tip glass" style={{ left: Math.min(x(hover) + 12, width - 200), top: padT }}>
              <div className="tchart__tip-time">{fullFmt.format(at(hover))}</div>
              {series.map((s, i) => (
                <div key={s.key} className="tchart__tip-row">
                  <span className="tchart__key" style={{ background: color(i) }} />
                  <strong className="mono">{s.values[hover] == null ? "–" : formatUnit(s.values[hover] ?? 0, unit)}</strong>
                  <span>{s.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      <div className="tchart__foot">
        {series.length > 1 && (
          <div className="legend">
            {series.map((s, i) => (
              <span key={s.key}>
                <span className="tchart__key" style={{ background: color(i) }} /> {s.label}
              </span>
            ))}
          </div>
        )}
        {!empty && (
          <button type="button" className="tchart__table-btn" onClick={() => setTable(!table)} aria-expanded={table}>
            {table ? "Hide table" : "Table"}
          </button>
        )}
      </div>
      {table && !empty && (
        <div className="table-wrap tchart__table">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                {series.map((s) => (
                  <th key={s.key} className="num">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Array.from({ length: n }, (_, i) => n - 1 - i)
                .filter((_, k) => k % Math.max(1, Math.ceil(n / 60)) === 0)
                .map((i) => (
                  <tr key={i}>
                    <td>{fullFmt.format(at(i))}</td>
                    {series.map((s) => (
                      <td key={s.key} className="num mono">
                        {s.values[i] == null ? "–" : formatUnit(s.values[i] ?? 0, unit)}
                      </td>
                    ))}
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
