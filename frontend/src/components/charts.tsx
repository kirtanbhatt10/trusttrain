import { useState } from "react";
import { humanize } from "./ui";

export interface BarItem {
  key: string;
  label?: string;
  value: number;
  /** CSS colour for the bar; text always stays in ink colours. */
  color: string;
}

/** Horizontal bar list: one shared axis (count), value labels, hover tooltip. */
export function BarList({ items, ariaLabel, emptyText = "No data yet." }: { items: BarItem[]; ariaLabel: string; emptyText?: string }) {
  const [hover, setHover] = useState<string | null>(null);
  const max = Math.max(1, ...items.map((i) => i.value));
  const total = items.reduce((s, i) => s + i.value, 0);
  if (total === 0) return <p className="py-4 text-sm text-ink-2">{emptyText}</p>;
  return (
    <ul aria-label={ariaLabel} className="space-y-2">
      {items.map((item) => (
        <li
          key={item.key}
          className="grid grid-cols-[8.5rem_1fr_3rem] items-center gap-3 text-sm"
          onMouseEnter={() => setHover(item.key)}
          onMouseLeave={() => setHover(null)}
        >
          <span className="truncate text-ink-2">{item.label ?? humanize(item.key)}</span>
          <span className="relative h-5">
            <span
              className="absolute inset-y-1 left-0 rounded-r-[4px] transition-[width]"
              style={{ width: `${(item.value / max) * 100}%`, minWidth: item.value ? 2 : 0, background: item.color, opacity: hover && hover !== item.key ? 0.45 : 1 }}
            />
            {hover === item.key && (
              <span role="tooltip" className="absolute -top-7 left-0 z-10 whitespace-nowrap rounded border border-line bg-raised px-2 py-0.5 text-xs text-ink shadow">
                {item.label ?? humanize(item.key)}: {item.value} ({Math.round((item.value / total) * 100)}%)
              </span>
            )}
          </span>
          <span className="text-right tabular-nums text-ink">{item.value}</span>
        </li>
      ))}
    </ul>
  );
}

interface HistoryPoint {
  date: string;
  inspections: number;
  findings: number;
}

const SERIES = [
  { key: "inspections" as const, label: "Inspections", color: "#3987e5" },
  { key: "findings" as const, label: "Findings", color: "#d95926" },
];

/** Daily detection activity: two count series on one axis, crosshair tooltip, table view. */
export function HistoryChart({ points }: { points: HistoryPoint[] }) {
  const [active, setActive] = useState<number | null>(null);
  const [asTable, setAsTable] = useState(false);
  if (points.length === 0) return <p className="py-4 text-sm text-ink-2">No inspections have been run yet.</p>;

  const W = 640, H = 200, L = 36, R = 12, T = 12, B = 28;
  const max = Math.max(1, ...points.flatMap((p) => [p.inspections, p.findings]));
  const x = (i: number) => (points.length === 1 ? L + (W - L - R) / 2 : L + (i * (W - L - R)) / (points.length - 1));
  const y = (v: number) => T + (H - T - B) * (1 - v / max);
  const ticks = [0, Math.ceil(max / 2), max];

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <div className="flex gap-4 text-xs text-ink-2" aria-label="Legend">
          {SERIES.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5">
              <span aria-hidden className="h-0.5 w-4 rounded" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </div>
        <button className="text-xs text-ink-2 underline underline-offset-2 hover:text-ink" onClick={() => setAsTable((v) => !v)}>
          {asTable ? "Show chart" : "Show table"}
        </button>
      </div>
      {asTable ? (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-muted">
              <th className="py-1 text-left font-medium">Date</th>
              <th className="py-1 text-right font-medium">Inspections</th>
              <th className="py-1 text-right font-medium">Findings</th>
            </tr>
          </thead>
          <tbody>
            {points.map((p) => (
              <tr key={p.date} className="border-t border-line/60">
                <td className="py-1 text-ink-2">{p.date}</td>
                <td className="py-1 text-right tabular-nums">{p.inspections}</td>
                <td className="py-1 text-right tabular-nums">{p.findings}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="w-full"
          role="img"
          aria-label="Inspections and findings per day"
          onMouseLeave={() => setActive(null)}
          onMouseMove={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            const px = ((e.clientX - rect.left) / rect.width) * W;
            let best = 0;
            points.forEach((_, i) => {
              if (Math.abs(x(i) - px) < Math.abs(x(best) - px)) best = i;
            });
            setActive(best);
          }}
        >
          {ticks.map((t) => (
            <g key={t}>
              <line x1={L} x2={W - R} y1={y(t)} y2={y(t)} stroke="#383835" strokeWidth={t === 0 ? 1 : 0.5} />
              <text x={L - 6} y={y(t) + 4} textAnchor="end" fontSize="10" fill="#898781">
                {t}
              </text>
            </g>
          ))}
          {[0, points.length - 1].filter((v, i, a) => a.indexOf(v) === i).map((i) => (
            <text key={i} x={x(i)} y={H - 8} textAnchor={points.length === 1 ? "middle" : i === 0 ? "start" : "end"} fontSize="10" fill="#898781">
              {points[i].date}
            </text>
          ))}
          {SERIES.map((s) => (
            <g key={s.key}>
              <polyline
                fill="none"
                stroke={s.color}
                strokeWidth={2}
                strokeLinejoin="round"
                points={points.map((p, i) => `${x(i)},${y(p[s.key])}`).join(" ")}
              />
              {points.map((p, i) => (
                <circle key={i} cx={x(i)} cy={y(p[s.key])} r={active === i ? 4 : 2.5} fill={s.color} stroke="#1a1a19" strokeWidth={2} />
              ))}
            </g>
          ))}
          {active !== null && (
            <g pointerEvents="none">
              <line x1={x(active)} x2={x(active)} y1={T} y2={H - B} stroke="#898781" strokeDasharray="3 3" />
              <g transform={`translate(${Math.min(x(active) + 8, W - 130)},${T + 4})`}>
                <rect width="120" height="50" rx="4" fill="#222220" stroke="#383835" />
                <text x="8" y="16" fontSize="10" fill="#c3c2b7">{points[active].date}</text>
                <text x="8" y="31" fontSize="11" fill="#f0efec">Inspections: {points[active].inspections}</text>
                <text x="8" y="44" fontSize="11" fill="#f0efec">Findings: {points[active].findings}</text>
              </g>
            </g>
          )}
        </svg>
      )}
    </div>
  );
}

export const RISK_COLORS: Record<string, string> = {
  critical: "#d03b3b",
  high: "#ec835a",
  medium: "#fab219",
  low: "#3987e5",
  none: "#0ca30c",
  unknown: "#898781",
  info: "#898781",
};
