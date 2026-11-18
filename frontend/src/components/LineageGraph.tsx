import { useMemo, useState } from "react";
import type { GraphEdge, GraphNode, LineageGraph as Graph } from "../types";
import { humanize } from "./ui";

const KIND_ORDER: GraphNode["kind"][] = ["dataset", "training_run", "model", "deployment"];
const KIND_STYLE: Record<GraphNode["kind"], { fill: string; label: string }> = {
  dataset: { fill: "#3987e5", label: "Dataset" },
  training_run: { fill: "#199e70", label: "Training run" },
  model: { fill: "#9085e9", label: "Model" },
  deployment: { fill: "#c98500", label: "Deployment" },
};
const NODE_W = 168;
const NODE_H = 46;

/** Assign each node a column = longest path from a root (data flows left → right). */
function layout(nodes: GraphNode[], edges: GraphEdge[]) {
  const incoming = new Map<string, string[]>();
  nodes.forEach((n) => incoming.set(n.id, []));
  edges.forEach((e) => incoming.get(e.target)?.push(e.source));
  const depth = new Map<string, number>();
  const visit = (id: string, stack: Set<string>): number => {
    if (depth.has(id)) return depth.get(id)!;
    if (stack.has(id)) return 0; // defensive: graph should be acyclic
    stack.add(id);
    const parents = incoming.get(id) ?? [];
    const d = parents.length ? Math.max(...parents.map((p) => visit(p, stack) + 1)) : 0;
    stack.delete(id);
    depth.set(id, d);
    return d;
  };
  nodes.forEach((n) => visit(n.id, new Set()));
  const columns = new Map<number, GraphNode[]>();
  [...nodes]
    .sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || a.label.localeCompare(b.label))
    .forEach((n) => {
      const d = depth.get(n.id) ?? 0;
      columns.set(d, [...(columns.get(d) ?? []), n]);
    });
  const pos = new Map<string, { x: number; y: number }>();
  columns.forEach((col, d) => col.forEach((n, i) => pos.set(n.id, { x: 16 + d * (NODE_W + 72), y: 16 + i * (NODE_H + 22) })));
  const width = 32 + (Math.max(0, ...columns.keys()) + 1) * (NODE_W + 72) - 72;
  const height = 32 + Math.max(1, ...[...columns.values()].map((c) => c.length)) * (NODE_H + 22) - 22;
  return { pos, width, height };
}

function descendants(start: string, edges: GraphEdge[]): Set<string> {
  const out = new Set<string>();
  const queue = [start];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of edges) {
      if (e.source === cur && !out.has(e.target)) {
        out.add(e.target);
        queue.push(e.target);
      }
    }
  }
  return out;
}

export function LineageGraph({ graph, onSelect }: { graph: Graph; onSelect?: (node: GraphNode) => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const { pos, width, height } = useMemo(() => layout(graph.nodes, graph.edges), [graph]);
  const downstream = useMemo(() => (selected ? descendants(selected, graph.edges) : new Set<string>()), [selected, graph.edges]);
  const lit = (id: string) => !selected || id === selected || downstream.has(id);

  if (graph.nodes.length === 0) return null;
  return (
    <div className="overflow-auto rounded-md border border-line bg-page">
      <svg width={width} height={height} role="img" aria-label="Supply chain lineage graph">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="#898781" />
          </marker>
        </defs>
        {graph.edges.map((e) => {
          const a = pos.get(e.source);
          const b = pos.get(e.target);
          if (!a || !b) return null;
          const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2;
          const on = lit(e.source) && lit(e.target);
          return (
            <path
              key={`${e.source}-${e.target}`}
              d={`M${x1},${y1} C${x1 + 36},${y1} ${x2 - 36},${y2} ${x2 - 2},${y2}`}
              fill="none"
              stroke={on && selected ? "#f0efec" : "#5c5b56"}
              strokeWidth={on && selected ? 1.6 : 1}
              opacity={on ? 1 : 0.25}
              markerEnd="url(#arrow)"
            >
              <title>{humanize(e.relation)}</title>
            </path>
          );
        })}
        {graph.nodes.map((n) => {
          const p = pos.get(n.id)!;
          const style = KIND_STYLE[n.kind];
          const flagged = n.quarantined || n.status === "quarantined" || n.integrity_status === "modified";
          return (
            <g
              key={n.id}
              transform={`translate(${p.x},${p.y})`}
              opacity={lit(n.id) ? 1 : 0.3}
              className="cursor-pointer"
              role="button"
              tabIndex={0}
              aria-label={`${style.label}: ${n.label}${flagged ? " (flagged)" : ""}`}
              onClick={() => {
                setSelected((s) => (s === n.id ? null : n.id));
                onSelect?.(n);
              }}
              onKeyDown={(ev) => {
                if (ev.key === "Enter" || ev.key === " ") {
                  ev.preventDefault();
                  setSelected((s) => (s === n.id ? null : n.id));
                  onSelect?.(n);
                }
              }}
            >
              <rect width={NODE_W} height={NODE_H} rx={6} fill="#1a1a19" stroke={selected === n.id ? "#f0efec" : flagged ? "#d03b3b" : "#383835"} strokeWidth={selected === n.id || flagged ? 2 : 1} />
              <rect width={4} height={NODE_H} rx={2} fill={style.fill} />
              <text x={14} y={18} fontSize="10" fill="#898781">
                {style.label}
                {flagged ? " · flagged" : ""}
              </text>
              <text x={14} y={34} fontSize="12" fill="#f0efec">
                {n.label.length > 22 ? `${n.label.slice(0, 21)}…` : n.label}
              </text>
              <title>{`${style.label}: ${n.label}${n.status ? ` (${n.status})` : ""}`}</title>
            </g>
          );
        })}
      </svg>
      <div className="flex flex-wrap gap-4 border-t border-line px-3 py-2 text-xs text-ink-2">
        {KIND_ORDER.map((k) => (
          <span key={k} className="inline-flex items-center gap-1.5">
            <span aria-hidden className="h-3 w-1 rounded" style={{ background: KIND_STYLE[k].fill }} />
            {KIND_STYLE[k].label}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden className="h-3 w-3 rounded border-2 border-critical" /> Quarantined or modified
        </span>
        <span className="ml-auto text-muted">{selected ? `${downstream.size} downstream artifact(s) highlighted` : "Select a node to trace downstream"}</span>
      </div>
    </div>
  );
}
