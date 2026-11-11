"use client";

import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationNodeDatum } from "d3-force";
import { useMemo, useState, type KeyboardEvent } from "react";

import type { Graph, GraphNode } from "@/lib/api/investigations";

import { typeLabel } from "./labels";

interface Props {
  graph: Graph;
  selectedId: string | null;
  onSelect: (node: GraphNode) => void;
  /** Ids of nodes and edges the last lookup added, briefly highlighted. */
  fresh: Set<string>;
}

type Point = SimulationNodeDatum & { id: string };
const WIDTH = 760;
const HEIGHT = 420;

const short = (value: string) => (value.length > 26 ? `${value.slice(0, 12)}…${value.slice(-10)}` : value);

/**
 * The investigation's IOC graph. The layout is computed once per graph change (d3-force, no animation), and nodes
 * keep their previous positions, so a lookup only moves what it added. Every node is a keyboard-focusable button,
 * and the same graph is listed as a table below for screen readers and large graphs.
 */
interface Layout {
  graph: Graph | null;
  at: Map<string, { x: number; y: number }>;
  viewBox: string;
}

/** Lay the graph out, starting every known node where it was before, so a lookup only moves what it added. */
function computeLayout(graph: Graph, previous: Map<string, { x: number; y: number }>): Layout {
  const points: Point[] = graph.nodes.map((n) => ({ id: n.id, ...previous.get(n.id) }));
  const ids = new Set(points.map((p) => p.id));
  const links = graph.edges.filter((e) => ids.has(e.left) && ids.has(e.right)).map((e) => ({ source: e.left, target: e.right }));
  forceSimulation(points)
    .force("link", forceLink<Point, { source: string; target: string }>(links).id((p) => p.id).distance(90))
    .force("charge", forceManyBody().strength(-260))
    .force("collide", forceCollide(30))
    .force("center", forceCenter(0, 0))
    .stop()
    .tick(300);
  const at = new Map(points.map((p) => [p.id, { x: p.x ?? 0, y: p.y ?? 0 }]));
  const xs = points.map((p) => p.x ?? 0);
  const ys = points.map((p) => p.y ?? 0);
  const pad = 60;
  const box = points.length
    ? [Math.min(...xs) - pad, Math.min(...ys) - pad, Math.max(...xs) - Math.min(...xs) + 2 * pad, Math.max(...ys) - Math.min(...ys) + 2 * pad]
    : [-WIDTH / 2, -HEIGHT / 2, WIDTH, HEIGHT];
  return { graph, at, viewBox: box.join(" ") };
}

export function GraphView({ graph, selectedId, onSelect, fresh }: Props) {
  const [stored, setStored] = useState<Layout>(() => computeLayout(graph, new Map()));
  let layout = stored;
  if (stored.graph !== graph) {
    layout = computeLayout(graph, stored.at);
    setStored(layout);
  }

  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  const onKey = (event: KeyboardEvent, node: GraphNode) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(node); }
  };

  return (
    <div className="graph-wrap">
      <svg className="ioc-graph" viewBox={layout.viewBox} preserveAspectRatio="xMidYMid meet" role="group"
        aria-label={`Indicator graph: ${graph.nodes.length} indicators, ${graph.edges.length} links`}>
        {graph.edges.map((e) => {
          const a = layout.at.get(e.left);
          const b = layout.at.get(e.right);
          if (!a || !b) return null;
          return (
            <line key={e.id} className={`graph-edge${fresh.has(e.id) ? " fresh" : ""}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y}>
              <title>{`${e.ontology_label} (${e.method_id})`}</title>
            </line>
          );
        })}
        {graph.nodes.map((n) => {
          const p = layout.at.get(n.id) ?? { x: 0, y: 0 };
          const classes = ["graph-node", n.origin, n.used ? "used" : "", n.id === selectedId ? "selected" : "", fresh.has(n.id) ? "fresh" : ""];
          return (
            <g key={n.id} className={classes.join(" ")} transform={`translate(${p.x} ${p.y})`} role="button" tabIndex={0}
              aria-pressed={n.id === selectedId} onClick={() => onSelect(n)} onKeyDown={(e) => onKey(e, n)}
              aria-label={`${typeLabel(n.type)} ${n.value}, ${n.origin === "report" ? "from the report" : "found by a lookup"}${n.used ? ", already looked up" : ""}`}>
              <circle r={11} />
              <text y={26} textAnchor="middle">{short(n.value)}</text>
            </g>
          );
        })}
      </svg>
      <ul className="graph-legend" aria-hidden="true">
        <li><span className="swatch report" /> From the report</li>
        <li><span className="swatch lookup" /> Found by a lookup</li>
        <li><span className="swatch used" /> Already looked up</li>
      </ul>
      <details className="graph-table">
        <summary>Show the graph as a table</summary>
        <div className="table-scroll">
          <table className="data-table">
            <caption className="sr-only">Indicators</caption>
            <thead><tr><th scope="col">Type</th><th scope="col">Indicator</th><th scope="col">Origin</th><th scope="col">Looked up</th></tr></thead>
            <tbody>
              {graph.nodes.map((n) => (
                <tr key={n.id}>
                  <td className="mono">{typeLabel(n.type)}</td>
                  <td><button type="button" className="link-button mono indicator-value" onClick={() => onSelect(n)}>{n.value}</button></td>
                  <td>{n.origin === "report" ? "Report" : "Lookup"}</td>
                  <td>{n.used ? "Yes" : "No"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {graph.edges.length > 0 && (
          <div className="table-scroll">
            <table className="data-table">
              <caption className="sr-only">Links</caption>
              <thead><tr><th scope="col">From</th><th scope="col">Link</th><th scope="col">To</th><th scope="col">Found by</th></tr></thead>
              <tbody>
                {graph.edges.map((e) => (
                  <tr key={e.id}>
                    <td className="mono indicator-value">{byId.get(e.left)?.value}</td>
                    <td>{e.ontology_label}</td>
                    <td className="mono indicator-value">{byId.get(e.right)?.value}</td>
                    <td className="mono">{e.method_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </details>
    </div>
  );
}
