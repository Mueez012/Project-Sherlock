"use client";

import { ArrowsOut, MagnifyingGlassMinus, MagnifyingGlassPlus } from "@phosphor-icons/react";
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationNodeDatum } from "d3-force";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";

import type { Graph, GraphNode } from "@/lib/api/investigations";

import { typeLabel } from "./labels";

interface Props {
  graph: Graph;
  selectedId: string | null;
  onSelect: (node: GraphNode) => void;
  /** Ids of nodes and edges the last lookup added, highlighted until the next one. */
  fresh: Set<string>;
}

type Point = SimulationNodeDatum & { id: string };
type XY = { x: number; y: number };
const PAD = 48;          // px kept free around the graph when it is fitted
const RADIUS = 8;        // px: a node's size on screen, the same at every zoom level
const MIN_ZOOM = 0.3;
const MAX_ZOOM = 12;
const STEP = 1.5;

const short = (value: string) => (value.length > 26 ? `${value.slice(0, 12)}…${value.slice(-10)}` : value);
const clamp = (k: number) => Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, k));

interface Layout {
  graph: Graph | null;
  at: Map<string, XY>;
  center: XY;
  span: XY;
}

/** Lay the graph out, starting every known node where it was before, so a lookup only moves what it added. */
function computeLayout(graph: Graph, previous: Map<string, XY>): Layout {
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
  const [minX, maxX, minY, maxY] = xs.length ? [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)] : [0, 0, 0, 0];
  return { graph, at, center: { x: (minX + maxX) / 2, y: (minY + maxY) / 2 }, span: { x: maxX - minX, y: maxY - minY } };
}

/**
 * The investigation's IOC graph. Layout positions are mapped onto the measured screen size, so nodes and labels keep
 * one readable size and only the distances scale: zoom (wheel, or the buttons) spreads nodes apart, drag on the
 * background pans, Fit shows everything. Every node is a keyboard-focusable button, and the same graph is listed as
 * a table below for screen readers and large graphs.
 */
export function GraphView({ graph, selectedId, onSelect, fresh }: Props) {
  const [stored, setStored] = useState<Layout>(() => computeLayout(graph, new Map()));
  let layout = stored;
  if (stored.graph !== graph) {
    layout = computeLayout(graph, stored.at);
    setStored(layout);
  }

  const svgRef = useRef<SVGSVGElement>(null);
  const [size, setSize] = useState({ w: 760, h: 420 });
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });  // zoom and pan on top of "fit everything"
  const [dragging, setDragging] = useState(false);
  const drag = useRef<{ px: number; py: number; x: number; y: number } | null>(null);
  const live = useRef({ w: size.w, h: size.h });

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (width > 0 && height > 0) setSize({ w: width, h: height });
    });
    observer.observe(svg);
    return () => observer.disconnect();
  }, []);

  useEffect(() => { live.current = { w: size.w, h: size.h }; }, [size]);

  // Zoom keeps the point under the cursor still. Wheel listeners must be non-passive to stop the page scrolling.
  const zoomAt = (factor: number, sx: number, sy: number) => {
    setView((v) => {
      const k = clamp(v.k * factor);
      const ratio = k / v.k;
      const { w, h } = live.current;
      return { k, x: sx - w / 2 - (sx - w / 2 - v.x) * ratio, y: sy - h / 2 - (sy - h / 2 - v.y) * ratio };
    });
  };
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const box = svg.getBoundingClientRect();
      zoomAt(Math.exp(-event.deltaY * 0.0015), event.clientX - box.left, event.clientY - box.top);
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  const fit = Math.min(
    (size.w - 2 * PAD) / Math.max(layout.span.x, 1),
    (size.h - 2 * PAD) / Math.max(layout.span.y, 1),
    2.5,
  );
  const scale = fit * view.k;
  const screen = (p: XY) => ({
    x: (p.x - layout.center.x) * scale + size.w / 2 + view.x,
    y: (p.y - layout.center.y) * scale + size.h / 2 + view.y,
  });

  const startPan = (event: PointerEvent<SVGRectElement>) => {
    drag.current = { px: event.clientX, py: event.clientY, x: view.x, y: view.y };
    event.currentTarget.setPointerCapture(event.pointerId);
    setDragging(true);
  };
  const pan = (event: PointerEvent<SVGRectElement>) => {
    const start = drag.current;
    if (start) setView((v) => ({ ...v, x: start.x + event.clientX - start.px, y: start.y + event.clientY - start.py }));
  };
  const endPan = () => {
    drag.current = null;
    setDragging(false);
  };

  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  const onKey = (event: KeyboardEvent, node: GraphNode) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(node); }
  };

  return (
    <div className="graph-wrap">
      <div className="graph-tools" role="toolbar" aria-label="Graph view">
        <button type="button" className="icon-button" onClick={() => zoomAt(STEP, size.w / 2, size.h / 2)} aria-label="Zoom in"><MagnifyingGlassPlus aria-hidden="true" /></button>
        <button type="button" className="icon-button" onClick={() => zoomAt(1 / STEP, size.w / 2, size.h / 2)} aria-label="Zoom out"><MagnifyingGlassMinus aria-hidden="true" /></button>
        <button type="button" className="icon-button" onClick={() => setView({ k: 1, x: 0, y: 0 })} aria-label="Fit the whole graph"><ArrowsOut aria-hidden="true" /></button>
      </div>
      <svg ref={svgRef} className={`ioc-graph${dragging ? " dragging" : ""}`} viewBox={`0 0 ${size.w} ${size.h}`} role="group"
        aria-label={`Indicator graph: ${graph.nodes.length} indicators, ${graph.edges.length} links. Scroll to zoom, drag to move.`}>
        <rect className="graph-pan" width={size.w} height={size.h} onPointerDown={startPan} onPointerMove={pan}
          onPointerUp={endPan} onPointerCancel={endPan} />
        {graph.edges.map((e) => {
          const a = layout.at.get(e.left);
          const b = layout.at.get(e.right);
          if (!a || !b) return null;
          const [p, q] = [screen(a), screen(b)];
          return (
            <line key={e.id} className={`graph-edge${fresh.has(e.id) ? " fresh" : ""}`} x1={p.x} y1={p.y} x2={q.x} y2={q.y}>
              <title>{`${e.ontology_label} (${e.method_id})`}</title>
            </line>
          );
        })}
        {graph.nodes.map((n) => {
          const p = screen(layout.at.get(n.id) ?? { x: 0, y: 0 });
          const classes = ["graph-node", n.origin, n.used ? "used" : "", n.id === selectedId ? "selected" : "", fresh.has(n.id) ? "fresh" : ""];
          return (
            <g key={n.id} className={classes.join(" ")} transform={`translate(${p.x} ${p.y})`} role="button" tabIndex={0}
              aria-pressed={n.id === selectedId} onClick={() => onSelect(n)} onKeyDown={(e) => onKey(e, n)}
              aria-label={`${typeLabel(n.type)} ${n.value}, ${n.origin === "report" ? "from the report" : "found by a lookup"}${n.used ? ", already looked up" : ""}`}>
              <circle r={RADIUS} />
              <text y={RADIUS + 15} textAnchor="middle">{short(n.value)}</text>
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
