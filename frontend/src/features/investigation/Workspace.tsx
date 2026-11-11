"use client";

import { DownloadSimple, WarningCircle } from "@phosphor-icons/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  InvestigationError, closeInvestigation, exportInvestigation, newRequestId, nodeMethods, readInvestigation,
  recoverInvestigation, runStep,
  type CreateStep, type GraphNode, type MethodRow, type NodeMethods, type Snapshot, type StepExecution, type StepSummary,
} from "@/lib/api/investigations";
import { readPendingStep, savePendingStep } from "@/lib/investigationStore";

import { EvidenceDialog } from "./EvidenceDialog";
import { GraphView } from "./GraphView";
import { CLOSED, stopLabel } from "./labels";
import { NodePanel, StepResult } from "./NodePanel";
import { StepLog } from "./StepLog";

interface Props {
  runId: string;
  /** The snapshot just returned by create, so the first render needs no extra request. */
  initial?: Snapshot | null;
  /** Present on the analysis page: highlight a report indicator's sentences in the report viewer. */
  onShowInReport?: (node: GraphNode) => void;
}

/** Errors after which the lookup may still complete on the server, so it is kept for a safe retry. */
const KEEP_PENDING = new Set(["network", "service_unavailable", "step_in_progress", "operation_in_progress"]);

const message = (e: unknown) => (e instanceof InvestigationError ? e.message : "Something went wrong. Please try again.");

function upsert(steps: StepSummary[], step: StepSummary): StepSummary[] {
  return [...steps.filter((s) => s.id !== step.id), step];
}

/** One saved investigation: its IOC graph, the selected indicator's lookups, the lookup log and the run's actions. */
export function Workspace({ runId, initial = null, onShowInReport }: Props) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(initial);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [methods, setMethods] = useState<NodeMethods | null>(null);
  const [methodsLoading, setMethodsLoading] = useState(false);
  const [running, setRunning] = useState<CreateStep | null>(null);
  const [last, setLast] = useState<StepExecution | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [evidence, setEvidence] = useState<string | null>(null);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const selectedRef = useRef<string | null>(null);

  const nodes = useMemo(() => new Map((snapshot?.graph.nodes ?? []).map((n) => [n.id, n])), [snapshot]);
  const closed = !!snapshot && CLOSED.has(snapshot.run.status);
  const interrupted = !!snapshot && !running && snapshot.steps.some((s) => s.status === "running");

  const reload = useCallback(async () => {
    const next = await readInvestigation(runId);
    setSnapshot(next);
    return next;
  }, [runId]);

  const loadMethods = useCallback(async (nodeId: string) => {
    setMethodsLoading(true);
    try {
      const m = await nodeMethods(runId, nodeId);
      if (selectedRef.current === nodeId) setMethods(m);
    } catch (e) {
      if (selectedRef.current === nodeId) { setMethods(null); setNotice(message(e)); }
    } finally {
      if (selectedRef.current === nodeId) setMethodsLoading(false);
    }
  }, [runId]);

  const send = useCallback(async (step: CreateStep, before: Snapshot) => {
    setRunning(step);
    setNotice("");
    try {
      const result = await runStep(runId, step);
      savePendingStep(runId, null);
      const known = new Set([...before.graph.nodes.map((n) => n.id), ...before.graph.edges.map((e) => e.id)]);
      setFresh(new Set([...result.graph.nodes.map((n) => n.id), ...result.graph.edges.map((e) => e.id)].filter((id) => !known.has(id))));
      setSnapshot((cur) => (cur ? { ...cur, run: result.run, graph: result.graph, steps: upsert(cur.steps, result.step) } : cur));
      setLast(result);
      if (selectedRef.current) void loadMethods(selectedRef.current);
    } catch (e) {
      const code = e instanceof InvestigationError ? e.code : "";
      if (KEEP_PENDING.has(code)) {
        // The server may still be running it, or finish it later: keep the step, so trying again returns the saved
        // result instead of looking up twice.
        setNotice(`${message(e)} Your lookup is kept; use "Try again" and it will not run twice.`);
      } else {
        savePendingStep(runId, null);
        setNotice(message(e));
        if (code === "stale_graph_revision" || code === "limit_reached" || code === "run_closed" || code === "recovery_required") {
          await reload().catch(() => undefined);
        }
      }
    } finally {
      setRunning(null);
    }
  }, [runId, loadMethods, reload]);

  // First load; a lookup whose answer never arrived (refresh, lost connection) is sent again with the same step id.
  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const current = initial ?? (await readInvestigation(runId));
        if (!live) return;
        setSnapshot(current);
        const pending = readPendingStep(runId);
        if (pending && !CLOSED.has(current.run.status)) await send(pending, current);
      } catch (e) {
        if (live) setNotice(message(e));
      }
    })();
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only on mount
  }, [runId]);

  const select = (node: GraphNode) => {
    selectedRef.current = node.id;
    setSelectedId(node.id);
    setMethods(null);
    void loadMethods(node.id);
  };

  const run = (method: MethodRow) => {
    if (!snapshot || !selectedId) return;
    const step: CreateStep = {
      step_id: newRequestId(), input_node_id: selectedId, method_id: method.id,
      expected_graph_revision: snapshot.run.graph_revision,
    };
    savePendingStep(runId, step);
    void send(step, snapshot);
  };

  const act = async (work: () => Promise<Snapshot | void>) => {
    setBusy(true);
    setNotice("");
    try {
      const next = await work();
      if (next) setSnapshot(next);
    } catch (e) {
      setNotice(message(e));
    } finally {
      setBusy(false);
      setConfirmCancel(false);
    }
  };

  const download = () => act(async () => {
    const { blob, filename } = await exportInvestigation(runId);
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: filename });
    document.body.append(a);  // some browsers ignore a click on a link that is not in the page
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 30_000);  // releasing at once can cancel the download
  });

  if (!snapshot) {
    return notice ? <p className="form-error" role="alert"><WarningCircle aria-hidden="true" weight="fill" /> {notice}</p>
      : <p className="muted">Loading the investigation…</p>;
  }

  const pendingRetry = !running && readPendingStep(runId);
  const selected = selectedId ? nodes.get(selectedId) ?? null : null;
  return (
    <div className="workspace">
      <div className="workspace-status">
        <p className="small muted">
          {stopLabel(closed ? snapshot.run.stop_reason : snapshot.run.status === "failed" ? snapshot.run.stop_reason : "ready")}
          {" · "}{snapshot.graph.nodes.length} indicators · {snapshot.graph.edges.length} links · {snapshot.steps.length} of {snapshot.run.config.max_steps} lookups
        </p>
        <div className="workspace-actions">
          {interrupted && <button type="button" className="button secondary" disabled={busy} onClick={() => act(() => recoverInvestigation(runId))}>Recover interrupted lookup</button>}
          {!closed && !confirmCancel && (
            <>
              <button type="button" className="button secondary" disabled={busy || !!running} onClick={() => act(() => closeInvestigation(runId, "finish"))}>Finish</button>
              <button type="button" className="button ghost" disabled={busy || !!running} onClick={() => setConfirmCancel(true)}>Cancel investigation</button>
            </>
          )}
          {confirmCancel && (
            <>
              <span className="small">Cancel this investigation? Its evidence is kept.</span>
              <button type="button" className="button secondary" disabled={busy} onClick={() => act(() => closeInvestigation(runId, "cancel"))}>Yes, cancel</button>
              <button type="button" className="button ghost" onClick={() => setConfirmCancel(false)}>No</button>
            </>
          )}
          <button type="button" className="button ghost" disabled={busy} onClick={download}><DownloadSimple aria-hidden="true" /> Download JSON</button>
        </div>
      </div>

      {notice && (
        <p className="form-error" role="alert"><WarningCircle aria-hidden="true" weight="fill" /> {notice}
          {pendingRetry && <> <button type="button" className="link-button" onClick={() => void send(pendingRetry, snapshot)}>Try again</button></>}
        </p>
      )}
      {snapshot.run.status === "failed" && snapshot.run.diagnostics.length > 0 && (
        <p className="notice small">{String(snapshot.run.diagnostics[0].message ?? snapshot.run.stop_reason)}</p>
      )}
      <p className="sr-only" aria-live="polite">{running ? "Running the lookup. This can take a minute." : ""}</p>

      <div className="workspace-grid">
        <div className="workspace-graph">
          {snapshot.graph.nodes.length ? (
            <GraphView graph={snapshot.graph} selectedId={selectedId} onSelect={select} fresh={fresh} />
          ) : (
            <p className="empty-note">No indicators were found in this report, so there is nothing to look up.</p>
          )}
        </div>
        <aside className="workspace-side" aria-live="polite">
          {running && (
            <p className="running-note" role="status">
              Looking up {nodes.get(running.input_node_id)?.value ?? "the indicator"} with <span className="mono">{running.method_id}</span>…
              This can take a minute (providers are paced).
            </p>
          )}
          {last && !running && <StepResult result={last} nodes={nodes} />}
          <NodePanel snapshot={snapshot} node={selected} methods={methods} loading={methodsLoading}
            running={!!running} closed={closed} onRun={run} onShowInReport={onShowInReport} />
        </aside>
      </div>

      <h3 className="panel-subhead">Lookup log</h3>
      <StepLog steps={snapshot.steps} nodes={nodes} onEvidence={setEvidence} />
      <EvidenceDialog runId={runId} stepId={evidence} onClose={() => setEvidence(null)} />
    </div>
  );
}
