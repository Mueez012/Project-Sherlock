// Session memory for investigations: which investigation belongs to the analysis on screen, the creation key while
// creating (so a lost answer does not create a second one), and a lookup that was sent but whose answer never
// arrived (so it is re-sent with the same step id, which returns the saved result instead of looking up twice).
import type { CreateStep } from "@/lib/api/investigations";

const linkKey = (resultId: string) => `sherklock:investigation:${resultId}`;
const pendingKey = (runId: string) => `sherklock:pending-step:${runId}`;

export interface InvestigationLink {
  runId?: string;
  creationKey?: string;
}

function read<T>(key: string): T | null {
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function write(key: string, value: unknown): void {
  try {
    if (value === null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Storage full or disabled: the investigation still works, it just is not remembered across a refresh.
  }
}

export const readLink = (resultId: string) => read<InvestigationLink>(linkKey(resultId));
export const saveLink = (resultId: string, link: InvestigationLink) => write(linkKey(resultId), link);
export const readPendingStep = (runId: string) => read<CreateStep>(pendingKey(runId));
export const savePendingStep = (runId: string, step: CreateStep | null) => write(pendingKey(runId), step);
