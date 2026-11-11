// Plain words for IOC Hunter's machine values. Unknown values fall back to the raw value, readable but unpolished.

const OUTCOMES: Record<string, string> = {
  ok: "Lookup succeeded",
  empty: "Lookup succeeded, nothing found",
  partial: "Partly completed",
  pending: "Still running",
  challenge: "Blocked by the provider's bot check",
  login_required: "The provider asked for a login",
  rate_limited: "The provider's rate limit was hit",
  browser_binary_missing: "The browser is not installed on the server",
  interrupted_unknown: "Interrupted; the outcome is unknown",
  not_found: "The provider has no record of it",
};

const ADMISSION: Record<string, string> = {
  known_unused_overlap: "Added to the graph: a result links to an indicator already known from the report.",
  no_known_unused_overlap: "Not added: no result links to an indicator that is already known and not yet looked up.",
  no_validated_outputs: "Not added: the lookup returned no usable results.",
};

const STOP: Record<string, string> = {
  ready: "Ready",
  user_finished: "Finished",
  user_cancelled: "Cancelled",
  step_limit: "Stopped: the step limit was reached",
  time_limit: "Stopped: the time limit was reached",
  node_limit: "Stopped: the graph size limit was reached",
  interrupted_extraction: "Failed: extraction was interrupted",
  no_iocs: "No indicators were found",
};

const REASONS: Record<string, string> = {
  run_closed: "This investigation is closed.",
  extraction_in_progress: "The report is still being read.",
  operation_in_progress: "A lookup is running. Wait for it to finish.",
  recovery_required: "A lookup was interrupted. Recover it first (button above).",
  step_limit: "The step limit has been reached.",
  time_limit: "The time limit has been reached.",
  saved_configuration_unavailable: "This investigation's saved setup cannot run here.",
  unresolved_live_route: "Not available for live lookups yet.",
  no_replay_fixture: "No recorded answer exists for this method in test (replay) mode.",
};

const SOURCES: Record<string, string> = { rapiddns: "RapidDNS", alienvault: "AlienVault OTX", virustotal: "VirusTotal" };

export const outcomeLabel = (s: string) => OUTCOMES[s] ?? s.replaceAll("_", " ");
export const admissionLabel = (s: string) => ADMISSION[s] ?? s.replaceAll("_", " ");
export const stopLabel = (s: string) => STOP[s] ?? s.replaceAll("_", " ");
export const reasonLabel = (s: string) => REASONS[s] ?? s.replaceAll("_", " ");
export const sourceLabel = (s: string) => SOURCES[s] ?? s;
export const typeLabel = (s: string) => s.replaceAll("_", " ");
/** Outcomes worth a warning colour: the lookup did not do its job. */
export const isProblem = (s: string) => !["ok", "empty", "pending"].includes(s);
export const CLOSED = new Set(["completed", "cancelled", "failed"]);
