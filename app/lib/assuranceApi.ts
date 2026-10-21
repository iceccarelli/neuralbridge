// Typed, honest fetch helpers for the /assurance workspace. One rule: every
// outcome the server can return is representable here, and none is turned into
// a success. The API enforces access; nothing in this file grants any.

export type FleetRow = {
  machine: string;
  site: string;
  manifest_id: string;
  configuration_hash: string;
  taken_at: string;
  verdict: string;
  worst: string | null;
  functions: number;
  stale: number;
  uncovered: number;
  interventions: number;
  verifications: number;
  tier_ceiling: string;
};

export type Fleet = {
  summary: { machines: number; covered: number; with_gaps: number; by_worst: Record<string, number> };
  machines: FleetRow[];
  chain_verified: boolean;
  chain_problems: string[];
};

// GET /v1/fleet/observations — what the customer's own Watch reported (assurance
// watch push). Nothing here is observed by the hosted service.
export type ObservationRow = {
  machine: string;
  reported: boolean;
  last_successful_observation_at: string | null;
  last_attempt_at: string | null;
  last_attempt_status: string | null;
  last_attempt_succeeded: boolean | null;
  last_attempt_detail: string;
  age_hours: number | null;
  stale: boolean;
  stale_reason: '' | 'never_reported' | 'never_successfully_observed' | 'older_than_cadence';
  cadence_hours: number;
  cadence_declared: boolean;
  consecutive_failed_attempts: number;
  open_case_ids: string[];
};

export type Observations = {
  as_of: string;
  default_cadence_hours: number;
  reporting: boolean;
  machines: ObservationRow[];
  summary: { machines: number; never_reported: number; latest_attempt_failed: number; stale: number };
  limitations: string[];
};

export type CaseRow = {
  case_id: string;
  machines: string[];
  trigger: string;
  opened_at: string;
  changed: string[];
  affected_functions: string[];
  evidence_state: string[];
  status: string;
  owner: string;
  next_action: string;
  age_days: number | null;
};

export type CaseQueue = {
  cases: CaseRow[];
  summary: { open: number; safety_relevant: number; awaiting_reverification: number; ready_to_close: number };
};

export type HistoryItem = { kind: string; at: string; detail: string };

export type CaseDetail = {
  case_id: string;
  status: string;
  trigger_type: string;
  trigger_id: string;
  machines: string[];
  affected_functions: string[];
  change_severity: string;
  invalidation_reason: string;
  required_actions: string[];
  required_reverifications: string[];
  human_decisions_required: string[];
  evidence_current: Record<string, string>;
  linked_evidence: { relation?: string; content_hash?: string; note?: string }[];
  owner: string;
  decision: string;
  decision_reason: string;
  decision_by: string;
  checks_skipped: string[];
  history: HistoryItem[];
};

export type ApiOutcome<T> =
  | { kind: 'ok'; data: T }
  | { kind: 'unconfigured' }
  | { kind: 'unauthorized'; message: string }
  | { kind: 'upgrade'; tier: string; remedy: string }
  | { kind: 'conflict'; message: string }
  | { kind: 'error'; status: number; message: string };

function messageOf(body: unknown, fallback: string): string {
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (typeof detail === 'string') return detail;
  if (detail && typeof detail === 'object') {
    const d = detail as { detail?: string; remedy?: string; error?: string };
    return d.detail || d.remedy || d.error || fallback;
  }
  return fallback;
}

export async function call<T>(
  apiBase: string,
  apiKey: string,
  path: string,
  init?: { method?: string; body?: unknown },
): Promise<ApiOutcome<T>> {
  if (!apiBase) return { kind: 'unconfigured' };
  let res: Response;
  try {
    res = await fetch(`${apiBase}${path}`, {
      method: init?.method || 'GET',
      headers: {
        ...(init?.body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(apiKey ? { 'X-API-Key': apiKey } : {}),
      },
      body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
    });
  } catch {
    return { kind: 'error', status: 0, message: 'The API could not be reached from this browser.' };
  }
  const body = await res.json().catch(() => null);
  if (res.ok) return { kind: 'ok', data: body as T };
  if (res.status === 401) return { kind: 'unauthorized', message: messageOf(body, 'This view needs an API key.') };
  if (res.status === 402) {
    const d = (body as { detail?: { tier?: string; remedy?: string } } | null)?.detail;
    return {
      kind: 'upgrade',
      tier: d?.tier || 'free',
      remedy: d?.remedy || 'Your plan does not include this view.',
    };
  }
  if (res.status === 409) return { kind: 'conflict', message: messageOf(body, 'The case is not in a state that allows that.') };
  return { kind: 'error', status: res.status, message: messageOf(body, `HTTP ${res.status}`) };
}
