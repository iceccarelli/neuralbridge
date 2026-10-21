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
  summary: {
    open: number;
    safety_relevant: number;
    awaiting_reverification: number;
    ready_to_close: number;
    // Counted apart from `open`: a deferral is "not today", not "settled". `degraded` is an
    // open case that names no machine (for example one raised from an incomplete collection).
    deferred: number;
    degraded: number;
  };
};

// The case's own history carries what happened and when. WHO is not a field of
// it: the actor is sealed on the ledger entry of each event (see ExportEntry).
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
  opened_at?: string;
  updated_at?: string;
  resolved_decisions?: { decision?: string; resolution?: string; by?: string; at?: string }[];
};

// GET /v1/change/cases/{id}/replay — the case rebuilt from the ledger alone. ok=false is HTTP 200.
export type Replay = { case_id: string; ok: boolean; entries: number; violations: string[]; case: unknown };

// POST /v1/change/assess/intervention
export type AssessInterventionResult = {
  opened: boolean;
  case: { case_id: string; status: string; history?: HistoryItem[] } | null;
  intervention_id: string;
};

// GET /v1/cases/{id}/export — the evidence bundle. `actor` on an entry is the
// person/automation the account asserted for that event.
export type ExportEntry = {
  seq: number;
  at: string;
  kind: string;
  subject: string;
  content_hash: string;
  actor: unknown;
};

export type ExportBundle = {
  exported_at: string;
  subject: string;
  chain_verified: boolean;
  entries: ExportEntry[];
};

// GET /v1/me
export type Me = {
  authenticated: boolean;
  tier: string;
  plan: {
    tier: string;
    name: string;
    blurb: string;
    price: string;
    purchasable: boolean;
    includes: string[];
    limits: Record<string, number | boolean | null>;
  };
  usage_today: Record<string, number>;
  account?: { id: string; company: string; email: string; status: string };
  keys?: { prefix?: string; label?: string; created_at?: string; revoked_at?: string | null; [k: string]: unknown }[];
  warning?: string;
  note?: string;
  // True for an account whose subscription ended but that has paid before: the server still
  // lets it read, verify and export the evidence it already holds (new records are closed).
  evidence_readout?: boolean;
};

// POST /v1/fleet/advisory — assess_impact(...).to_dict()
export type FunctionExposure = {
  function_id: string;
  description: string;
  coverage_before: string;
  newly_in_question: boolean;
  last_verified_at: string;
  last_verified_hash: string;
};

export type Exposure = {
  machine: string;
  site: string;
  item_id: string;
  item_name: string;
  item_version: string;
  basis: 'hash' | 'hash_mismatch' | 'version' | 'name_only';
  confidence: string;
  needs_a_human: boolean;
  detail: string;
  functions: FunctionExposure[];
  newly_in_question: string[];
};

export type ImpactReport = {
  advisory_id: string;
  advisory_hash: string;
  issued_by: string;
  severity: string;
  title: string;
  reference: string;
  assessed_at: string;
  verdict: 'clear' | 'exposed' | 'needs_review';
  machines_in_fleet: number;
  machines_affected: string[];
  functions_newly_in_question: number;
  exposures: Exposure[];
  checks_skipped: string[];
};

// POST /v1/change/assess/advisory
export type AssessAdvisoryResult = {
  opened: boolean;
  case: { case_id: string; status: string; history?: HistoryItem[] } | null;
  verdict: string;
};

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

export type ApiOutcome<T> =
  | { kind: 'ok'; data: T; at: number }
  | { kind: 'unconfigured' }
  // 401: no key, or a key the server does not recognise.
  | { kind: 'unauthorized'; status: 401; message: string }
  // 402: authenticated, not entitled (plan or account state).
  | { kind: 'upgrade'; status: 402; tier: string; accountStatus: string; code: string; remedy: string }
  // 403: refused for a reason that is not payment.
  | { kind: 'forbidden'; status: 403; message: string }
  // 404: nothing by that id in the caller's own ledger/store.
  | { kind: 'notfound'; status: 404; message: string }
  // 409: the request is well-formed but the resource's state does not allow it.
  | { kind: 'conflict'; status: 409; message: string }
  // 413: the request body is over the server's limit.
  | { kind: 'toolarge'; status: 413; limitBytes: number | null; message: string }
  // 422: the server could not use the content of the request.
  | { kind: 'invalid'; status: 422; message: string }
  // 429: a daily allowance is spent.
  | { kind: 'ratelimited'; status: 429; message: string; remedy: string; retryAfter: string }
  // The request never produced an HTTP answer.
  | { kind: 'unreachable'; message: string }
  // Anything else, including 5xx.
  | { kind: 'error'; status: number; code: string; message: string };

export type Detail = { code: string; message: string; remedy: string; extra: Record<string, unknown> };

// FastAPI shapes seen from this server: {"detail": "text"}, {"detail": {error, detail|remedy, ...}},
// {"detail": [{loc, msg}, ...]} (request validation) and, from the ValueError handler,
// {"error": ..., "detail": "text"}.
export function parseDetail(body: unknown, fallback: string): Detail {
  const out: Detail = { code: '', message: '', remedy: '', extra: {} };
  const b = body as { detail?: unknown; error?: unknown } | null;
  if (!b || typeof b !== 'object') {
    out.message = fallback;
    return out;
  }
  if (typeof b.error === 'string') out.code = b.error;
  const d = b.detail;
  if (typeof d === 'string') {
    out.message = d;
  } else if (Array.isArray(d)) {
    out.message = d
      .map((e) => {
        const item = e as { loc?: unknown[]; msg?: string };
        const where = Array.isArray(item.loc) ? item.loc.filter((p) => p !== 'body').join('.') : '';
        return where ? `${where}: ${item.msg ?? 'invalid'}` : (item.msg ?? 'invalid');
      })
      .join('; ');
  } else if (d && typeof d === 'object') {
    const o = d as Record<string, unknown>;
    if (typeof o.error === 'string') out.code = o.error;
    if (typeof o.detail === 'string') out.message = o.detail;
    if (typeof o.remedy === 'string') out.remedy = o.remedy;
    out.extra = o;
  }
  if (!out.message && !out.remedy) out.message = fallback;
  return out;
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
    return { kind: 'unreachable', message: 'The API could not be reached from this browser.' };
  }
  const body = await res.json().catch(() => null);
  if (res.ok) return { kind: 'ok', data: body as T, at: Date.now() };
  return classify(res.status, body, res.headers.get('retry-after') || '');
}

// Plain-text GET (the hosted supplier feed is newline-delimited JSON). Never sends a key:
// the feed is public by design.
export async function callText(apiBase: string, path: string): Promise<ApiOutcome<string>> {
  if (!apiBase) return { kind: 'unconfigured' };
  let res: Response;
  try {
    res = await fetch(`${apiBase}${path}`);
  } catch {
    return { kind: 'unreachable', message: 'The API could not be reached from this browser.' };
  }
  if (res.ok) return { kind: 'ok', data: await res.text(), at: Date.now() };
  const body = await res.json().catch(() => null);
  return classify(res.status, body, res.headers.get('retry-after') || '');
}

export function classify(status: number, body: unknown, retryAfter = ''): ApiOutcome<never> {
  const d = parseDetail(body, `HTTP ${status}`);
  switch (status) {
    case 401:
      return { kind: 'unauthorized', status, message: d.message || 'This view needs an API key.' };
    case 402: {
      const x = d.extra as { tier?: string; account_status?: string };
      return {
        kind: 'upgrade',
        status,
        tier: x.tier || 'free',
        accountStatus: x.account_status || '',
        code: d.code,
        remedy: d.remedy || d.message || 'Your plan does not include this view.',
      };
    }
    case 403:
      return { kind: 'forbidden', status, message: d.remedy ? `${d.message} ${d.remedy}`.trim() : d.message };
    case 404:
      return { kind: 'notfound', status, message: d.message };
    case 409:
      return {
        kind: 'conflict',
        status,
        message: d.remedy ? `${d.message} ${d.remedy}`.trim() : d.message || 'The case is not in a state that allows that.',
      };
    case 413: {
      const limit = (d.extra as { limit_bytes?: number }).limit_bytes;
      return { kind: 'toolarge', status, limitBytes: typeof limit === 'number' ? limit : null, message: d.message };
    }
    case 422:
      return { kind: 'invalid', status, message: d.message };
    case 429:
      return { kind: 'ratelimited', status, message: d.message, remedy: d.remedy, retryAfter };
    default:
      return { kind: 'error', status, code: d.code, message: d.message };
  }
}

export type Described = { heading: string; text: string; remedy: string; kind: ApiOutcome<unknown>['kind'] };

// One sentence per outcome a person can act on. The server's own remedy text is
// passed through unchanged; this only adds which refusal it was.
export function describeOutcome(outcome: Exclude<ApiOutcome<unknown>, { kind: 'ok' }>): Described {
  switch (outcome.kind) {
    case 'unconfigured':
      return {
        kind: outcome.kind,
        heading: 'No API configured',
        text: 'This build has no API address (NEXT_PUBLIC_ASSURANCE_API_URL), so there is nothing to ask. Nothing is shown rather than something invented.',
        remedy: '',
      };
    case 'unauthorized':
      return {
        kind: outcome.kind,
        heading: 'Not signed in (401)',
        text: `The API did not accept the key: ${outcome.message}`,
        remedy: 'Paste a valid key. Keys start with asr_ and are shown once, at checkout.',
      };
    case 'upgrade':
      return {
        kind: outcome.kind,
        heading: `Not included in your plan (402)`,
        text: `Your plan (${outcome.tier}${outcome.accountStatus ? `, account ${outcome.accountStatus}` : ''}) does not include this.`,
        remedy: outcome.remedy,
      };
    case 'forbidden':
      return {
        kind: outcome.kind,
        heading: 'Refused (403)',
        text: outcome.message || 'The server refused this request.',
        remedy: '',
      };
    case 'notfound':
      return {
        kind: outcome.kind,
        heading: 'Not found (404)',
        text: outcome.message || 'Nothing by that id.',
        remedy: '',
      };
    case 'conflict':
      return {
        kind: outcome.kind,
        heading: 'Not allowed in the current state (409)',
        text: outcome.message,
        remedy: '',
      };
    case 'toolarge':
      return {
        kind: outcome.kind,
        heading: 'Too large (413)',
        text: `${outcome.message || 'The request body is over the server limit.'}${
          outcome.limitBytes ? ` Limit: ${outcome.limitBytes.toLocaleString('en')} bytes.` : ''
        }`,
        remedy: 'Send a smaller file, or split it (a feed can be sent record by record).',
      };
    case 'invalid':
      return {
        kind: outcome.kind,
        heading: 'The server could not use that content (422)',
        text: outcome.message,
        remedy: '',
      };
    case 'ratelimited':
      return {
        kind: outcome.kind,
        heading: 'Daily allowance used (429)',
        text: outcome.message || 'You have used today’s allowance for this call.',
        remedy: `${outcome.remedy}${outcome.retryAfter ? ` Retry after ${outcome.retryAfter} s.` : ''}`.trim(),
      };
    case 'unreachable':
      return {
        kind: outcome.kind,
        heading: 'API unreachable',
        text: outcome.message,
        remedy: 'This is not an empty result: nothing was learned. Check your connection and try Reload.',
      };
    case 'error':
      if (outcome.code === 'ledger_integrity') {
        return {
          kind: outcome.kind,
          heading: 'THE LEDGER CHAIN DOES NOT VERIFY (500)',
          text: `The server refused to build this because your ledger's hash chain fails verification: ${outcome.message}`,
          remedy:
            'Nothing was exported. Do not rely on anything drawn from this ledger until the break is explained; this is not an empty result.',
        };
      }
      return {
        kind: outcome.kind,
        heading: outcome.status >= 500 ? `Server error (${outcome.status})` : `Request failed (${outcome.status})`,
        text: outcome.message,
        remedy: outcome.status >= 500 ? 'The server failed; this is not an empty result. Try again shortly.' : '',
      };
  }
}

// Failures after which keeping the last good data on screen is honest (the data may be
// old, and we say so). After a 401/402/403/404 the old data may no longer be yours to see.
export function keepsLastGood(outcome: Exclude<ApiOutcome<unknown>, { kind: 'ok' }>): boolean {
  return (
    outcome.kind === 'unreachable' ||
    outcome.kind === 'ratelimited' ||
    (outcome.kind === 'error' && outcome.status >= 500)
  );
}
