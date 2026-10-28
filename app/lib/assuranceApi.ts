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
  // Optional: older servers omit them. Hours between a manifest's date and the look that used it,
  // as reported by the client, and whether the client marked it as sealed earlier and relayed.
  last_successful_manifest_age_hours?: number | null;
  last_successful_manifest_relayed?: boolean | null;
  // Optional: how the freshness of the last successful look was obtained. Treat planted_in_same_report
  // (the manifest was first received in the very report that relayed it), and a relayed look whose
  // manifest was already older than the window at the server's receipt, as freshness the reporter
  // asserted. The service labels these; it does not refuse them.
  last_successful_relay_basis?:
    | 'unrelayed'
    | 'held_from_earlier_report'
    | 'planted_in_same_report'
    | 'same_configuration_held'
    | 'relayed_basis_unrecorded'
    | null;
  last_successful_manifest_first_received_in_this_report?: boolean | null;
  last_successful_manifest_age_at_receipt_hours?: number | null;
  last_successful_manifest_age_exceeds_window_at_receipt?: boolean | null;
  last_attempt_manifest_age_hours?: number | null;
  // Optional: older servers omit them. Every observation is a statement by the holder of the account's
  // key ("client_reported"); received_at is the server's clock, and a skew flag means the reporter's
  // observed_at and that receipt differ by more than the server's bound (24 h).
  basis?: 'client_reported';
  last_successful_observed_at_declared?: string | null;
  last_successful_received_at?: string | null;
  last_successful_observed_at_skew?: boolean | null;
  last_attempt_observed_at_skew?: boolean | null;
};

export type Observations = {
  as_of: string;
  basis?: 'client_reported';
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
  // Only with ?skeleton=true: every OTHER entry of the account's ledger (no evidence). Past the
  // server's limit it is left out: `skeleton` is then empty and `skeleton_truncated` is true.
  skeleton?: unknown[];
  skeleton_truncated?: boolean;
  // The newest attestation the service READ from this account's ledger. A hosted export has none
  // until the operator has signed the ledger.
  anchor?: { sequence?: number; head_seq?: number; basis?: string; attested_at?: string } | null;
};

// What an export actually carries, read from the RESPONSE (never from the request checkbox):
// a file that was asked to carry the skeleton may not, and a hosted export has no anchor unless
// the operator signed the ledger.
export type ExportCompleteness = {
  skeleton: 'carried' | 'truncated' | 'absent' | 'not_requested';
  anchor: { sequence: number; headSeq: number; readFromLedger: boolean } | null;
};

export function exportCompleteness(bundle: ExportBundle, requestedSkeleton: boolean): ExportCompleteness {
  let skeleton: ExportCompleteness['skeleton'] = 'not_requested';
  if (requestedSkeleton) {
    if (bundle.skeleton_truncated === true) skeleton = 'truncated';
    else if (Array.isArray(bundle.skeleton)) skeleton = 'carried';
    else skeleton = 'absent';
  }
  const a = bundle.anchor;
  const anchor =
    a && typeof a === 'object' && typeof a.sequence === 'number' && typeof a.head_seq === 'number'
      ? { sequence: a.sequence, headSeq: a.head_seq, readFromLedger: a.basis === 'read_from_ledger' }
      : null;
  return { skeleton, anchor };
}

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

/**
 * The translation record an importer (`assurance fleet import-csaf`) writes into the advisory
 * (fleet/advisory.py ImportRecord). Present only for an import. An import is never signed:
 * `trust` is the only value the server accepts, and `partial` means affected products were
 * dropped, so a report with no match is not "clear".
 */
export type AdvisoryImportRecord = {
  origin: string;
  trust: 'unsigned_inspect_only' | string;
  partial: boolean;
  dropped: { product_id: string; reason: string }[];
  partial_reasons?: string[];
  severity_source: 'defaulted_by_importer' | 'operator_flag' | string;
  tlp: string;
  tracking_status: string;
  document_category: string;
  document_date: string;
  notes: string[];
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
  /** False when the ledger chain does not verify: an empty match list then proves nothing. */
  chain_verified: boolean;
  machines_affected: string[];
  functions_newly_in_question: number;
  exposures: Exposure[];
  checks_skipped: string[];
  // Per-machine classification (fleet/impact.py). Optional: an older server omits them, and an
  // absent field is never read as "nothing unknown".
  machine_classification?: MachineClassification[];
  unknown_machines?: string[];
  unknown_functions?: { machine?: string; function_id?: string; item_id?: string; reason?: string }[];
  prior_evidence_in_question?: Record<string, unknown>[];
  clear_is_complete?: boolean;
  provenance?: Record<string, unknown>;
  // Optional: an older server omits them. An advisory that is an unsigned import carries its
  // record; `incomplete` means the translation dropped affected products (never read as clear).
  advisory_import?: AdvisoryImportRecord | null;
  incomplete?: boolean;
  incomplete_reasons?: string[];
};

export type MachineClassification = {
  machine: string;
  site: string;
  classification:
    | 'match_by_hash'
    | 'match_by_version_only'
    | 'possible_match_name_only'
    | 'contradictory_label_vs_hash'
    | 'unknown'
    | 'no_match_found'
    | string;
  basis: string;
  uncertainty: string;
  item_ids: string[];
  unknown_reasons: string[];
};

// POST /v1/change/assess/advisory
export type AssessAdvisoryResult = {
  opened: boolean;
  case: { case_id: string; status: string; history?: HistoryItem[]; provenance?: Record<string, string> } | null;
  verdict: string;
  incomplete?: boolean;
  advisory_trust?: Record<string, unknown>;
  advisory_import?: AdvisoryImportRecord | null;
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
  | { kind: 'forbidden'; status: 403; message: string; code?: string }
  // 404: nothing by that id in the caller's own ledger/store.
  | { kind: 'notfound'; status: 404; message: string }
  // 409: the request is well-formed but the resource's state does not allow it. `code` is the
  // server's error code when it gave one (e.g. anchor_contradicts_ledger); `finding` is what it
  // found and `remedy` what to do about it, kept apart so a page can show both with the refusal.
  | { kind: 'conflict'; status: 409; message: string; code?: string; finding?: string; remedy?: string }
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

export type Detail = { code: string; message: string; finding: string; remedy: string; extra: Record<string, unknown> };

// FastAPI shapes seen from this server: {"detail": "text"}, {"detail": {error, detail|remedy, ...}},
// {"detail": [{loc, msg}, ...]} (request validation) and, from the ValueError handler,
// {"error": ..., "detail": "text"}.
export function parseDetail(body: unknown, fallback: string): Detail {
  const out: Detail = { code: '', message: '', finding: '', remedy: '', extra: {} };
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
    // `finding` is what the server found (a refusal that is a finding, not a fault, e.g.
    // anchor_contradicts_ledger); it is the message when there is no `detail` text.
    if (typeof o.finding === 'string') out.finding = o.finding;
    if (typeof o.remedy === 'string') out.remedy = o.remedy;
    out.extra = o;
  }
  if (!out.message && out.finding) out.message = out.finding;
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
      return {
        kind: 'forbidden',
        status,
        message: d.remedy ? `${d.message} ${d.remedy}`.trim() : d.message,
        code: d.code,
      };
    case 404:
      return { kind: 'notfound', status, message: d.message };
    case 409:
      return {
        kind: 'conflict',
        status,
        message: d.remedy ? `${d.message} ${d.remedy}`.trim() : d.message || 'The case is not in a state that allows that.',
        code: d.code || undefined,
        finding: d.finding || undefined,
        remedy: d.remedy || undefined,
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
      if (outcome.code === 'anchor_contradicts_ledger') {
        // A finding, not a fault: a signature the service made over this very ledger no
        // longer matches it. The advice to keep the evidence travels with the refusal.
        return {
          kind: outcome.kind,
          heading: 'The export contradicts a signed ledger head (409)',
          text: outcome.finding || outcome.message,
          remedy:
            outcome.remedy ||
            'Keep the ledger and its attestation log exactly as they are: the service signed what this ledger held, and it no longer matches. Do not repair or re-create either until this is explained.',
        };
      }
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

// ---------------------------------------------------------------------------
// Operators (src/assurance/api/operator_routes.py)
// ---------------------------------------------------------------------------

export type Operator = {
  id: string;
  name: string;
  role: 'contributor' | 'decider' | string;
  created_at?: string;
  created_by?: string;
  disabled: boolean;
  disabled_at?: string | null;
};

export type OperatorList = { operators: Operator[]; you: { operator_id: string | null; role: string } };

// POST /v1/operators — `api_key` is shown once and is never requested again.
export type CreatedOperator = { operator_id: string; name: string; role: string; api_key: string; note: string };

// The refusals a case action can meet, each with what the person can do about it. Matched on the
// server's own error code; the server's wording follows, not replaced.
const FORBIDDEN_ACTIONS: Record<string, string> = {
  operator_required:
    'This step is a human decision and needs a key issued to an individual operator with the decider role. An account key cannot make it. Create an operator below (if the account has none) or paste that operator\u2019s key as the decision credential.',
  decider_role_required:
    'The key you used belongs to an operator who is not a decider. Use a decider operator\u2019s key, or ask an existing decider to create one for you.',
  actor_mismatch:
    'The name sent does not match the operator this key was issued to. An action is attributed to the credential that made it; use that operator\u2019s own key and do not type a different name.',
  account_required: 'This credential is not tied to a customer account, so it has no operators.',
};

export function explainForbidden(outcome: Extract<ApiOutcome<unknown>, { kind: 'forbidden' }>): string {
  return (outcome.code && FORBIDDEN_ACTIONS[outcome.code]) || '';
}

// What a ledger actor's role string says about how the name was established. The role string
// is sealed with the entry: `... attribution=authenticated_operator` (a credential bound to a
// named operator was presented), `declared_by_account_key` (the account key holder typed the
// name) or `declared_open_mode` (no accounts configured). Anything else, including entries
// written before attribution was recorded, is reported as not recorded and never upgraded.
export type Attribution = {
  basis: 'authenticated_operator' | 'declared_by_account_key' | 'declared_open_mode' | 'not_recorded';
  label: string;
};

export function parseAttribution(role: string | undefined): Attribution {
  const m = /attribution=([a-z_]+)/.exec(role || '');
  switch (m?.[1]) {
    case 'authenticated_operator':
      return { basis: 'authenticated_operator', label: 'operator credential presented (not identity proof)' };
    case 'declared_by_account_key':
      return { basis: 'declared_by_account_key', label: 'name declared by the holder of an account key (not authenticated)' };
    case 'declared_open_mode':
      return { basis: 'declared_open_mode', label: 'name declared, server in open mode (not authenticated)' };
    default:
      return { basis: 'not_recorded', label: 'attribution not recorded' };
  }
}

// ---------------------------------------------------------------------------
// Supplier trust (src/assurance/api/supplier_routes.py, supplier/trust.py)
// ---------------------------------------------------------------------------

export type KeyPin = {
  supplier_id: string;
  fingerprint: string;
  status: string;
  effective_from: string;
  retired_at: string;
  revoked_at: string;
  pinned_by: string;
  obtained_via: string;
  pinned_at: string;
  reason: string;
};

export type SupplierTrust = {
  pins: KeyPin[];
  history: Record<string, unknown>[];
  overrides: { supplier_id: string; advisory_id: string; advisory_hash: string; actor: string; reason: string; at: string }[];
  integrity_problems: string[];
  trust_statement: string;
};

export type RecordTrust = {
  sequence: number;
  advisory_id: string;
  is_withdrawal: boolean;
  key_fingerprint: string;
  signature: string;
  key_trust: string;
  authentic: boolean;
  signature_valid_under_candidate: boolean | null;
};

export type TrustedAdvisoryRow = {
  advisory_id: string;
  supplier_id: string;
  sequence: number;
  severity: string;
  title: string;
  advisory_hash: string;
  record_authentic: boolean;
  trust_basis: string;
  automated_consequences_permitted: boolean;
  override: { actor: string; reason: string; at: string; advisory_hash: string } | null;
  override_refused: string;
  implications_reviewed: boolean;
  case_opened: string;
  evaluated_at: string;
  // Set by the server for an advisory that is an unsigned import found inside a signed feed: the
  // signature is over the supplier's file, the file says it is a translation nobody has
  // authenticated, so no consequence is permitted whatever the pinned key says.
  inspect_only?: boolean;
  advisory_import?: AdvisoryImportRecord | null;
};

export type FeedTrust = {
  trust_state: string;
  policy_satisfied: boolean;
  inspect_only: boolean;
  structurally_readable: boolean;
  record_count: number;
  signature_state: string;
  key_trust_state: string;
  chain_valid: boolean;
  chain_problems: string[];
  duplicate_advisories: string[];
  conflicting_advisories: string[];
  supplier_id: string;
  key_fingerprints: string[];
  records: RecordTrust[];
  advisories: TrustedAdvisoryRow[];
  withdrawn: string[];
  unauthenticated_withdrawals: string[];
  problems: string[];
  trust_statement: string;
};

// POST /v1/fleet/advisory/signed
export type SignedImpactResult = {
  trust: FeedTrust;
  advisories: (TrustedAdvisoryRow & { impact: ImpactReport | null; error?: string })[];
  inspect_only: boolean;
  trust_statement: string;
};
