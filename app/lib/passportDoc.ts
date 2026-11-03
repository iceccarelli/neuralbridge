// Machine passport: the shapes of POST /v1/machinery/passport/check and of a passport file, and
// the pure functions that read them. No imports, so tests can run this file under node.

/** POST /v1/machinery/passport/check. No ledger is supplied over HTTP, so `checked.against_ledger`
 *  is false and the records the passport names are not looked at. `problems` carries both
 *  findings and "NOT CHECKED: ..." limitations; see `splitCheckFindings`. */
export type PassportCheck = {
  ok: boolean;
  problems: string[];
  checked: { seal: boolean; internal_consistency: boolean; against_ledger: boolean };
  machine?: Record<string, unknown> | null;
  recorded_verdict?: string | null;
  configuration_hash?: string | null;
  functions_not_current?: { function_id?: string | null; coverage?: string | null }[];
};

/** The server marks a limitation of its check (something it did not look at) with this prefix. */
export const NOT_CHECKED_PREFIX = 'NOT CHECKED';

/** Findings (the file contradicts itself) apart from limitations (the check did not look). */
export function splitCheckFindings(problems: string[]): { findings: string[]; limitations: string[] } {
  const findings: string[] = [];
  const limitations: string[] = [];
  for (const p of problems) (p.startsWith(NOT_CHECKED_PREFIX) ? limitations : findings).push(p);
  return { findings, limitations };
}

export type PassportFunction = {
  function_id: string;
  description: string | null;
  required_performance: string | null;
  coverage: string | null;
  detail: string | null;
  last_verified_hash: string | null;
  last_verified_at: string | null;
  invalidated_by: string | null;
  evidence_tier: string | null;
};

/** What a passport file states. A field the file does not carry is `null`, never an empty
 *  string, `0` or `false`. */
export type PassportDoc = {
  schema: string;
  content_hash: string | null;
  kind: string | null;
  machine: Record<string, string | null>;
  manifest_id: string | null;
  manifest_hash: string | null;
  configuration_hash: string | null;
  verdict: string | null;
  coverage_verdict: string | null;
  evidence_tier_floor: string | null;
  ledger_chain_verified: boolean | null;
  ledger_head: Record<string, unknown> | null;
  assessed_at: string | null;
  recorded_at: string | null;
  validation_state: string | null;
  confidence: string | null;
  actor: { identifier: string | null; role: string | null; kind: string | null } | null;
  origin: { system: string | null; reference: string | null; method: string | null } | null;
  functions: PassportFunction[];
  intervention_ids: string[] | null;
  verification_hashes: string[] | null;
  checks_skipped: string[];
};

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
// The producer writes "" for "none"; that is no value, not a value.
const nonEmpty = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);
const strList = (v: unknown): string[] | null => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : null);

export const PASSPORT_SCHEMAS = ['assurance.machinery.passport/1', 'assurance.machinery.passport/2'];

/** Read a passport file. Returns a reason instead of a document when it is not one. This reads
 *  what the file says; whether the file is coherent is the server's check, not this function. */
export function readPassport(raw: unknown): { ok: true; doc: PassportDoc } | { ok: false; reason: string } {
  if (!isObj(raw)) return { ok: false, reason: 'A passport is one JSON object.' };
  if (typeof raw.schema !== 'string' || !PASSPORT_SCHEMAS.includes(raw.schema)) {
    const shown = typeof raw.schema === 'string' ? `“${raw.schema.slice(0, 80)}”` : 'not stated';
    return { ok: false, reason: `This is not a machine passport: its schema is ${shown}, and a passport states ${PASSPORT_SCHEMAS.join(' or ')}.` };
  }
  const ev = raw.evidence;
  if (!isObj(ev) || !isObj(ev.body)) return { ok: false, reason: 'This passport has no sealed evidence block to read.' };
  const b = ev.body;
  const machine: Record<string, string | null> = {};
  if (isObj(b.machine)) for (const [k, v] of Object.entries(b.machine)) machine[k] = nonEmpty(v);
  const actor = isObj(ev.actor) ? { identifier: str(ev.actor.identifier), role: nonEmpty(ev.actor.role), kind: str(ev.actor.kind) } : null;
  const origin = isObj(ev.origin) ? { system: str(ev.origin.system), reference: nonEmpty(ev.origin.reference), method: nonEmpty(ev.origin.method) } : null;
  const functions: PassportFunction[] = Array.isArray(b.functions)
    ? b.functions.filter(isObj).map((f) => ({
        function_id: str(f.function_id) ?? 'unnamed function',
        description: nonEmpty(f.description),
        required_performance: nonEmpty(f.required_performance),
        coverage: str(f.coverage),
        detail: nonEmpty(f.detail),
        last_verified_hash: nonEmpty(f.last_verified_hash),
        last_verified_at: nonEmpty(f.last_verified_at),
        invalidated_by: nonEmpty(f.invalidated_by),
        evidence_tier: nonEmpty(f.evidence_tier),
      }))
    : [];
  return {
    ok: true,
    doc: {
      schema: raw.schema,
      content_hash: str(ev.content_hash),
      kind: str(ev.kind),
      machine,
      manifest_id: str(b.manifest_id),
      manifest_hash: str(b.manifest_hash),
      configuration_hash: str(b.configuration_hash),
      verdict: str(b.verdict),
      coverage_verdict: str(b.coverage_verdict),
      evidence_tier_floor: nonEmpty(b.evidence_tier_floor),
      ledger_chain_verified: typeof b.ledger_chain_verified === 'boolean' ? b.ledger_chain_verified : null,
      ledger_head: isObj(b.ledger_head) && Object.keys(b.ledger_head).length > 0 ? b.ledger_head : null,
      assessed_at: str(b.assessed_at),
      recorded_at: str(ev.recorded_at),
      validation_state: str(ev.validation_state),
      confidence: str(ev.confidence),
      actor,
      origin,
      functions,
      intervention_ids: strList(b.intervention_ids),
      verification_hashes: strList(b.verification_hashes),
      checks_skipped: strList(ev.checks_skipped) ?? [],
    },
  };
}

export type PassportGap = { id: string; text: string; source: 'passport' | 'check' | 'derived' };

/** Everything this passport leaves unchecked, in one list, with where each item came from:
 *  the producer's own `checks_skipped` (sealed in the file), the limitations the server's check
 *  reports, and gaps read off the file's own fields (function states, absent evidence). `check`
 *  is null when the check has not answered; that is itself a gap. */
export function passportGaps(doc: PassportDoc, check: PassportCheck | null): PassportGap[] {
  const gaps: PassportGap[] = [];
  if (check === null) {
    gaps.push({ id: 'check-not-run', source: 'derived', text: 'The seal and internal-consistency check has not answered, so nothing in this file has been checked.' });
  } else {
    if (!check.checked.against_ledger) {
      gaps.push({
        id: 'not-against-ledger',
        source: 'check',
        text: 'NOT CHECKED: the records this passport names (verifications, interventions, the ledger chain) were not looked up. No ledger is supplied over HTTP; the offline command `assurance machinery check <passport> --ledger <register.db>` does that.',
      });
    }
    splitCheckFindings(check.problems).limitations.forEach((t, i) => gaps.push({ id: `limit-${i}`, source: 'check', text: t }));
  }
  doc.checks_skipped.forEach((t, i) => gaps.push({ id: `skipped-${i}`, source: 'passport', text: t }));
  for (const f of doc.functions) {
    if (f.coverage !== 'current') {
      gaps.push({ id: `fn-${f.function_id}`, source: 'derived', text: `${f.function_id}: coverage is ${f.coverage ?? 'not stated'}${f.detail ? `. ${f.detail}` : '.'}` });
    }
  }
  if (doc.functions.length === 0) gaps.push({ id: 'no-functions', source: 'derived', text: 'The passport lists no safety functions, so it asserts nothing about any.' });
  if (doc.verification_hashes === null) gaps.push({ id: 'no-vf-field', source: 'derived', text: 'The passport does not say which verifications it rests on.' });
  else if (doc.verification_hashes.length === 0) gaps.push({ id: 'no-vf', source: 'derived', text: 'No verification is named: the evidence this passport rests on is empty.' });
  if (doc.evidence_tier_floor === null) gaps.push({ id: 'no-tier', source: 'derived', text: 'No evidence tier is stated, so what grade of evidence it rests on is not known from the file.' });
  if (doc.ledger_chain_verified === false) gaps.push({ id: 'chain', source: 'derived', text: 'The passport records that the ledger chain did not verify when it was produced. Nothing in it is covered.' });
  else if (doc.ledger_chain_verified === null) gaps.push({ id: 'chain-unstated', source: 'derived', text: 'The passport does not state whether the ledger chain verified.' });
  return gaps;
}
