// Reading an advisory, a signed advisory record or a supplier feed into records the
// workspace can show. This reads STRUCTURE only. It does not, and cannot, verify a
// signature: that needs the supplier's public key, which neither this page nor the hosted
// API holds. Whatever a file says about its own signer is reported as "claimed".

export type SignedClaims = {
  format: string;
  sequence: number | null;
  supplierId: string;
  legalName: string;
  keyContact: string;
  keyFingerprint: string;
  publishedAt: string;
  previous: string;
  hasSignature: boolean;
};

export type ParsedRecord = {
  index: number;
  advisory: Record<string, unknown>;
  advisoryId: string;
  title: string;
  severity: string;
  issuedBy: string;
  claims: SignedClaims | null;
  /** This record is a withdrawal of an earlier advisory (as the file says). */
  isWithdrawal: boolean;
  withdraws: string;
  withdrawalReason: string;
  /** A later record in the same file withdraws this advisory id (as the file says). */
  withdrawnLater: boolean;
};

export type ParsedInput =
  | { ok: true; shape: 'bare' | 'signed-record' | 'feed'; records: ParsedRecord[] }
  | { ok: false; error: string };

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === 'string' ? v : '');

function fromObject(o: Record<string, unknown>, index: number): ParsedRecord | string {
  const signed = isObj(o.advisory) && ('signature' in o || 'key_fingerprint' in o || 'supplier' in o || 'format' in o);
  const adv = signed ? (o.advisory as Record<string, unknown>) : o;
  if (!isObj(adv) || typeof adv.advisory_id !== 'string' || !adv.advisory_id) {
    return `Record ${index + 1} has no advisory_id, so it is not a component advisory.`;
  }
  let claims: SignedClaims | null = null;
  if (signed) {
    const sup = isObj(o.supplier) ? o.supplier : {};
    claims = {
      format: str(o.format),
      sequence: typeof o.sequence === 'number' ? o.sequence : null,
      supplierId: str(sup.supplier_id),
      legalName: str(sup.legal_name),
      keyContact: str(sup.key_contact),
      keyFingerprint: str(o.key_fingerprint),
      publishedAt: str(o.published_at),
      previous: str(o.previous),
      hasSignature: typeof o.signature === 'string' && o.signature.length > 0,
    };
  }
  const withdraws = signed ? str(o.withdraws) : '';
  return {
    index,
    advisory: adv,
    advisoryId: adv.advisory_id,
    title: str(adv.title),
    severity: str(adv.severity),
    issuedBy: str(adv.issued_by),
    claims,
    isWithdrawal: withdraws !== '',
    withdraws,
    withdrawalReason: signed ? str(o.withdrawal_reason) : '',
    withdrawnLater: false,
  };
}

export function parseAdvisoryInput(text: string): ParsedInput {
  const t = text.trim();
  if (!t) return { ok: false, error: 'Nothing to read: paste an advisory or a feed, or choose a file.' };

  let items: unknown[];
  let multi = false;
  try {
    const whole = JSON.parse(t);
    if (Array.isArray(whole)) {
      items = whole;
      multi = true;
    } else {
      items = [whole];
    }
  } catch {
    // Not one JSON value: a feed is one JSON record per line.
    items = [];
    multi = true;
    const lines = t.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        items.push(JSON.parse(line));
      } catch (e) {
        return {
          ok: false,
          error: `The input is not JSON, and line ${i + 1} is not JSON either (${(e as Error).message}). A feed is one JSON record per line; an advisory is one JSON object. It could not be read.`,
        };
      }
    }
  }
  if (items.length === 0) return { ok: false, error: 'The input held no records.' };

  const records: ParsedRecord[] = [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!isObj(item)) return { ok: false, error: `Record ${i + 1} is not a JSON object, so it could not be read.` };
    const r = fromObject(item, i);
    if (typeof r === 'string') return { ok: false, error: r };
    records.push(r);
  }
  for (const r of records) {
    if (r.isWithdrawal) continue;
    r.withdrawnLater = records.some((w) => w.isWithdrawal && w.withdraws === r.advisoryId && w.index > r.index);
  }
  const anySigned = records.some((r) => r.claims);
  return { ok: true, shape: anySigned ? (multi ? 'feed' : 'signed-record') : 'bare', records };
}
