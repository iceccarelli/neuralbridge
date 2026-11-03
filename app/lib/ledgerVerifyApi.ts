// GET /v1/ledger/verify — the evidence chain check plus completeness against the service's own
// signed anchor. Nothing here calls the network: `usePanel` sends the request (through `call()`,
// which carries the key as a header); this module only says what the answer means.
//
// The server reports two separate facts and this module keeps them separate:
//   chain         `verified` / `problems`: every record present links to the one before it.
//   completeness  `completeness` / `anchor`: whether anything was removed from the END, which a
//                 hash chain alone cannot show. Only a signed head from outside the ledger can.
// A chain that links up is NOT a complete ledger. "unchecked" is a valid, common answer.

export const LEDGER_VERIFY_PATH = '/v1/ledger/verify';

export type LedgerAnchor = {
  sequence: number;
  attested_at: string;
  ledger_length: number;
  head_seq: number;
  head_link_hash: string;
  key_fingerprint: string;
  basis: string;
};

export type LedgerVerifyResponse = {
  verified: boolean;
  problems: string[];
  completeness: string;
  not_checked: string[];
  ledger_id: string;
  anchor: LedgerAnchor | null;
  anchor_meaning: string;
  attestation: {
    ledger_schema_version?: number;
    length: number;
    head_seq: number;
    head_link_hash: string;
    attested_at: string;
  };
  note?: string;
};

export type ChainState = 'intact' | 'broken' | 'unknown';
// complete    : chain links AND the ledger agrees with a signed anchor (nothing before it is missing)
// incomplete  : the signed anchor CONTRADICTS the ledger — records removed, or the ledger replaced
// unanchored  : chain links, but there is no signed anchor to compare with; completeness unknown
// unchecked   : completeness was not compared, or the answer is malformed / self-contradictory
export type Completeness = 'complete' | 'incomplete' | 'unanchored' | 'unchecked';

export type LedgerVerdict = {
  chain: ChainState;
  completeness: Completeness;
  // Why the state is `unchecked`, when the page itself (not the server) had to decline to conclude.
  inconsistency: string;
  // Records appended after the anchor was signed (not covered by it); null when not stated.
  uncoveredAfterAnchor: number | null;
};

const isStr = (v: unknown): v is string => typeof v === 'string';
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

function wellFormed(d: Partial<LedgerVerifyResponse> | null | undefined): d is LedgerVerifyResponse {
  return (
    !!d &&
    typeof d.verified === 'boolean' &&
    Array.isArray(d.problems) &&
    isStr(d.completeness) &&
    Array.isArray(d.not_checked)
  );
}

function verdict(
  chain: ChainState,
  completeness: Completeness,
  inconsistency = '',
  uncoveredAfterAnchor: number | null = null,
): LedgerVerdict {
  return { chain, completeness, inconsistency, uncoveredAfterAnchor };
}

// Decide what the answer says. Anything the page cannot establish is `unchecked`; nothing is ever
// upgraded. The server's flags are cross-checked: `verified: true` with problems listed is not
// trusted, and a "checked" completeness without a stated anchor is not trusted.
export function judge(d: Partial<LedgerVerifyResponse> | null | undefined): LedgerVerdict {
  if (!wellFormed(d)) {
    return verdict('unknown', 'unchecked', 'The answer is missing fields this page needs, so nothing is concluded from it.');
  }
  const chain: ChainState = d.verified && d.problems.length === 0 ? 'intact' : 'broken';

  if (d.completeness === 'contradicted_by_anchor') {
    // Loud whatever else the response says: the signed head is not in this ledger.
    return verdict(chain, 'incomplete');
  }
  if (chain === 'broken') return verdict(chain, 'unchecked');

  if (d.completeness === 'checked_against_anchor') {
    const a = d.anchor;
    if (!a || !isStr(a.key_fingerprint) || !a.key_fingerprint || !isNum(a.ledger_length)) {
      return verdict(chain, 'unchecked', 'The answer says completeness was checked but does not name the anchor it used.');
    }
    const len = d.attestation?.length;
    if (isNum(len) && len < a.ledger_length) {
      return verdict(chain, 'unchecked', 'The ledger is reported shorter than its anchor yet not contradicted; not trusted.');
    }
    return verdict(chain, 'complete', '', isNum(len) ? len - a.ledger_length : null);
  }
  if (d.completeness === 'not_checked') {
    if (d.anchor) return verdict(chain, 'unchecked', 'An anchor is named but the answer says it was not compared.');
    return verdict(chain, 'unanchored');
  }
  return verdict(chain, 'unchecked', `Unrecognised completeness value "${d.completeness}"; nothing is concluded from it.`);
}
