'use client';

import { judge, type ChainState, type Completeness, type LedgerVerifyResponse } from '../../lib/ledgerVerifyApi';

const CHAIN_HEAD: Record<ChainState, string> = {
  intact: 'links agree',
  broken: 'BROKEN',
  unknown: 'not stated',
};

const CHAIN_TEXT: Record<ChainState, string> = {
  intact: 'Every record present links to the one before it. This does not show that nothing was removed.',
  broken: 'The records do not agree with each other. Treat everything in this ledger as in question.',
  unknown: 'The server did not state a chain result.',
};

const COMPLETENESS_HEAD: Record<Completeness, string> = {
  complete: 'complete up to the signed anchor',
  incomplete: 'INCOMPLETE — the signed anchor contradicts this ledger',
  unanchored: 'unanchored — not established',
  unchecked: 'unchecked — not compared',
};

const COMPLETENESS_TEXT: Record<Completeness, string> = {
  complete:
    'The ledger is at least as long as, and agrees with, a head the service signed. Records added after that head are not covered by it.',
  incomplete:
    'Records were removed from the end, or the ledger was replaced: the head the service signed is not in this ledger. Do not rely on this ledger until that is explained.',
  unanchored:
    'There is no signed anchor for this ledger, so a deletion from the end cannot be detected. This is not a pass.',
  unchecked: 'Nothing is concluded about completeness.',
};

function Hash({ value, testid, absent = 'not stated' }: { value: string | undefined | null; testid: string; absent?: string }) {
  return value ? (
    <code data-testid={testid} style={{ overflowWrap: 'anywhere' }}>
      {value}
    </code>
  ) : (
    <span data-testid={testid}>{absent}</span>
  );
}

// Presents GET /v1/ledger/verify. The server's own words (problems, not_checked, anchor_meaning)
// are shown unedited. Colour is never the only signal: every state has a heading in words.
export default function LedgerVerifyView({ data, tier }: { data: LedgerVerifyResponse; tier: string | null }) {
  const v = judge(data);
  const a = data.anchor;
  const att = data.attestation;
  const problems = Array.isArray(data.problems) ? data.problems : [];
  const notChecked = Array.isArray(data.not_checked) ? data.not_checked : [];
  const count = att && typeof att.length === 'number' ? att.length : null;
  const loud = v.completeness === 'incomplete' || v.chain === 'broken';
  return (
    <div data-testid="lv-result" data-chain={v.chain} data-completeness={v.completeness}>
      {loud && (
        <p className="aw-alert" role="alert" data-testid="lv-alert">
          <strong>
            {v.completeness === 'incomplete'
              ? 'LEDGER INCOMPLETE — records removed past the signed anchor, or the ledger was replaced.'
              : 'LEDGER CHAIN DOES NOT VERIFY.'}
          </strong>
          {problems.length ? ` First problem: ${problems[0]}` : ''}
        </p>
      )}
      <h3 data-testid="lv-chain" data-state={v.chain} className={v.chain === 'broken' ? 'aw-bad' : undefined}>
        Chain integrity: {CHAIN_HEAD[v.chain]}
      </h3>
      <p>{CHAIN_TEXT[v.chain]}</p>
      <h3
        data-testid="lv-completeness"
        data-state={v.completeness}
        className={v.completeness === 'incomplete' ? 'aw-bad' : undefined}
      >
        Completeness: {COMPLETENESS_HEAD[v.completeness]}
      </h3>
      <p data-testid="lv-completeness-text">{COMPLETENESS_TEXT[v.completeness]}</p>
      {v.inconsistency && (
        <p className="aw-note" data-testid="lv-inconsistency">
          {v.inconsistency}
        </p>
      )}
      {v.completeness === 'complete' && (
        <p className="aw-note" data-testid="lv-uncovered">
          {v.uncoveredAfterAnchor === null
            ? 'How many records follow the anchor is not stated; those are not covered by it.'
            : `${v.uncoveredAfterAnchor} record(s) follow the anchor and are not covered by it.`}
        </p>
      )}
      {problems.length > 0 && (
        <>
          <h3>Problems reported</h3>
          <ul data-testid="lv-problems">
            {problems.map((p, i) => (
              <li key={`${i}-${p}`}>{p}</li>
            ))}
          </ul>
        </>
      )}
      <dl className="aw-kv">
        <dt>Ledger id</dt>
        <dd>
          <Hash value={data.ledger_id} testid="lv-ledger-id" />
        </dd>
        <dt>Entries</dt>
        <dd data-testid="lv-entries">{count === null ? 'not stated' : count === 0 ? '0 (empty ledger)' : count}</dd>
        <dt>Head hash</dt>
        <dd>
          <Hash value={att?.head_link_hash} testid="lv-head-hash" />
          {count === 0 && <span className="aw-note"> (the empty-ledger start value; no record exists yet)</span>}
        </dd>
        <dt>Anchor fingerprint</dt>
        <dd>
          <Hash value={a?.key_fingerprint} testid="lv-anchor-fingerprint" absent="none — no anchor was used" />
        </dd>
        <dt>Tier</dt>
        <dd data-testid="lv-tier">{tier ?? 'not loaded'}</dd>
      </dl>
      {a && (
        <dl className="aw-kv" data-testid="lv-anchor">
          <dt>Anchor signed at</dt>
          <dd>{a.attested_at}</dd>
          <dt>Anchor covers</dt>
          <dd>
            {a.ledger_length} record(s), head hash <Hash value={a.head_link_hash} testid="lv-anchor-head" />
          </dd>
          <dt>Anchor basis</dt>
          <dd>{a.basis}</dd>
        </dl>
      )}
      {notChecked.length > 0 && (
        <>
          <h3>Not established</h3>
          <ul data-testid="lv-not-checked">
            {notChecked.map((s, i) => (
              <li key={`${i}-${s}`}>{s}</li>
            ))}
          </ul>
        </>
      )}
      {data.anchor_meaning && (
        <p className="aw-note" data-testid="lv-anchor-meaning">
          {data.anchor_meaning}
        </p>
      )}
      {data.note && <p className="aw-note">{data.note}</p>}
    </div>
  );
}
