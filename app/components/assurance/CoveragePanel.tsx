'use client';

import {
  describeOutcome,
  type AttestLog,
  type CaseQueue,
  type Fleet,
  type Value,
} from '../../lib/assuranceApi';
import { computeCoverage, type Source } from '../../lib/coverage';
import CoverageView from './CoverageView';
import { PanelFrame } from './PanelFrame';
import { usePanel, type Panel } from './usePanel';

// A source feeds the report only while its latest answer is a good one. A refusal, an error or a
// request still in flight makes the cells it feeds UNKNOWN; last-good data is not reused here.
function sourceOf<T>(p: Panel<T>): Source<T> {
  const o = p.outcome;
  if (o === null) return { status: 'loading' };
  if (o.kind === 'ok') return { status: 'ok', data: o.data };
  const d = describeOutcome(o);
  return { status: 'unavailable', reason: `${d.heading}. ${d.text}` };
}

// Coverage of the fleet by evidence, verification, intel match and attested anchor. It composes
// four existing reads (GET /v1/fleet/machines, /v1/value, /v1/change/cases, /v1/ledger/attest/log)
// and adds no endpoint. Every denominator is shown, and what the records or the sources do not
// say is UNKNOWN, never zero and never covered.
export default function CoveragePanel({
  apiKey,
  fleet,
  queue,
}: {
  apiKey: string;
  fleet: Panel<Fleet>;
  queue: Panel<CaseQueue>;
}) {
  const value = usePanel<Value>(apiKey, '/v1/value');
  const attest = usePanel<AttestLog>(apiKey, '/v1/ledger/attest/log');
  const sources = [
    { name: 'Fleet', path: '/v1/fleet/machines', src: sourceOf(fleet) },
    { name: 'Position', path: '/v1/value', src: sourceOf(value) },
    { name: 'Cases', path: '/v1/change/cases', src: sourceOf(queue) },
    { name: 'Attestation log', path: '/v1/ledger/attest/log', src: sourceOf(attest) },
  ];

  return (
    <PanelFrame id="aw-coverage" title="Coverage" what="coverage" apiKey={apiKey} panel={fleet}>
      {(data) => {
        const report = computeCoverage({
          fleet: data,
          value: sourceOf(value),
          cases: sourceOf(queue),
          attest: sourceOf(attest),
        });
        return (
          <>
            <p className="aw-note" data-testid="coverage-intro">
              How much of your fleet the records cover, counted against every machine enrolled in your ledger. What the
              records do not say is shown as UNKNOWN: it is not counted as covered and not as zero. This is a count of
              recorded evidence, not a statement that any machine is safe or compliant.
            </p>
            {!data.chain_verified && (
              <p className="aw-alert" role="alert" data-testid="coverage-chain-broken">
                <strong>THE LEDGER CHAIN DOES NOT VERIFY</strong>: every cell is UNKNOWN.
              </p>
            )}
            <ul className="aw-note" data-testid="coverage-sources">
              {sources.map((s) => (
                <li key={s.path} data-source={s.path} data-status={s.src.status}>
                  <code>{s.path}</code> ({s.name}):{' '}
                  {s.src.status === 'ok'
                    ? 'answered'
                    : s.src.status === 'loading'
                      ? 'loading; the cells it feeds are UNKNOWN until it answers'
                      : `not available; the cells it feeds are UNKNOWN. ${s.src.reason}`}
                </li>
              ))}
            </ul>
            <p>
              <button
                type="button"
                className="aw-reload"
                disabled={value.loading || attest.loading}
                onClick={() => {
                  void fleet.reload();
                  void value.reload();
                  void queue.reload();
                  void attest.reload();
                }}
              >
                Reload every source
              </button>
            </p>
            <CoverageView report={report} />
            <p className="aw-note">
              Intel is the weakest dimension: a match is only recorded when a supplier-advisory case names the machine.
              The operator&apos;s public-source store is not matched against your machines here; see the lookup panel
              for what it records about one CVE. Evidence dates and observations are reported by your own client.
            </p>
          </>
        );
      }}
    </PanelFrame>
  );
}
