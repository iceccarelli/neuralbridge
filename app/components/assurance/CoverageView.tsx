'use client';

import { DIMENSIONS, shareText, type CoverageReport, type Dimension, type State, type Tally } from '../../lib/coverage';

export const DIMENSION_LABEL: Record<Dimension, string> = {
  evidence: 'Evidence: inventory read off the unit',
  verification: 'Verification: safety functions current',
  intel: 'Intel match recorded',
  anchor: 'Attested anchor read by the operator',
};

const STATE_LABEL: Record<State, string> = {
  covered: 'Covered',
  partial: 'Partial',
  none: 'Not covered',
  unknown: 'UNKNOWN',
};

// What "covered" means on each dimension, so a number is never read as more than it is.
const DIMENSION_NOTE: Record<Dimension, string> = {
  evidence: 'Covered: every listed item was hashed off the unit. Items from a vendor file or typed in, or an incomplete collection, are partial.',
  verification:
    'Covered: every declared safety function is current. Current on evidence below validated is partial. No function declared is unknown.',
  intel:
    'Covered: a supplier-advisory case names the machine, so a match is recorded. Every other machine is unknown: the service holds no per-machine "assessed, no match" record, and a machine no source mentions is not clear.',
  anchor:
    'Covered: the machine’s record is at or before a head the operator’s signer read from the ledger. Holder-declared attestations never count. This view does not check the signature.',
};

function StateBadge({ state }: { state: State }) {
  return (
    <strong className={state === 'covered' ? undefined : 'aw-bad'} data-state={state}>
      {STATE_LABEL[state]}
    </strong>
  );
}

function TallyCells({ t }: { t: Tally }) {
  return (
    <>
      <td data-testid="tally-covered">{shareText(t.covered, t.denominator)}</td>
      <td data-testid="tally-partial">{t.partial}</td>
      <td data-testid="tally-none">{t.none}</td>
      <td data-testid="tally-unknown">
        <strong>{t.unknown}</strong>
      </td>
      <td data-testid="tally-denominator">{t.denominator}</td>
    </>
  );
}

function SummaryTable({ title, tally, testid, unit }: { title: string; tally: Record<Dimension, Tally>; testid: string; unit: string }) {
  return (
    <div className="aw-scroll" tabIndex={0} role="region" aria-label="Coverage summary table, scrolls sideways">
      <table className="aw-table" data-testid={testid}>
        <caption className="aw-note">{title}</caption>
        <thead>
          <tr>
            <th>Dimension</th>
            <th>Covered, of all {unit}</th>
            <th>Partial</th>
            <th>Not covered</th>
            <th>Unknown</th>
            <th>All {unit} (denominator)</th>
          </tr>
        </thead>
        <tbody>
          {DIMENSIONS.map((d) => (
            <tr key={d} data-dimension={d}>
              <td>{DIMENSION_LABEL[d]}</td>
              <TallyCells t={tally[d]} />
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function CoverageView({ report }: { report: CoverageReport }) {
  if (report.empty) {
    return (
      <p className="console-empty-note" data-testid="coverage-empty">
        No machine is enrolled in your ledger, so coverage is not defined: 0 of 0 is not a share, and an empty fleet is not
        clear and not covered. Nothing was assessed.
      </p>
    );
  }
  const cfg = report.configurations;
  const order = [...report.machines].sort((a, b) => {
    const gaps = (m: typeof a) => DIMENSIONS.filter((d) => m.cells[d].state !== 'covered').length;
    return gaps(b) - gaps(a) || a.machine.localeCompare(b.machine);
  });
  return (
    <>
      <SummaryTable title="Machines" tally={report.tally} testid="coverage-machines" unit="machines" />
      <SummaryTable title={`Configurations (${cfg.denominator} distinct by hash)`} tally={cfg.tally} testid="coverage-configs" unit="configurations" />
      {cfg.unhashed_machines > 0 && (
        <p className="aw-note" data-testid="coverage-unhashed">
          {cfg.unhashed_machines} machine(s) carry no configuration hash and are not counted in any configuration; they
          are in the machine counts above.
        </p>
      )}
      <p data-testid="coverage-functions">
        {report.functions
          ? `Safety functions current: ${report.functions.current} of ${report.functions.total} declared` +
            (report.functions.machines_without_figures
              ? `; ${report.functions.machines_without_figures} machine(s) have no function figures and are not in that count`
              : '')
          : 'Safety functions current: unknown (the position answer is not available).'}
      </p>
      <ul className="aw-note" data-testid="coverage-definitions">
        {DIMENSIONS.map((d) => (
          <li key={d}>
            <strong>{DIMENSION_LABEL[d]}.</strong> {DIMENSION_NOTE[d]}
          </li>
        ))}
      </ul>
      <h3>Per machine, with the reason for each cell</h3>
      <div className="aw-scroll" tabIndex={0} role="region" aria-label="Coverage per machine, scrolls sideways">
        <table className="aw-table" data-testid="coverage-rows">
          <thead>
            <tr>
              <th>Machine</th>
              {DIMENSIONS.map((d) => (
                <th key={d}>{DIMENSION_LABEL[d]}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {order.map((m) => (
              <tr key={m.machine} data-testid="coverage-row" data-machine={m.machine}>
                <td>
                  {m.machine}
                  {m.site ? <span className="aw-note"> ({m.site})</span> : null}
                </td>
                {DIMENSIONS.map((d) => (
                  <td key={d} data-dimension={d} data-state={m.cells[d].state}>
                    <StateBadge state={m.cells[d].state} />
                    <br />
                    <span className="aw-note">{m.cells[d].reason}</span>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
