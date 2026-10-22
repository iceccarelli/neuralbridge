'use client';

import type { CSSProperties } from 'react';
import type { ImpactReport, MachineClassification } from '../../lib/assuranceApi';

// What an advisory means for one machine, by the evidence it rests on. Every state carries its
// words; colour is never the only signal. Nothing here is green: "no match found" rests on the
// manifest being complete, and "unknown" and "contradictory" are findings that need a person.
const CLASS: Record<string, { label: string; style: CSSProperties; note: string }> = {
  match_by_hash: {
    label: 'MATCH BY HASH',
    style: {
      borderLeft: '6px solid var(--danger)',
      background: 'var(--surface-alt)',
    },
    note: 'the artefact on the machine is byte-identical to one the supplier named',
  },
  match_by_version_only: {
    label: 'MATCH BY VERSION LABEL ONLY',
    style: {
      borderLeft: '6px solid var(--orange)',
      background: 'var(--surface-alt)',
    },
    note: 'a label match is not an artefact match',
  },
  possible_match_name_only: {
    label: 'POSSIBLE MATCH — NAME ONLY',
    style: {
      borderLeft: '6px dotted var(--orange)',
      background: 'var(--surface-alt)',
    },
    note: 'the component name matches; the version is unknown or not listed',
  },
  contradictory_label_vs_hash: {
    label: 'CONTRADICTORY — LABEL VS HASH',
    style: {
      borderLeft: '6px double var(--danger)',
      outline: '1px dashed var(--danger)',
      background: 'var(--surface-alt)',
    },
    note: 'neither affected nor cleared: the label matches and the supplier’s own hashes do not',
  },
  unknown: {
    label: 'UNKNOWN — CANNOT BE CLEARED',
    style: {
      borderLeft: '6px dashed var(--ink-soft)',
      outline: '1px dashed var(--ink-soft)',
      background: 'var(--surface-alt)',
    },
    note: 'something stands in the way of assessing this machine; it is not cleared',
  },
  no_match_found: {
    label: 'NO MATCH FOUND',
    style: {
      borderLeft: '6px solid var(--border)',
      background: 'var(--surface)',
    },
    note: 'rests on the manifest being complete: it says nothing about what the machine actually runs',
  },
};

export function ClassificationBadge({ c }: { c: string }) {
  const k = CLASS[c];
  return (
    <strong
      data-testid="classification-badge"
      data-classification={c}
      style={{
        display: 'inline-block',
        padding: '0.1rem 0.5rem',
        ...(k?.style ?? { border: '1px dashed var(--ink-soft)' }),
      }}
    >
      {k ? k.label : `UNRECOGNISED CLASSIFICATION (${c}) — treat as unknown`}
    </strong>
  );
}

export function ClassificationTable({ report }: { report: ImpactReport }) {
  const rows: MachineClassification[] | undefined = report.machine_classification;
  const unknownMachines = report.unknown_machines;
  const unknownFns = report.unknown_functions;
  const prior = report.prior_evidence_in_question;
  if (!rows) {
    // An older server: say what is missing rather than imply that nothing is unknown.
    return (
      <p className="aw-note" data-testid="classification-missing">
        This server did not return a per-machine classification, so which machines are unknown or contradictory is not
        shown here. Do not read the absence of that list as nothing being unknown.
      </p>
    );
  }
  return (
    <div data-testid="classification">
      <h4>Per machine: what this advisory means for it</h4>
      {rows.length === 0 ? (
        <p className="aw-note">No machine was classified: no machine is enrolled in this ledger.</p>
      ) : (
        <div className="aw-scroll">
          <table className="aw-table" data-testid="classification-table">
            <thead>
              <tr>
                <th>Machine</th>
                <th>Classification</th>
                <th>Basis and uncertainty</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((m) => (
                <tr
                  key={m.machine}
                  data-testid="classification-row"
                  data-machine={m.machine}
                  data-classification={m.classification}
                >
                  <td>
                    {m.machine}
                    <br />
                    <span className="aw-note">{m.site || 'site not recorded'}</span>
                  </td>
                  <td>
                    <ClassificationBadge c={m.classification} />
                    <br />
                    <span className="aw-note">{CLASS[m.classification]?.note ?? ''}</span>
                  </td>
                  <td>
                    {m.basis ? (
                      <>
                        basis: <code>{m.basis}</code>
                        <br />
                      </>
                    ) : (
                      'no matching basis'
                    )}
                    <span data-testid="classification-uncertainty">{m.uncertainty}</span>
                    {m.item_ids.length > 0 && (
                      <>
                        <br />
                        <span className="aw-note">items: {m.item_ids.join(', ')}</span>
                      </>
                    )}
                    {m.unknown_reasons.length > 0 && (
                      <ul>
                        {m.unknown_reasons.map((r) => (
                          <li key={r}>{r}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div data-testid="unknowns" className="aw-prov">
        <p>
          <strong>Unknown machines ({unknownMachines?.length ?? 'not reported'}):</strong>{' '}
          {unknownMachines && unknownMachines.length > 0
            ? unknownMachines.join(', ')
            : unknownMachines
              ? 'none listed'
              : 'the server did not say'}
        </p>
        <p>
          <strong>Unknown safety functions ({unknownFns?.length ?? 'not reported'}):</strong>{' '}
          {unknownFns && unknownFns.length > 0
            ? unknownFns
                .map((f) => `${f.machine ?? '?'}/${f.function_id ?? '?'}${f.reason ? ` (${f.reason})` : ''}`)
                .join('; ')
            : unknownFns
              ? 'none listed'
              : 'the server did not say'}
        </p>
        <p>
          <strong>Prior evidence in question ({prior?.length ?? 'not reported'}):</strong>{' '}
          {prior && prior.length > 0
            ? `${prior.length} piece(s) of earlier verification evidence now rest on a component this advisory names; each needs a person to re-check it.`
            : prior
              ? 'none listed'
              : 'the server did not say'}
        </p>
        <p data-testid="clear-is-complete" data-value={String(report.clear_is_complete)}>
          <strong>clear_is_complete: {String(report.clear_is_complete)}.</strong>{' '}
          {report.clear_is_complete === true
            ? 'The server says a clear verdict covers every enrolled machine and declared function in this assessment. It is still only a match against the latest sealed manifests.'
            : 'A clear verdict, if shown, does not cover the unknown machines and functions above, or the server did not say that it does.'}
        </p>
      </div>
    </div>
  );
}
