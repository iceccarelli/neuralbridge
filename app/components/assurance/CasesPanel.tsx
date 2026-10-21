'use client';

import type { CaseQueue } from '../../lib/assuranceApi';
import { PanelFrame } from './PanelFrame';
import type { Panel } from './usePanel';

export default function CasesPanel({
  apiKey,
  queue,
  selected,
  onOpen,
}: {
  apiKey: string;
  queue: Panel<CaseQueue>;
  selected: string;
  onOpen: (caseId: string) => void;
}) {
  return (
    <PanelFrame id="aw-cases" title="Change-assurance cases" what="the case queue" apiKey={apiKey} panel={queue}>
      {(data) => (
        <>
          <p data-testid="case-summary">
            {data.summary.open} open · {data.summary.safety_relevant} safety-relevant ·{' '}
            {data.summary.awaiting_reverification} awaiting re-verification · {data.summary.ready_to_close} ready for a
            human decision
          </p>
          {data.cases.length === 0 ? (
            <p className="console-empty-note">
              No cases. A case opens when Watch or an assessment finds a change or advisory.
            </p>
          ) : (
            <div className="aw-scroll">
              <table className="aw-table" data-testid="case-table">
                <thead>
                  <tr>
                    <th>Case</th>
                    <th>Status</th>
                    <th>Machines</th>
                    <th>Safety functions in question</th>
                    <th>Evidence</th>
                    <th>Owner</th>
                    <th>Next action</th>
                  </tr>
                </thead>
                <tbody>
                  {data.cases.map((c) => (
                    <tr key={c.case_id} className={c.case_id === selected ? 'aw-selected' : ''}>
                      <td>
                        <button className="aw-link" onClick={() => onOpen(c.case_id)}>
                          {c.case_id}
                        </button>
                        <br />
                        <span className="aw-note">{c.trigger}</span>
                      </td>
                      <td>{c.status}</td>
                      <td>{c.machines.join(', ')}</td>
                      <td>{c.affected_functions.join(', ') || '—'}</td>
                      <td>{c.evidence_state.join(', ')}</td>
                      <td>{c.owner || 'unassigned'}</td>
                      <td>{c.next_action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </PanelFrame>
  );
}
