'use client';

import { useEffect, useState } from 'react';
import { useSharedApiKey } from '../lib/apiKey';
import type { CaseQueue, Fleet, Me, Observations } from '../lib/assuranceApi';
import AdvisoriesPanel from './assurance/AdvisoriesPanel';
import CaseDetailPanel from './assurance/CaseDetailPanel';
import CasesPanel from './assurance/CasesPanel';
import FleetPanel from './assurance/FleetPanel';
import InterventionPanel from './assurance/InterventionPanel';
import { Refusal } from './assurance/PanelFrame';
import PlanPanel from './assurance/PlanPanel';
import { API_BASE, usePanel } from './assurance/usePanel';

// The customer workspace. Every panel is its own request with its own loading, refusal and
// "as of" state: one failing never blanks another, a panel that has not answered is a
// skeleton rather than an empty list, and the server alone decides what a key may read or do.
export default function AssuranceWorkspace() {
  const { key, setKey } = useSharedApiKey();
  const [selected, setSelected] = useState('');
  const [actor, setActor] = useState('');

  const fleet = usePanel<Fleet>(key, '/v1/fleet/machines');
  const obs = usePanel<Observations>(key, '/v1/fleet/observations');
  const queue = usePanel<CaseQueue>(key, '/v1/change/cases');
  const me = usePanel<Me>(key, '/v1/me');
  const loading = fleet.loading || obs.loading || queue.loading || me.loading;

  // /assurance?case=<id> opens that case once a key is present.
  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get('case');
    if (id) setSelected(id);
  }, []);

  useEffect(() => {
    if (selected) document.getElementById('aw-case')?.scrollIntoView?.({ block: 'start' });
  }, [selected]);

  const refreshAll = () => {
    void fleet.reload();
    void obs.reload();
    void queue.reload();
    void me.reload();
  };
  const afterCaseChange = () => {
    void queue.reload();
    void fleet.reload();
    void obs.reload();
  };

  return (
    <div className="aw">
      <div className="key-row">
        <label htmlFor="aw-key">API key</label>
        <input
          id="aw-key"
          type="password"
          autoComplete="off"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="Cell-plan key"
        />
        <button className="btn btn-primary" onClick={refreshAll} disabled={loading || !API_BASE || !key}>
          {loading ? 'Loading…' : 'Refresh'}
        </button>
        <span className="key-row-note">
          Kept in this tab only, sent only to the configured API. Your key decides which ledger you read.
        </span>
      </div>

      {!API_BASE && <Refusal outcome={{ kind: 'unconfigured' }} what="Workspace" />}
      {API_BASE && !key && <p className="console-empty-note">Paste a key to load your fleet and cases.</p>}

      <FleetPanel apiKey={key} fleet={fleet} obs={obs} />
      <CasesPanel apiKey={key} queue={queue} selected={selected} onOpen={setSelected} />
      {selected && (
        <CaseDetailPanel
          key={selected}
          apiKey={key}
          caseId={selected}
          actor={actor}
          setActor={setActor}
          onChanged={afterCaseChange}
        />
      )}
      <AdvisoriesPanel
        apiKey={key}
        actor={actor}
        setActor={setActor}
        onOpenCase={setSelected}
        onChanged={() => {
          void queue.reload();
        }}
      />
      <InterventionPanel
        apiKey={key}
        actor={actor}
        setActor={setActor}
        onOpenCase={setSelected}
        onChanged={() => {
          void queue.reload();
        }}
      />
      <PlanPanel apiKey={key} me={me} />
    </div>
  );
}
