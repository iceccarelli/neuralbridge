'use client';

import type { Me } from '../../lib/assuranceApi';
import { LEDGER_VERIFY_PATH, type LedgerVerifyResponse } from '../../lib/ledgerVerifyApi';
import LedgerVerifyView from './LedgerVerifyView';
import { PanelFrame } from './PanelFrame';
import { usePanel, type Panel } from './usePanel';

// GET /v1/ledger/verify for the ledger this key reads. Read-only. The tier is what GET /v1/me
// says (passed in by the workspace, which already holds that request); until it answers it
// reads "not loaded", never a guess.
export default function LedgerVerifyPanel({ apiKey, me }: { apiKey: string; me: Panel<Me> }) {
  const verify = usePanel<LedgerVerifyResponse>(apiKey, LEDGER_VERIFY_PATH);
  const tier = me.outcome?.kind === 'ok' ? me.outcome.data.tier : (me.good?.data.tier ?? null);
  return (
    <PanelFrame id="aw-ledger-verify" title="Ledger verify" what="the ledger check" apiKey={apiKey} panel={verify}>
      {(data) => <LedgerVerifyView data={data} tier={tier} />}
    </PanelFrame>
  );
}
