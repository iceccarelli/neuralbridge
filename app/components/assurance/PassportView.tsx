import type { ReactNode } from 'react';
import type { ApiOutcome } from '../../lib/assuranceApi';
import { passportGaps, splitCheckFindings, type PassportCheck, type PassportDoc } from '../../lib/passportDoc';
import { Refusal } from './PanelFrame';

// What each verdict the passport can carry means, in words that say what was recorded and no
// more. The verdict itself is shown as the file spelled it.
const VERDICT: Record<string, string> = {
  covered: 'every declared function reads current, on evidence at the validated tier or better, as recorded.',
  covered_at_community: 'every declared function reads current, but only on evidence below the validated tier: about a recorded file; the behaviour was not exercised on the machine.',
  gaps: 'at least one declared function does not read current.',
  no_functions_declared: 'the manifest declares no safety function, so there is nothing for the passport to cover.',
  ledger_chain_not_verified: 'the ledger this was read from does not verify, so nothing in it is covered.',
};

function Val({ v, code }: { v: string | null | undefined; code?: boolean }) {
  if (v === null || v === undefined) return <span className="aw-unstated">not stated</span>;
  return code ? <code>{v}</code> : <>{v}</>;
}

function Row({ label, testid, children }: { label: string; testid?: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd data-testid={testid}>{children}</dd>
    </>
  );
}

function CheckStatus({ check }: { check: ApiOutcome<PassportCheck> | null }) {
  if (check === null) {
    return (
      <p className="aw-note" role="status" data-testid="passport-check" data-state="running">
        Checking the seal and internal consistency…
      </p>
    );
  }
  if (check.kind !== 'ok') {
    return (
      <div data-testid="passport-check" data-state="unchecked">
        <Refusal outcome={check} what="Passport check" />
        <p className="aw-verdict">
          <code>unchecked</code> — the check did not answer, so neither the seal nor the file&apos;s consistency has been looked at. This is not a clean result.
        </p>
      </div>
    );
  }
  const { findings, limitations } = splitCheckFindings(check.data.problems);
  const sound = check.data.ok;
  return (
    <div data-testid="passport-check" data-state={sound ? 'no-problem-found' : 'problems'}>
      <p className="aw-verdict" data-testid="passport-check-outcome">
        {sound ? (
          <>
            <code>no problem found</code> — the seal matches the sealed content and the file does not contradict itself.
          </>
        ) : (
          <>
            <code>problems found</code> — do not rely on this file as a record of the machine until they are explained.
          </>
        )}
      </p>
      {findings.length > 0 && (
        <ul data-testid="passport-problems">
          {findings.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      <dl className="aw-kv">
        <Row label="Seal" testid="passport-chk-seal">
          {check.data.checked.seal ? 'checked' : 'not checked'}
        </Row>
        <Row label="Internal consistency" testid="passport-chk-consistency">
          {check.data.checked.internal_consistency ? 'checked' : 'not checked'}
        </Row>
        <Row label="Against a ledger" testid="passport-chk-ledger">
          {check.data.checked.against_ledger ? 'checked' : 'NOT checked: the records it names were not looked up'}
        </Row>
      </dl>
      {limitations.length > 0 && <p className="aw-note">The check also lists its own limits; they are in the unchecked list below.</p>}
    </div>
  );
}

// A passport as the server's assemble route and the offline command produce it. It shows what
// the file states, the check the server ran on it, who is named as having sealed it and at
// what tier, and every gap in one list. The page decides nothing: where the file or the check is
// silent the page says "not stated" or "unchecked", never a default.
export default function PassportView({ doc, check, source }: { doc: PassportDoc; check: ApiOutcome<PassportCheck> | null; source: string }) {
  const gaps = passportGaps(doc, check?.kind === 'ok' ? check.data : null);
  const noProblem = check?.kind === 'ok' && check.data.ok;
  const verdictText = doc.verdict ? VERDICT[doc.verdict] : undefined;
  const machineKey = [doc.machine.manufacturer, doc.machine.model].filter(Boolean).join(' ');
  return (
    <div className="aw-receipt aw-passport" data-testid="passport-view" data-verdict={doc.verdict ?? 'unstated'} data-check={noProblem ? 'no-problem-found' : 'not-established'}>
      <p className="aw-note" data-testid="passport-source">
        Read from {source}. Everything below is what the file says; only the check says whether the file holds together.
      </p>
      {!noProblem && check !== null && (
        <p className="aw-note" data-testid="passport-untrusted">
          The check did not find this file sound, or did not answer. Treat the statements below as claims in a file, not as a record.
        </p>
      )}

      <h3>Verification status</h3>
      <CheckStatus check={check} />

      <h3>What the passport asserts</h3>
      <p className="aw-verdict" data-testid="passport-verdict">
        <code>{doc.verdict ?? 'no verdict stated'}</code>
        {doc.verdict && ' — '}
        {doc.verdict && (verdictText ?? 'a verdict this page has no description for; read it as the file spells it.')}
      </p>
      <dl className="aw-kv">
        <Row label="Machine" testid="passport-machine">
          <Val v={machineKey || null} />
          {doc.machine.serial ? <> · serial <code>{doc.machine.serial}</code></> : null}
        </Row>
        <Row label="Site" testid="passport-site">
          <Val v={doc.machine.site ?? null} />
        </Row>
        <Row label="Manifest" testid="passport-manifest">
          <Val v={doc.manifest_id} code />
        </Row>
        <Row label="Configuration hash" testid="passport-config-hash">
          <Val v={doc.configuration_hash} code />
        </Row>
        <Row label="Assessed at" testid="passport-assessed">
          <Val v={doc.assessed_at} />
        </Row>
        <Row label="Sealed state" testid="passport-state">
          <Val v={doc.validation_state} code /> at confidence <Val v={doc.confidence} code />
        </Row>
      </dl>

      <h4>Safety functions</h4>
      {doc.functions.length > 0 ? (
        <div className="aw-scroll" tabIndex={0} role="region" aria-label="Passport safety functions table, scrolls sideways">
          <table className="aw-table" data-testid="passport-functions">
            <thead>
              <tr>
                <th scope="col">Function</th>
                <th scope="col">Required performance</th>
                <th scope="col">Coverage</th>
                <th scope="col">Evidence tier</th>
                <th scope="col">Last verification</th>
                <th scope="col">Invalidated by</th>
              </tr>
            </thead>
            <tbody>
              {doc.functions.map((f) => (
                <tr key={f.function_id} data-coverage={f.coverage ?? 'unstated'}>
                  <th scope="row">
                    {f.function_id}
                    {f.description && <span className="aw-fn-desc"> {f.description}</span>}
                  </th>
                  <td><Val v={f.required_performance} /></td>
                  <td>
                    <code>{f.coverage ?? 'not stated'}</code>
                  </td>
                  <td><Val v={f.evidence_tier} code /></td>
                  <td>
                    {f.last_verified_at || f.last_verified_hash ? (
                      <>
                        <Val v={f.last_verified_at} />
                        {f.last_verified_hash && <code className="aw-hash"> {f.last_verified_hash}</code>}
                      </>
                    ) : (
                      <span className="aw-unstated">none recorded</span>
                    )}
                  </td>
                  <td><Val v={f.invalidated_by} code /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="aw-note" data-testid="passport-functions">The passport lists no safety functions.</p>
      )}

      <h3>Evidence it rests on</h3>
      <dl className="aw-kv">
        <Row label="Verifications named" testid="passport-verifications">
          {doc.verification_hashes === null ? (
            <span className="aw-unstated">not stated</span>
          ) : doc.verification_hashes.length === 0 ? (
            'none: no verification is named'
          ) : (
            <ul>
              {doc.verification_hashes.map((h) => (
                <li key={h}>
                  <code>{h}</code>
                </li>
              ))}
            </ul>
          )}
        </Row>
        <Row label="Interventions named" testid="passport-interventions">
          {doc.intervention_ids === null ? (
            <span className="aw-unstated">not stated</span>
          ) : doc.intervention_ids.length === 0 ? (
            'none recorded in the ledger it was read from (a change nobody recorded is invisible to it)'
          ) : (
            <ul>
              {doc.intervention_ids.map((h) => (
                <li key={h}>
                  <code>{h}</code>
                </li>
              ))}
            </ul>
          )}
        </Row>
        <Row label="Weakest evidence tier" testid="passport-tier-floor">
          <Val v={doc.evidence_tier_floor} code />
        </Row>
        <Row label="Ledger chain when produced" testid="passport-chain">
          {doc.ledger_chain_verified === null ? <span className="aw-unstated">not stated</span> : <code>{String(doc.ledger_chain_verified)}</code>}
        </Row>
        <Row label="Ledger head" testid="passport-ledger-head">
          {doc.ledger_head ? (
            <>
              entries <code>{String(doc.ledger_head.length ?? 'not stated')}</code> · head <code>{String(doc.ledger_head.head_seq ?? 'not stated')}</code> · link{' '}
              <code>{String(doc.ledger_head.head_link_hash ?? 'not stated')}</code>
            </>
          ) : (
            <span className="aw-unstated">none recorded</span>
          )}
        </Row>
      </dl>

      <h3>Signer and attestation tier</h3>
      <dl className="aw-kv" data-testid="passport-signer">
        <Row label="Named as sealing" testid="passport-actor">
          {doc.actor ? (
            <>
              <Val v={doc.actor.identifier} /> · role <Val v={doc.actor.role} /> · <Val v={doc.actor.kind} code />
            </>
          ) : (
            <span className="aw-unstated">not stated</span>
          )}
        </Row>
        <Row label="Signature" testid="passport-signature">
          none. A passport carries no signature field. The seal is a content hash anyone can recompute, so it shows the file was not edited after sealing, not who made it.
        </Row>
        <Row label="Name and role" testid="passport-actor-basis">
          declared by the caller when the passport was made, not authenticated by this page or by the check.
        </Row>
        <Row label="Ledger head" testid="passport-head-signed">
          the head value is a value to sign or publish; it is not itself signed.
        </Row>
        <Row label="Evidence tier" testid="passport-tier">
          <Val v={doc.evidence_tier_floor} code />
          {doc.evidence_tier_floor === null
            ? ' — no tier stated; nothing about attestation can be read from the file.'
            : ' — the weakest tier among the verifications it rests on. The validated tier needs a recorder attestation accepted under a trust list the reader holds; this page cannot check that.'}
        </Row>
        <Row label="Producer" testid="passport-origin">
          {doc.origin ? (
            <>
              <Val v={doc.origin.system} code /> · <Val v={doc.origin.reference} />
            </>
          ) : (
            <span className="aw-unstated">not stated</span>
          )}
        </Row>
      </dl>

      <h3>What is unchecked</h3>
      <ul data-testid="passport-gaps">
        {gaps.map((g) => (
          <li key={g.id} data-source={g.source}>
            <span className="aw-gap-src">{g.source === 'passport' ? 'sealed in the file' : g.source === 'check' ? 'the check' : 'read from the file'}:</span> {g.text}
          </li>
        ))}
      </ul>
    </div>
  );
}
