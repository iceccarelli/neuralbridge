import type { EnrolReceipt } from '../../lib/assuranceApi';

// What each status the server can return means, in words that claim nothing about the machine.
// The status itself is shown as the server spelled it.
const HEADLINE: Record<string, { text: string; state: 'ok' | 'same' | 'refused' }> = {
  enrolled: { text: 'Enrolled: the declaration and the baseline configuration were written to your ledger.', state: 'ok' },
  already_enrolled: { text: 'Already enrolled: this key and configuration are on record. Nothing was written.', state: 'same' },
  configuration_differs: {
    text: 'Refused: this machine is already enrolled with a different configuration. Nothing was written.',
    state: 'refused',
  },
  identity_conflict: {
    text: 'Refused: this machine is already enrolled with different declared details. Nothing was written.',
    state: 'refused',
  },
};

function Hash({ value }: { value: string }) {
  return value ? <code>{value}</code> : <span>not stated</span>;
}

function List({ items, id }: { items: string[]; id: string }) {
  return (
    <ul data-testid={id}>
      {items.map((t) => (
        <li key={t}>{t}</li>
      ))}
    </ul>
  );
}

// The receipt as the server wrote it. Every limit it lists is shown; nothing is added that
// says the machine passed, is covered or is fine.
export default function EnrolReceiptView({ receipt }: { receipt: EnrolReceipt }) {
  const head = HEADLINE[receipt.status] ?? { text: `Unrecognised status “${receipt.status}”.`, state: 'same' as const };
  const coverage = Object.entries(receipt.coverage);
  const declared = Object.entries(receipt.declared).filter(([, v]) => v);
  return (
    <div className="aw-receipt" data-testid="enrol-receipt" data-status={receipt.status} data-state={head.state}>
      <p className="aw-verdict" data-testid="enrol-outcome">
        <code>{receipt.status}</code> — {head.text}
      </p>
      {receipt.pointer && (
        <p data-testid="enrol-pointer">
          <strong>What the server points to:</strong> {receipt.pointer}
        </p>
      )}
      <dl className="aw-kv">
        <dt>Machine key</dt>
        <dd data-testid="enrol-machine">
          <code>{receipt.machine}</code>
        </dd>
        <dt>Configuration hash</dt>
        <dd data-testid="enrol-config-hash">
          <Hash value={receipt.configuration_hash} />
        </dd>
        {receipt.enrolled_configuration_hash && receipt.enrolled_configuration_hash !== receipt.configuration_hash && (
          <>
            <dt>Enrolled with</dt>
            <dd data-testid="enrol-enrolled-hash">
              <Hash value={receipt.enrolled_configuration_hash} />
            </dd>
          </>
        )}
        <dt>Entries written</dt>
        <dd data-testid="enrol-written">
          {receipt.written
            ? `yes — manifest entry ${receipt.manifest_entry}, enrolment entry ${receipt.enrolment_entry}`
            : 'none (written: false)'}
        </dd>
        {receipt.enrolled_by && (
          <>
            <dt>Declared by</dt>
            <dd>{receipt.enrolled_by}</dd>
          </>
        )}
        {declared.length > 0 && (
          <>
            <dt>Declared details</dt>
            <dd>{declared.map(([k, v]) => `${k}: ${v}`).join(', ')}</dd>
          </>
        )}
        <dt>Items listed</dt>
        <dd>{receipt.items}</dd>
        <dt>Identity basis</dt>
        <dd>{receipt.identity_basis}</dd>
      </dl>

      {receipt.conflicts.length > 0 && (
        <div data-testid="enrol-conflicts">
          <h3>Declared details that disagree</h3>
          <ul>
            {receipt.conflicts.map((c) => (
              <li key={c.attribute}>
                {c.attribute}: enrolled as “{c.enrolled || 'not declared'}”, claimed “{c.claimed}”
              </li>
            ))}
          </ul>
        </div>
      )}

      <h3>Items that carry no hash</h3>
      {receipt.uncomparable_items.length > 0 ? (
        <div data-testid="enrol-uncomparable">
          <p>{receipt.uncomparable_note}</p>
          <List items={receipt.uncomparable_items} id="enrol-uncomparable-items" />
        </div>
      ) : (
        <p className="aw-note" data-testid="enrol-uncomparable">
          None listed by the server. That is a statement about the items that were listed, not about items nobody listed.
        </p>
      )}

      <h3>Assurance tier ceiling</h3>
      <p data-testid="enrol-ceiling">
        <code>{receipt.tier_ceiling || 'not stated'}</code> — a ceiling, not a result.
        {receipt.tier_ceiling_note && <span className="aw-note"> Server note: {receipt.tier_ceiling_note}.</span>}
      </p>

      <h3>Safety functions that cannot be demonstrated</h3>
      {receipt.undemonstrable_functions.length > 0 ? (
        <div data-testid="enrol-undemonstrable">
          <p>These declare no verification check, so nothing could ever be shown for them as declared.</p>
          <List items={receipt.undemonstrable_functions} id="enrol-undemonstrable-items" />
        </div>
      ) : (
        <p className="aw-note" data-testid="enrol-undemonstrable">None named by the server.</p>
      )}

      <h3>Coverage of each safety function</h3>
      {coverage.length > 0 ? (
        <table className="aw-table" data-testid="enrol-coverage">
          <thead>
            <tr>
              <th scope="col">Function</th>
              <th scope="col">Coverage (as the server reads it back from your ledger)</th>
            </tr>
          </thead>
          <tbody>
            {coverage.map(([fn, cov]) => (
              <tr key={fn} data-coverage={cov}>
                <th scope="row">{fn}</th>
                <td>
                  <code>{cov}</code>
                  {cov === 'never_verified' && ' — no verification has been recorded for this function'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="aw-note" data-testid="enrol-coverage">No coverage was returned with this receipt.</p>
      )}

      {receipt.notes.length > 0 && (
        <>
          <h3>Notes from the server</h3>
          <List items={receipt.notes} id="enrol-notes" />
        </>
      )}

      <h3>What enrolment does NOT establish</h3>
      <List items={receipt.does_not_establish} id="enrol-not-established" />

      {receipt.next_steps.length > 0 && (
        <>
          <h3>Next steps</h3>
          <List items={receipt.next_steps} id="enrol-next-steps" />
        </>
      )}
    </div>
  );
}
