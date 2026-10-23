'use client';

import type { Fleet, ObservationRow, Observations } from '../../lib/assuranceApi';
import { PanelFrame, Refusal } from './PanelFrame';
import type { Panel } from './usePanel';

function ageLabel(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'unknown age';
  const days = Math.floor((Date.now() - t) / 86_400_000);
  return days <= 0 ? 'today' : `${days} day${days === 1 ? '' : 's'} ago`;
}

const STALE_WHY: Record<string, string> = {
  never_reported: 'never reported',
  never_successfully_observed: 'no successful observation has ever been reported',
  older_than_cadence: 'last successful observation is older than the declared cadence',
};

function when(iso: string | null): string {
  return iso ? `${ageLabel(iso)} (${iso})` : '';
}

function hours(h: number | null | undefined): string {
  return typeof h === 'number' ? `${h} h` : 'not stated';
}

// Where the record behind a machine's row comes from, how complete the look was and how far it can
// be trusted. All of it is the customer's own report: no field here is independent telemetry.
function SourceCell({ row }: { row: ObservationRow | undefined }) {
  if (!row || !row.reported) {
    return (
      <td data-testid="obs-source" data-source="manifest-only">
        <strong>Source: sealed manifest only.</strong> No Watch observation was reported for this machine. A missing
        report is not evidence the machine is unchanged.
      </td>
    );
  }
  const status = row.last_attempt_status ?? '';
  const completeness =
    status === 'incomplete'
      ? 'INCOMPLETE — part of what the plan names was not read; it cannot say the machine is current'
      : status === 'uncollectable'
        ? 'NOT COLLECTED — the attempt produced nothing'
        : status === 'manifest_stale'
          ? 'NOT A LOOK — the manifest was too old to describe the machine at that time'
          : row.last_attempt_succeeded
            ? `reported as a complete look (status ${status || 'not stated'})`
            : `not a complete look (status ${status || 'not stated'})`;
  return (
    <td data-testid="obs-source" data-source="client-reported-watch" data-completeness={status}>
      <strong>Source: client-reported Watch observation</strong> (<code>assurance watch push</code>), not independent
      telemetry. Basis: <code data-testid="obs-basis">{row.basis ?? 'client_reported'}</code>.
      <br />
      <span className="aw-note" data-testid="obs-replay-limit">
        A compromised Watch holding your account key can replay a genuine earlier manifest as a look at the machine;
        this service cannot tell that from an honest look at an unchanged machine.
      </span>
      <br />
      Completeness of the latest attempt: {completeness}.
      <br />
      <span className="aw-note">
        Manifest age at the last successful look: {hours(row.last_successful_manifest_age_hours)}
        {row.last_successful_manifest_relayed ? ' (a manifest sealed earlier and relayed; its age is shown, not judged)' : ''}
        . At the latest attempt: {hours(row.last_attempt_manifest_age_hours)}. Dates and cadence are declared by the
        reporting client; the server&rsquo;s own receipt time is{' '}
        {row.last_successful_received_at ?? 'not stated'}, and a look is never counted as later than it.
        {row.last_successful_observed_at_skew
          ? ' The reported look date differs from the server receipt by more than 24 h (observed_at_skew); read the date with care.'
          : ''}
      </span>
      {row.last_attempt_detail && (
        <>
          <br />
          <span className="aw-note">Detail reported: {row.last_attempt_detail}</span>
        </>
      )}
      {row.open_case_ids.length > 0 && (
        <>
          <br />
          <span className="aw-note">Open case(s): {row.open_case_ids.join(', ')}</span>
        </>
      )}
    </td>
  );
}

// One machine's Watch columns. A failed or incomplete attempt is shown as failed,
// never as an observation; a machine nobody reported is not shown as current.
function ObservationCells({ row }: { row: ObservationRow | undefined }) {
  if (!row || !row.reported) {
    return (
      <>
        <td data-testid="obs-last-success">No Watch report received — run <code>assurance watch push</code></td>
        <td data-testid="obs-last-attempt">—</td>
        <td data-testid="obs-stale">
          <strong className="aw-bad">Stale</strong> — never reported
        </td>
        <SourceCell row={row} />
      </>
    );
  }
  const failedLast = row.last_attempt_succeeded === false;
  return (
    <>
      <td data-testid="obs-last-success" title={row.last_successful_observation_at ?? undefined}>
        {row.last_successful_observation_at ? (
          when(row.last_successful_observation_at)
        ) : (
          <span className="aw-bad">None — no successful observation has been reported</span>
        )}
      </td>
      <td data-testid="obs-last-attempt" title={row.last_attempt_at ?? undefined}>
        {failedLast ? (
          <>
            <strong className="aw-bad">FAILED — {row.last_attempt_status}</strong>{' '}
            {row.last_attempt_at ? ageLabel(row.last_attempt_at) : ''}
            {row.consecutive_failed_attempts > 1 ? `, ${row.consecutive_failed_attempts} attempts in a row` : ''}
            <br />
            <span className="aw-note">Not an observation: this machine is not shown as current.</span>
          </>
        ) : (
          <>
            {row.last_attempt_status} {row.last_attempt_at ? ageLabel(row.last_attempt_at) : ''}
          </>
        )}
      </td>
      <td data-testid="obs-stale">
        {row.stale ? (
          <>
            <strong className="aw-bad">Stale</strong> — {STALE_WHY[row.stale_reason] ?? row.stale_reason} (cadence{' '}
            {row.cadence_hours} h{row.cadence_declared ? '' : ', default'})
          </>
        ) : (
          <>
            No — within {row.cadence_hours} h, the cadence the client declared. That is its report, not a check by this
            service.
          </>
        )}
      </td>
      <SourceCell row={row} />
    </>
  );
}

export default function FleetPanel({
  apiKey,
  fleet,
  obs,
}: {
  apiKey: string;
  fleet: Panel<Fleet>;
  obs: Panel<Observations>;
}) {
  // The observation columns come from a second request. While it is in flight they are
  // "loading", after a failure they are "unavailable" (with the reason), and never blank.
  const obsData = obs.outcome?.kind === 'ok' ? obs.outcome.data : (obs.good?.data ?? null);
  const obsPending = obs.outcome === null || (obs.loading && obsData === null);

  return (
    <PanelFrame id="aw-fleet" title="Fleet" what="the fleet" apiKey={apiKey} panel={fleet}>
      {(data) => (
        <>
          {!data.chain_verified && (
            <p className="aw-alert" role="alert" data-testid="chain-broken">
              <strong>THE LEDGER CHAIN DOES NOT VERIFY</strong> — every row below is drawn from a store whose integrity is
              in question.
              {data.chain_problems.length ? ` First problem: ${data.chain_problems[0]}` : ''}
            </p>
          )}
          <p data-testid="fleet-summary">
            {data.summary.machines} machine(s): {data.summary.covered} with every declared safety function covered,{' '}
            {data.summary.with_gaps} not fully covered (a declared function with a gap, or no safety function declared
            at all — see each row).
          </p>
          {data.machines.length === 0 ? (
            <p className="console-empty-note">
              No machine is enrolled in your ledger. Enrol a machine&apos;s safety manifest with{' '}
              <code>POST /v1/machinery/manifest</code>; until then there is nothing to assess, which is not the same as
              nothing wrong.
            </p>
          ) : (
            <div className="aw-scroll">
              <table className="aw-table" data-testid="fleet-table">
                <thead>
                  <tr>
                    <th>Machine</th>
                    <th>Site</th>
                    <th>Last sealed manifest</th>
                    <th>Last successful observation</th>
                    <th>Last attempt</th>
                    <th>Stale?</th>
                    <th>Record source and completeness</th>
                    <th>Config</th>
                    <th>Evidence</th>
                    <th>Stale</th>
                    <th>Not current</th>
                  </tr>
                </thead>
                <tbody>
                  {data.machines.map((m) => (
                    <tr key={m.machine} data-testid="fleet-row" data-machine={m.machine}>
                      <td>{m.machine}</td>
                      <td>{m.site || '—'}</td>
                      <td title={m.taken_at} data-testid="manifest-cell">
                        {ageLabel(m.taken_at)}
                        <br />
                        <span className="aw-note">sealed manifest {m.taken_at}</span>
                      </td>
                      {obsData ? (
                        <ObservationCells row={obsData.machines.find((r) => r.machine === m.machine)} />
                      ) : (
                        <td colSpan={4} data-testid={obsPending ? 'obs-loading' : 'obs-unavailable'}>
                          {obsPending ? 'Loading observation status…' : 'Observation status unavailable.'}
                        </td>
                      )}
                      <td>
                        <code>{m.configuration_hash.slice(0, 12)}</code>
                      </td>
                      <td>{m.worst ?? 'no safety function declared'}</td>
                      <td>{m.stale}</td>
                      <td>{m.uncovered}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {obsData &&
            (() => {
              const enrolled = new Set(data.machines.map((m) => m.machine));
              const extra = obsData.machines.filter((r) => !enrolled.has(r.machine));
              if (extra.length === 0) return null;
              return (
                <>
                  <h3>Reported by Watch, no manifest in this ledger</h3>
                  <p className="aw-note">
                    These machines appear only in Watch reports, as attempts that did not produce a manifest here (for
                    example a machine that could not be collected on its first run).
                  </p>
                  <div className="aw-scroll">
                    <table className="aw-table" data-testid="obs-extra-table">
                      <thead>
                        <tr>
                          <th>Machine</th>
                          <th>Last successful observation</th>
                          <th>Last attempt</th>
                          <th>Stale?</th>
                          <th>Record source and completeness</th>
                        </tr>
                      </thead>
                      <tbody>
                        {extra.map((r) => (
                          <tr key={r.machine} data-machine={r.machine}>
                            <td>{r.machine}</td>
                            <ObservationCells row={r} />
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              );
            })()}
          {data.machines.length > 0 && obsData && !obsData.reporting && (
            <p className="console-empty-note" data-testid="obs-none">
              No Watch report received — run <code>assurance watch push</code>. Until you do, this workspace only knows
              the manifests that were recorded in it; it cannot say when any machine was last looked at.
            </p>
          )}
          {obsData && obsData.reporting && (
            <p data-testid="obs-summary">
              {obsData.summary.stale} stale · {obsData.summary.latest_attempt_failed} whose latest attempt failed ·{' '}
              {obsData.summary.never_reported} never reported. Reported by you, not independently observed; each machine
              is judged against the cadence your Watch declared with its last successful look (default{' '}
              {obsData.default_cadence_hours} h). Computed by the server at {obsData.as_of}.
            </p>
          )}
          {obs.outcome && obs.outcome.kind !== 'ok' && <Refusal outcome={obs.outcome} what="Watch observations" />}
          <div className="aw-prov" data-testid="fleet-limits">
            <p>
              <strong>Limits of what this table shows.</strong> A submitted observation is not independent telemetry. A
              missing report is not evidence the machine is unchanged. A date is when the reporting client says it looked.
            </p>
            {obsData && obsData.limitations.length > 0 && (
              <ul>
                {obsData.limitations.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            )}
          </div>
          <p className="aw-note">
            &ldquo;Last sealed manifest&rdquo; is the last configuration recorded in this ledger, not a live observation.
            The hosted API does not run Watch: Watch still runs in your kit or scheduler, and the observation columns show
            only what you chose to report with <code>assurance watch push</code>. A look that failed or was incomplete is
            shown as failed, never as unchanged, and a machine whose last successful observation is older than your
            declared cadence, or that was never reported, is shown as stale. These are your reports; the hosted service
            did not observe any machine.
          </p>
        </>
      )}
    </PanelFrame>
  );
}
