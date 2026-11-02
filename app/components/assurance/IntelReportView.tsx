import type { ReactNode } from 'react';
import type { IntelCitation, IntelCve } from '../../lib/assuranceApi';

// Every statement from a public source carries where it came from. This is the citation as
// the server gave it: which recorded observation, from which source, when, and the bytes' hash.
// The hash shows which bytes were recorded, not that the named source published them.
export function Citation({ c }: { c: IntelCitation }) {
  return (
    <span className="aw-cite" data-testid="intel-citation">
      observation #{c.observation_seq} · {c.source} · retrieved {c.retrieved_at} · sha256 <code>{c.sha256}</code>
      {c.feed_stamp ? ` · feed ${c.feed_stamp}` : ''}
    </span>
  );
}

function Row({ label, state, testid, children }: { label: string; state: string; testid: string; children: ReactNode }) {
  return (
    <div className="aw-intel-row" data-testid={testid} data-state={state}>
      <h3>{label}</h3>
      {children}
    </div>
  );
}

function Kev({ kev }: { kev: IntelCve['kev'] }) {
  if (kev.status === 'listed') {
    return (
      <Row label="CISA KEV" state="listed" testid="intel-kev">
        <p className="aw-verdict">
          <code>listed</code> — in the Known Exploited Vulnerabilities catalogue
        </p>
        <p>
          {[kev.vendor_project, kev.product].filter(Boolean).join(' · ')}
          {kev.date_added ? ` · added ${kev.date_added}` : ''}
          {kev.due_date ? ` · due ${kev.due_date}` : ''}
          {kev.known_ransomware_campaign_use ? ` · ransomware campaign use: ${kev.known_ransomware_campaign_use}` : ''}
        </p>
        <Citation c={kev.citation} />
      </Row>
    );
  }
  if (kev.status === 'not_listed_in_kev') {
    return (
      <Row label="CISA KEV" state="not_listed_in_kev" testid="intel-kev">
        <p className="aw-verdict">
          <code>not_listed_in_kev</code> — absent from the catalogue as recorded
        </p>
        <p data-testid="intel-kev-note">{kev.not_established}</p>
        <Citation c={kev.citation} />
      </Row>
    );
  }
  return (
    <Row label="CISA KEV" state="unchecked" testid="intel-kev">
      <p className="aw-verdict">
        <code>unchecked</code> — KEV was not consulted
      </p>
      <p data-testid="intel-kev-note">{kev.note}</p>
    </Row>
  );
}

function Epss({ epss }: { epss: IntelCve['epss'] }) {
  if (epss.status === 'available') {
    return (
      <Row label="EPSS" state="available" testid="intel-epss">
        <p className="aw-verdict">
          <code>available</code> — score <span data-testid="intel-epss-score">{String(epss.score)}</span>, percentile{' '}
          {String(epss.percentile)}, as of <span data-testid="intel-epss-date">{epss.score_date}</span>
        </p>
        <p>{epss.note}</p>
        <Citation c={epss.citation} />
      </Row>
    );
  }
  // No score is not a score of zero: no number is rendered here at all.
  return (
    <Row label="EPSS" state="unavailable" testid="intel-epss">
      <p className="aw-verdict">
        <code>unavailable</code> — there is no score to show
      </p>
      <p data-testid="intel-epss-note">{epss.note}</p>
      <p className="aw-note">{epss.reason}</p>
    </Row>
  );
}

function Nvd({ nvd }: { nvd: IntelCve['nvd'] }) {
  if (nvd.status === 'unknown') {
    return (
      <Row label="NVD" state="unknown" testid="intel-nvd">
        <p className="aw-verdict">
          <code>unknown</code> — no NVD record was recorded for this CVE
        </p>
        <p>{nvd.note}</p>
      </Row>
    );
  }
  return (
    <Row label="NVD" state={nvd.status} testid="intel-nvd">
      <p className="aw-verdict">
        <code>{nvd.status}</code>
        {nvd.status === 'rejected' ? ' — NVD marks this CVE id as rejected' : ' — an NVD record exists'}
        {nvd.vuln_status ? ` (vulnStatus ${nvd.vuln_status})` : ''}
        {nvd.last_modified ? `, last modified ${nvd.last_modified}` : ''}
      </p>
      <Citation c={nvd.citation} />
    </Row>
  );
}

// What the recorded public sources say about one CVE id, as the server returned it. The
// summary "unknown" means no recorded source mentions the id; it is never drawn as clear.
export default function IntelReportView({ report }: { report: IntelCve }) {
  const unknown = report.summary.status !== 'recorded';
  const src = report.sources_consulted;
  return (
    <div className="aw-intel" data-testid="intel-report">
      <div className="aw-intel-summary" data-testid="intel-summary" data-state={unknown ? 'unknown' : 'recorded'}>
        <strong>
          {report.cve_id}: <code>{report.summary.status}</code>
        </strong>{' '}
        {unknown ? 'Unknown, not clear. ' : ''}
        {report.summary.reason}
      </div>

      <Kev kev={report.kev} />
      <Epss epss={report.epss} />
      <Nvd nvd={report.nvd} />

      {report.cvss.length > 0 && (
        <div data-testid="intel-cvss">
          <h3>CVSS, as NVD published it</h3>
          <ul>
            {report.cvss.map((m, i) => (
              <li key={`${m.family}-${i}`}>
                {m.family} {m.version ?? ''}: {m.base_score ?? 'no score'} {m.base_severity ?? ''} {m.vector ? <code>{m.vector}</code> : null}
                {m.metric_source ? ` (${m.metric_source})` : ''}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div data-testid="intel-conflicts">
        <h3>Conflicts between sources</h3>
        {report.conflicts.length === 0 ? (
          <p className="aw-note">None recorded between NVD and a vendor advisory for this CVE.</p>
        ) : (
          <ul>
            {report.conflicts.map((c, i) => (
              <li key={`${c.kind}-${i}`} data-testid="intel-conflict">
                <strong>{c.kind}</strong> (component link: {c.component_link})
                <p>
                  NVD: {c.nvd.says}
                  <br />
                  <Citation c={c.nvd.citation} />
                </p>
                <p>
                  Vendor advisory: {c.csaf.says}
                  <br />
                  <Citation c={c.csaf.citation} />
                </p>
                <p className="aw-note">{c.resolution}</p>
              </li>
            ))}
          </ul>
        )}
      </div>

      {report.csaf_advisories.length > 0 && (
        <p data-testid="intel-csaf">Vendor advisories that name this CVE: {report.csaf_advisories.join(', ')}</p>
      )}
      {report.not_representable.length > 0 && (
        <div data-testid="intel-not-representable">
          <h3>Statements the advisory model cannot hold</h3>
          <ul>
            {report.not_representable.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </div>
      )}

      <div data-testid="intel-provenance">
        <h3>Sources consulted</h3>
        {src.observations.length === 0 ? (
          <p className="aw-note">No accepted observation exists in the store.</p>
        ) : (
          <table className="aw-table">
            <thead>
              <tr>
                <th scope="col">Observation</th>
                <th scope="col">Source</th>
                <th scope="col">Retrieved</th>
                <th scope="col">sha256</th>
              </tr>
            </thead>
            <tbody>
              {src.observations.map((o) => (
                <tr key={o.seq} data-testid="intel-observation">
                  <td>#{o.seq}</td>
                  <td>{o.source}</td>
                  <td>{o.retrieved_at}</td>
                  <td>
                    <code>{o.sha256}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {src.sources_without_an_accepted_observation.length > 0 && (
          <p data-testid="intel-missing-sources">
            Sources with no accepted observation (absent, not quiet): {src.sources_without_an_accepted_observation.join(', ')}
          </p>
        )}
        {report.unreadable_observations.length > 0 && (
          <p className="aw-bad" data-testid="intel-unreadable">
            Observations that could not be re-read: {report.unreadable_observations.join(', ')}
          </p>
        )}
      </div>

      <div data-testid="intel-not-established">
        <h3>What this does not establish</h3>
        <ul>
          {report.not_established.map((t) => (
            <li key={t}>{t}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
