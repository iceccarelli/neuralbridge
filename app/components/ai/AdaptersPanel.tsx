'use client';

import { PanelFrame } from '../assurance/PanelFrame';
import { usePanel } from '../assurance/usePanel';
import styles from '../assurance/workspace.module.css';

export const PLATFORM_BASE = process.env.NEXT_PUBLIC_NEURALBRIDGE_API_URL || '';

// GET /adapters on the platform API (src/neuralbridge/api/routes/adapters.py). Authentication is
// optional there (an anonymous caller is the free tier); a customer sees the adapter types the
// process registered, never other tenants' bound connections (those are operator-only).
export type AdapterInfo = {
  type: string;
  status: string;
  category: string;
  description: string;
  supported_operations: string[];
  stats: { operations: number; errors: number; avg_duration_ms: number };
};
export type AdapterList = { adapters: AdapterInfo[]; total: number };

export default function AdaptersPanel({ apiKey }: { apiKey: string }) {
  const panel = usePanel<AdapterList>(apiKey, '/adapters', PLATFORM_BASE, true);
  return (
    <PanelFrame
      id="ai-adapters"
      title="Adapter catalogue"
      what="the adapter catalogue"
      apiKey={apiKey}
      panel={panel}
      base={PLATFORM_BASE}
      keyOptional
    >
      {(list) => (
        <div data-testid="adapter-catalogue">
          <p className="aw-note">
            The adapter types this API process has registered ({list.total}). Registration is not a support claim:
            most adapters are evolving, and the README&apos;s status table is the statement of what is supported. A
            status of <code>disconnected</code> means the adapter holds no live link; the counters are this process
            since it started, not a history.
          </p>
          {list.adapters.length === 0 ? (
            <p className="console-empty-note" data-testid="adapters-empty">
              This API has no adapter registered for your account. Nothing is shown rather than a placeholder list.
            </p>
          ) : (
            <div className={styles.scroll}>
              <table className={styles.table}>
                <caption className="aw-visually-hidden">Registered adapter types</caption>
                <thead>
                  <tr>
                    <th scope="col">Type</th>
                    <th scope="col">Category</th>
                    <th scope="col">Status</th>
                    <th scope="col">Operations</th>
                    <th scope="col">Since start</th>
                  </tr>
                </thead>
                <tbody>
                  {list.adapters.map((a) => (
                    <tr key={a.type}>
                      <td>
                        <code>{a.type}</code>
                        <br />
                        <span className="aw-note">{a.description}</span>
                      </td>
                      <td>{a.category}</td>
                      <td>{a.status}</td>
                      <td>{a.supported_operations.join(', ') || 'none listed'}</td>
                      <td>
                        {a.stats.operations} call{a.stats.operations === 1 ? '' : 's'}, {a.stats.errors} error
                        {a.stats.errors === 1 ? '' : 's'}
                        {a.stats.operations > 0 ? `, avg ${a.stats.avg_duration_ms} ms` : ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </PanelFrame>
  );
}
