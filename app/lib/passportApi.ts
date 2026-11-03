// Machine passport client: POST /v1/machinery/passport (assemble) and POST
// /v1/machinery/passport/check (free re-check of a file). The pure reading of a passport is in
// passportDoc.ts.
import { call, type ApiOutcome } from './assuranceApi';
import type { PassportCheck } from './passportDoc';

export * from './passportDoc';

/** Re-check a passport file. Free and open to anyone, so no key is sent: the file leaves this
 *  browser for the configured API only, with nothing that identifies the account. */
export function checkPassport(apiBase: string, passport: unknown): Promise<ApiOutcome<PassportCheck>> {
  return call<PassportCheck>(apiBase, '', '/v1/machinery/passport/check', { method: 'POST', body: { passport } });
}

/** Assemble the machine's current passport from a manifest WITHOUT sealing it: `seal: false`, so
 *  nothing is written to the account's ledger. Needs a key; the server decides 401/402. */
export function assemblePassport(
  apiBase: string,
  apiKey: string,
  manifest: unknown,
  actor: string,
  role: string,
): Promise<ApiOutcome<Record<string, unknown>>> {
  return call<Record<string, unknown>>(apiBase, apiKey, '/v1/machinery/passport', {
    method: 'POST',
    body: { manifest, actor, ...(role ? { role } : {}), seal: false },
  });
}
