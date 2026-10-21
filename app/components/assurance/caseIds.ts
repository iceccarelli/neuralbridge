import { call, type CaseQueue } from '../../lib/assuranceApi';
import { API_BASE } from './usePanel';

// The ids already in the caller's queue, read just before an assessment that may open a case.
// The assess routes answer with the case either way (an identical observation leaves an
// existing case as it was), so "opened" can only be said by comparing with what was there
// before. null = could not tell, and the caller must then not claim either.
export async function queueIds(apiKey: string): Promise<Set<string> | null> {
  const out = await call<CaseQueue>(API_BASE, apiKey, '/v1/change/cases');
  return out.kind === 'ok' ? new Set(out.data.cases.map((c) => c.case_id)) : null;
}

export function openedOrExisting(before: Set<string> | null, caseId: string, status: string): string {
  if (before === null) return `Case ${caseId} is in your queue (status ${status}).`;
  return before.has(caseId)
    ? `Case ${caseId} already existed; nothing new was opened (status ${status}).`
    : `Case ${caseId} opened (status ${status}).`;
}
