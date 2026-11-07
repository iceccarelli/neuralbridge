// What the workspace screens say about WHO and WHERE: which account and plan answered, which API
// origin the key is sent to, and which ledger the records come from. Pure, so node can run it.
//
// Nothing here is a claim of the page's own: the account and plan are what `GET /v1/me` returned
// for the key, the origin is the build-time API address, and "ledger" is derived only from the
// account id the server reported. Before the server has answered, the honest value is "unknown".

export type Environment = 'unconfigured' | 'local' | 'hosted';
export type KeyTransport = 'none' | 'local' | 'encrypted' | 'cleartext';

export type OriginInfo = {
  configured: boolean;
  /** scheme://host[:port], or '' */
  origin: string;
  host: string;
  environment: Environment;
  /** How a key typed here would travel: nowhere, to this machine, over TLS, or in the clear. */
  keyTransport: KeyTransport;
  /** The build setting that supplies this address. */
  setting: string;
};

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1', '0.0.0.0']);

export function describeOrigin(url: string, setting: string): OriginInfo {
  const none: OriginInfo = { configured: false, origin: '', host: '', environment: 'unconfigured', keyTransport: 'none', setting };
  if (!url) return none;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return none;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return none;
  const host = u.hostname.toLowerCase();
  const local = LOCAL_HOSTS.has(host) || host.endsWith('.localhost');
  return {
    configured: true,
    origin: u.origin,
    host: u.host,
    environment: local ? 'local' : 'hosted',
    keyTransport: local ? 'local' : u.protocol === 'https:' ? 'encrypted' : 'cleartext',
    setting,
  };
}

export const ENVIRONMENT_LABEL: Record<Environment, string> = {
  unconfigured: 'No API configured',
  local: 'Local API (this machine)',
  hosted: 'Hosted API',
};

export const KEY_TRANSPORT_NOTE: Record<KeyTransport, string> = {
  none: 'No key is sent: there is no API address.',
  local: 'A key is sent only to this machine.',
  encrypted: 'A key is sent only to this origin, over HTTPS.',
  cleartext: 'WARNING: this address is plain http to a non-local host; a key sent to it is readable on the network.',
};

type MeAccount = { id?: string; company?: string; email?: string; status?: string; source?: string };
type MeLike = { authenticated?: boolean; tier?: string; plan?: { name?: string; tier?: string }; account?: MeAccount };

export type Identity = {
  /** 'anonymous' = the server answered and no account owns the key; 'unknown' = no answer yet. */
  state: 'unknown' | 'anonymous' | 'account';
  accountLabel: string;
  accountStatus: string;
  accountSource: string;
  planLabel: string;
  tier: string;
  /** Which ledger this key reads. */
  ledger: string;
  isOperator: boolean;
};

export function identityFromMe(me: MeLike | null | undefined): Identity {
  if (!me) {
    return { state: 'unknown', accountLabel: 'not reported yet', accountStatus: '', accountSource: '', planLabel: 'not reported yet', tier: '', ledger: 'not known until the API answers', isOperator: false };
  }
  const tier = me.tier || me.plan?.tier || '';
  const planLabel = me.plan?.name ? `${me.plan.name} (${tier || 'tier not reported'})` : tier || 'not reported';
  const a = me.account;
  if (!me.authenticated || !a) {
    return { state: 'anonymous', accountLabel: 'no account (no key presented)', accountStatus: '', accountSource: '', planLabel, tier, ledger: 'none: the free validator keeps no ledger for you', isOperator: false };
  }
  const operator = a.id === 'operator';
  const who = [a.company, a.email].filter(Boolean).join(' · ') || a.id || 'unnamed account';
  return {
    state: 'account',
    accountLabel: who,
    accountStatus: a.status || '',
    accountSource: a.source || '',
    planLabel,
    tier,
    ledger: operator ? "the operator's shared ledger (operator-only, not a customer ledger)" : "your account's own ledger",
    isOperator: operator,
  };
}
