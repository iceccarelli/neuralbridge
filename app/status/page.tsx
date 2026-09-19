import type { Metadata } from 'next';
import { REPO } from '../lib/links';

export const metadata: Metadata = {
  title: 'Status | Industrial Autonomous Assurance',
  description: 'The founder checklist between this build and a live, sellable deployment — checked at build time, not asserted.',
  alternates: { canonical: '/status' },
  robots: { index: false, follow: true },
};

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

interface ChecklistItem {
  label: string;
  done: boolean;
  detail: string;
  action: string;
}

const items: ChecklistItem[] = [
  {
    label: 'NEXT_PUBLIC_ASSURANCE_API_URL',
    done: API_BASE !== '',
    detail: API_BASE
      ? `Set to ${API_BASE}. Pricing, checkout, and the Validator playground call the live API.`
      : 'Not set at this build. Pricing, checkout, and the Validator playground all show their honest offline state instead of calling anything.',
    action: 'Deploy the API (deploy/assurance/fly.toml), then set this in Vercel → Project Settings → Environment Variables and redeploy the site. See DEPLOY_NOW.md §1–4.',
  },
  {
    label: 'Fly secrets (Stripe keys, price IDs, ASSURANCE_API_KEYS)',
    done: false,
    detail: 'Cannot be checked from a static build — these live on the Fly deployment, not in this repository.',
    action: 'fly secrets set ... — see DEPLOY_NOW.md §2 and .env.example for every name and what it does.',
  },
  {
    label: 'Stripe webhook registered',
    done: false,
    detail: 'Cannot be checked from a static build.',
    action: 'Create the endpoint at https://<your-fly-app>.fly.dev/v1/billing/webhook, subscribed to checkout.session.completed, customer.subscription.updated, customer.subscription.deleted. See DEPLOY_NOW.md §3.',
  },
  {
    label: 'GitHub Pages enabled (docs mirror)',
    done: false,
    detail: 'The on-site /docs pages work regardless — this only affects whether iceccarelli.github.io/neuralbridge also serves as a static mirror.',
    action: 'Repo Settings → Pages → enable "GitHub Actions" as the source (one-time, admin-only), then flip DOCS in app/lib/links.ts back to the Pages URL if a static mirror is still wanted.',
  },
  {
    label: 'Stale neuralbridge.vercel.app project retired',
    done: false,
    detail: 'Cannot be checked from a static build — this is a different Vercel project than the one that deploys this site.',
    action: 'In the Vercel dashboard, delete the old "v0 Human-like Neural Interface" project or redirect it to https://neuralbridge.io. See DEPLOY_NOW.md §5.',
  },
  {
    label: 'Smoke test passed on the live site',
    done: false,
    detail: 'Cannot be checked from a static build — run it against the deployed site after the steps above.',
    action: 'See SMOKE.md — five browser checks. All five must pass before announcing the site as live.',
  },
];

export default function StatusPage() {
  const doneCount = items.filter((i) => i.done).length;

  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 3.5rem' }}>
        <div className="shell">
          <span className="kicker">FOUNDER CHECKLIST, NOT A CODE BLOCKER</span>
          <h1 style={{ maxWidth: '26ch' }}>What&apos;s between this build and a live, sellable deployment</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            Every item below is deploy/ops work outside this repository&apos;s CI — nothing here is something a PR
            can fix. See <a href={`${REPO}/blob/main/DEPLOY_NOW.md`} target="_blank" rel="noreferrer">DEPLOY_NOW.md</a>{' '}
            for the exact command sequence and <code>.env.example</code> for every variable name.
          </p>
          <div className="status-progress">
            <div className="status-progress-bar">
              <div className="status-progress-fill" style={{ width: `${(doneCount / items.length) * 100}%` }} />
            </div>
            <span>{doneCount} of {items.length} checkable from this build confirmed — the rest need a real deployment to verify, which is expected.</span>
          </div>
        </div>
      </section>

      <section className="section" style={{ paddingTop: '2.5rem' }}>
        <div className="shell" style={{ maxWidth: '76ch' }}>
          <div className="status-checklist">
            {items.map((item) => (
              <div className={`status-checklist-item ${item.done ? 'done' : 'pending'}`} key={item.label}>
                <span className="status-checklist-mark" aria-hidden>{item.done ? '✓' : '○'}</span>
                <div>
                  <strong>{item.label}</strong>
                  <p>{item.detail}</p>
                  {!item.done && <p className="status-checklist-action">{item.action}</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
