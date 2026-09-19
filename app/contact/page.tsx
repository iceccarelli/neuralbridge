import type { Metadata } from 'next';
import { Suspense } from 'react';
import ContactForm from '../components/ContactForm';

export const metadata: Metadata = {
  title: 'Contact | Industrial Autonomous Assurance',
  description: 'Talk to sales about Register or Cell, or reach the supplier feed program — one form, no CRM behind it yet.',
  alternates: { canonical: '/contact' },
  openGraph: {
    title: 'Contact | Industrial Autonomous Assurance',
    description: 'Talk to sales about Register or Cell, or reach the supplier feed program.',
    url: '/contact',
    type: 'website',
  },
};

export default function ContactPage() {
  return (
    <main id="top">
      <section className="section" style={{ paddingTop: '3rem' }}>
        <div className="shell" style={{ maxWidth: '640px' }}>
          <div className="section-head">
            <span className="eyebrow">Contact</span>
            <h2>Talk to a human</h2>
            <p>
              Register and Cell are sales-assisted today — no self-serve checkout is live yet (see{' '}
              <a href="/#pricing">pricing</a> for why). The Supplier tier is unlisted and sales-assigned by design.
              Fill this in and it opens a pre-filled email in your own mail client.
            </p>
          </div>
          <Suspense fallback={null}>
            <ContactForm />
          </Suspense>
        </div>
      </section>
    </main>
  );
}
