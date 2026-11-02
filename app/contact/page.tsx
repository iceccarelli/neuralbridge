import type { Metadata } from 'next';
import { buildMetadata } from '../lib/seo';
import { Suspense } from 'react';
import ContactForm from '../components/ContactForm';

export const metadata: Metadata = buildMetadata({
  title: 'Contact',
  description:
    'Talk to sales about Register or Cell, or reach the supplier feed program. One form that opens a pre-filled email in your own mail client; no CRM behind it yet.',
  path: '/contact',
});

export default function ContactPage() {
  return (
    <main id="top">
      <section className="section" style={{ paddingTop: '3rem' }}>
        <div className="shell" style={{ maxWidth: '640px' }}>
          <div className="section-head">
            <span className="eyebrow">Contact</span>
            <h1>Talk to a human</h1>
            <p>
              Register and Cell are sales-assisted today — no self-serve checkout is live yet (see{' '}
              <a href="/#pricing">pricing</a> for why). The Supplier tier is unlisted and sales-assigned by design.
              Fill this in and it opens a pre-filled email in your own mail client.
            </p>
          </div>
          <Suspense fallback={<div className="contact-form-fallback" aria-hidden="true" />}>
            <ContactForm />
          </Suspense>
        </div>
      </section>
    </main>
  );
}
