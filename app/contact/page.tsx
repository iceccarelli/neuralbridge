import type { Metadata } from 'next';
import { buildMetadata } from '../lib/seo';
import { Suspense } from 'react';
import ContactForm from '../components/ContactForm';

export const metadata: Metadata = buildMetadata({
  title: 'Contact',
  description:
    'Ask NeuralBridge about Register or Cell, a copy of the source, services or the supplier feed. One form that opens a pre-filled email in your own mail client.',
  path: '/contact',
});

export default function ContactPage() {
  return (
    <main id="top">
      <section className="section" style={{ paddingTop: '3rem' }}>
        <div className="shell" style={{ maxWidth: '640px' }}>
          <div className="section-head">
            <span className="eyebrow">Contact</span>
            <h1>Contact NeuralBridge</h1>
            <p>
              This is the one route for everything that is not self-serve: a copy of the source for the CLI and
              offline kit, Register or Cell (sales-assisted today; no checkout is live, see{' '}
              <a href="/#pricing">pricing</a> for why), the unlisted Supplier tier, and general questions about the{' '}
              <a href="/services">services</a>. No response time is promised. Fill this in and it opens a
              pre-filled email in your own mail client.
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
