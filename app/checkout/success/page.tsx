import type { Metadata } from 'next';
import { Suspense } from 'react';
import CheckoutSuccessClient from './SuccessClient';

export const metadata: Metadata = {
  title: 'Checkout | Industrial Autonomous Assurance',
  description: 'Confirming your payment and collecting your API key.',
  alternates: { canonical: '/checkout/success' },
  robots: { index: false, follow: true },
  openGraph: {
    title: 'Checkout | Industrial Autonomous Assurance',
    description: 'Confirming your payment and collecting your API key.',
    url: '/checkout/success',
    type: 'website',
  },
};

export default function CheckoutSuccessPage() {
  return (
    <main id="top">
      <Suspense fallback={null}>
        <CheckoutSuccessClient />
      </Suspense>
    </main>
  );
}
