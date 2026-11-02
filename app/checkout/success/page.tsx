import type { Metadata } from 'next';
import { buildMetadata } from '../../lib/seo';
import { Suspense } from 'react';
import CheckoutSuccessClient from './SuccessClient';

export const metadata: Metadata = {
  ...buildMetadata({
    title: 'Checkout',
    description:
      'Confirming your payment and collecting your API key.',
    path: '/checkout/success',
  }),
  robots: { index: false, follow: true },
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
