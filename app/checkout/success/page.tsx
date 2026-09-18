import type { Metadata } from 'next';
import { Suspense } from 'react';
import CheckoutSuccessClient from './SuccessClient';

export const metadata: Metadata = {
  title: 'Checkout | Industrial Autonomous Assurance',
  description: 'Confirming your payment and collecting your API key.',
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
