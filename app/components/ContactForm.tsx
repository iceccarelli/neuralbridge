'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';

// No backend exists to receive this yet — see Feedback.tsx and the pricing
// section's honesty note about what is and isn't deployed. This form does
// not claim to file into a CRM: it builds a mailto: link and hands off to
// the visitor's own mail client, which is the honest version of "send" when
// there is no server behind it. CONTACT_EMAIL is a placeholder the founder
// owns — swap it for the real monitored inbox in one place.
const CONTACT_EMAIL = 'hello@neuralbridge.io';

const INTENTS = [
  { value: 'register-cell', label: 'Register or Cell — pricing / demo' },
  { value: 'supplier', label: 'Supplier feed — publish advisories' },
  { value: 'press', label: 'Press or partnership' },
  { value: 'other', label: 'Something else' },
] as const;

type Intent = (typeof INTENTS)[number]['value'];

export default function ContactForm({ defaultIntent }: { defaultIntent?: string }) {
  const searchParams = useSearchParams();
  const initialIntent =
    (searchParams.get('intent') as Intent | null) ??
    (defaultIntent as Intent | undefined) ??
    'register-cell';

  const [intent, setIntent] = useState<Intent>(
    INTENTS.some((i) => i.value === initialIntent) ? initialIntent : 'register-cell'
  );
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [company, setCompany] = useState('');
  const [message, setMessage] = useState('');

  const intentLabel = INTENTS.find((i) => i.value === intent)?.label ?? '';

  const mailtoHref = () => {
    const subject = `${intentLabel} — ${company || name || 'inquiry'}`;
    const header = [
      name && `Name: ${name}`,
      company && `Company: ${company}`,
      email && `Reply-to: ${email}`,
    ].filter((line): line is string => Boolean(line));
    const body = [...header, '', message || '(no message entered)'].join('\n');
    return `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  };

  const canSend = name.trim() !== '' && email.trim() !== '' && message.trim() !== '';

  return (
    <form
      className="contact-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (!canSend) return;
        window.location.href = mailtoHref();
      }}
    >
      <div className="contact-field">
        <label htmlFor="contact-intent">What is this about?</label>
        <select id="contact-intent" value={intent} onChange={(e) => setIntent(e.target.value as Intent)}>
          {INTENTS.map((i) => (
            <option key={i.value} value={i.value}>{i.label}</option>
          ))}
        </select>
      </div>

      <div className="contact-field-row">
        <div className="contact-field">
          <label htmlFor="contact-name">Name</label>
          <input id="contact-name" type="text" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div className="contact-field">
          <label htmlFor="contact-email">Email</label>
          <input id="contact-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
      </div>

      <div className="contact-field">
        <label htmlFor="contact-company">Company (optional)</label>
        <input id="contact-company" type="text" value={company} onChange={(e) => setCompany(e.target.value)} />
      </div>

      <div className="contact-field">
        <label htmlFor="contact-message">Message</label>
        <textarea
          id="contact-message"
          rows={5}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder={
            intent === 'supplier'
              ? 'Which components, how many advisories a year, and any deadline you are working against.'
              : 'What you are trying to do, and how many machines/products this needs to cover.'
          }
          required
        />
      </div>

      <button className="btn btn-primary" type="submit" disabled={!canSend}>
        Open in your mail client →
      </button>
      <p className="contact-form-note">
        This opens a pre-filled email to {CONTACT_EMAIL} in your own mail app — there is no hosted form backend or
        CRM behind this yet, so nothing is sent until you do.
      </p>
    </form>
  );
}
