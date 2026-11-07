'use client';

import { useRef, useState } from 'react';
import { useSearchParams } from 'next/navigation';

// No backend exists to receive this yet — see the pricing
// section's honesty note about what is and isn't deployed. This form does
// not claim to file into a CRM: it builds a mailto: link and hands off to
// the visitor's own mail client, which is the honest version of "send" when
// there is no server behind it. CONTACT_EMAIL is a placeholder the founder
// owns — swap it for the real monitored inbox in one place.
const CONTACT_EMAIL = 'hello@neuralbridge.io';

const INTENTS = [
  { value: 'register-cell', label: 'Register or Cell — pricing / demo' },
  { value: 'source', label: 'A copy of the source — CLI and offline kit' },
  { value: 'services', label: 'Services — a general enquiry' },
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

  // Validate on submit instead of disabling the button: a disabled button cannot be focused, so a keyboard or
  // screen-reader user would never learn which field is missing (WCAG 3.3.1, 3.3.3).
  type Field = 'name' | 'email' | 'message';
  const [errors, setErrors] = useState<Partial<Record<Field, string>>>({});
  const refs = {
    name: useRef<HTMLInputElement>(null),
    email: useRef<HTMLInputElement>(null),
    message: useRef<HTMLTextAreaElement>(null),
  };
  const validate = (): Partial<Record<Field, string>> => {
    const found: Partial<Record<Field, string>> = {};
    if (name.trim() === '') found.name = 'Enter your name.';
    if (email.trim() === '') found.email = 'Enter your email address so we can reply.';
    else if (!/^\S+@\S+\.\S+$/.test(email.trim())) found.email = 'Enter an email address like name@company.com.';
    if (message.trim() === '') found.message = 'Tell us what you are trying to do.';
    return found;
  };
  const fieldProps = (f: Field) => ({
    'aria-invalid': errors[f] ? true : undefined,
    'aria-describedby': errors[f] ? `contact-${f}-error` : undefined,
  });
  const errorList = (Object.keys(errors) as Field[]).filter((f) => errors[f]);

  return (
    <form
      className="contact-form"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        const found = validate();
        setErrors(found);
        const first = (['name', 'email', 'message'] as Field[]).find((f) => found[f]);
        if (first) {
          refs[first].current?.focus();
          return;
        }
        window.location.href = mailtoHref();
      }}
    >
      <div role="alert" className="contact-form-errors" hidden={errorList.length === 0}>
        {errorList.length > 0 && (
          <>
            <strong>
              {errorList.length === 1 ? 'One field needs attention:' : `${errorList.length} fields need attention:`}
            </strong>
            <ul>
              {errorList.map((f) => (
                <li key={f}>{errors[f]}</li>
              ))}
            </ul>
          </>
        )}
      </div>
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
          <input id="contact-name" type="text" autoComplete="name" ref={refs.name} value={name} onChange={(e) => setName(e.target.value)} required {...fieldProps('name')} />
          {errors.name && <p className="contact-field-error" id="contact-name-error">{errors.name}</p>}
        </div>
        <div className="contact-field">
          <label htmlFor="contact-email">Email</label>
          <input id="contact-email" type="email" autoComplete="email" ref={refs.email} value={email} onChange={(e) => setEmail(e.target.value)} required {...fieldProps('email')} />
          {errors.email && <p className="contact-field-error" id="contact-email-error">{errors.email}</p>}
        </div>
      </div>

      <div className="contact-field">
        <label htmlFor="contact-company">Company (optional)</label>
        <input id="contact-company" type="text" autoComplete="organization" value={company} onChange={(e) => setCompany(e.target.value)} />
      </div>

      <div className="contact-field">
        <label htmlFor="contact-message">Message</label>
        <textarea
          id="contact-message"
          ref={refs.message}
          rows={5}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder={
            intent === 'supplier'
              ? 'Which components, how many advisories a year, and any deadline you are working against.'
              : intent === 'services'
                ? 'Which of the services on the services page you are interested in, and what you can provide. No capacity, price or SLA is offered in advance.'
                : intent === 'source'
                  ? 'Who you are, what you would run it on (a laptop, a plant server, an air-gapped machine) and which commands you want to try.'
                  : 'What you are trying to do, and how many machines/products this needs to cover.'
          }
          required
          {...fieldProps('message')}
        />
        {errors.message && <p className="contact-field-error" id="contact-message-error">{errors.message}</p>}
      </div>

      <button className="btn btn-primary" type="submit">
        Open in your mail client →
      </button>
      <p className="contact-form-note">
        This opens a pre-filled email to {CONTACT_EMAIL} in your own mail app — there is no hosted form backend or
        CRM behind this yet, so nothing is sent until you do.
      </p>
    </form>
  );
}
