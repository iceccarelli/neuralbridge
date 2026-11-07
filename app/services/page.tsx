import type { Metadata } from 'next';
import Inline from '../components/Inline';
import { buildMetadata } from '../lib/seo';
import { SALES } from '../lib/links';
import { SERVICES, SERVICES_DISCLAIMER, type Service } from '../lib/services';

export const metadata: Metadata = buildMetadata({
  title: 'Services',
  description:
    'Eight productised outcomes around Industrial Autonomous Assurance: inputs, deliverables, exclusions and evidence produced. No capacity, SLA or price offered.',
  path: '/services',
});

const AVAILABILITY_LABEL: Record<Service['availability'], { text: string; cls: string }> = {
  available: { text: 'Product capability exists today', cls: 'is-live' },
  partial: { text: 'Product capability partly exists', cls: 'is-gap' },
  gap: { text: 'Needs development', cls: 'is-none' },
};

function Rows({ label, items }: { label: string; items: string[] }) {
  return (
    <li>
      <h3>{label}</h3>
      <ul>
        {items.map((item) => (
          <li key={item}>
            <Inline text={item} />
          </li>
        ))}
      </ul>
    </li>
  );
}

export default function ServicesPage() {
  return (
    <main id="top">
      <section className="page-hero">
        <div className="shell">
          <span className="kicker">Services</span>
          <h1>Help around the product, described before it is promised</h1>
          <p>
            NeuralBridge builds Industrial Autonomous Assurance. This page lists eight repeatable outcomes that could be
            scoped around it: what each needs from the customer, what it hands over, what it does not, which evidence it
            produces, what the software does by itself and what needs an engineer’s review.
          </p>
          <ul className="toc" aria-label="Services">
            {SERVICES.map((service) => (
              <li key={service.id}>
                <a href={`#${service.id}`}>{service.name}</a>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="section">
        <div className="shell">
          <div className="note-box" role="note" aria-label="What this page does not offer">
            <p>
              <strong>Read this first.</strong>
            </p>
            <ul>
              {SERVICES_DISCLAIMER.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>

          {SERVICES.map((service) => {
            const state = AVAILABILITY_LABEL[service.availability];
            return (
              <article className="service" id={service.id} key={service.id} aria-labelledby={`${service.id}-h`}>
                <h2 id={`${service.id}-h`}>{service.name}</h2>
                <p className="lede">
                  <strong>For:</strong> {service.customer}
                </p>
                <p className="tag-row" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', margin: '0 0 1rem' }}>
                  <span className={`tag ${state.cls}`}>{state.text}</span>
                  <span className="tag is-none">No capacity, SLA or price offered</span>
                </p>
                <ul className="ruled">
                  <li>
                    <h3>The problem</h3>
                    <p>{service.problem}</p>
                  </li>
                  <Rows label="Customer inputs" items={service.inputs} />
                  <Rows label="Deliverables" items={service.deliverables} />
                  <Rows label="Evidence produced" items={service.evidence} />
                  <Rows label="Automated by the software" items={service.automated} />
                  <Rows label="Needs engineering or named-person review" items={service.review} />
                  <Rows label="Exclusions" items={service.exclusions} />
                  <Rows label="Technical prerequisites" items={service.prerequisites} />
                  <Rows label="Customer responsibilities" items={service.responsibilities} />
                  <Rows label="Ongoing-support dependency" items={service.support} />
                  <Rows label="What can be verified independently" items={service.verifiable} />
                  <Rows label="Product capability that exists today" items={service.today} />
                  <Rows label="What needs development first" items={service.gap} />
                </ul>
              </article>
            );
          })}

          <div className="note-box">
            <p>
              <strong>The only next step is a general conversation.</strong> There is no order form, price list,
              booking link or SLA. If something here matches a need, <a href={SALES}>contact NeuralBridge</a> and say
              which entry; nothing is promised in reply. The software itself is described on the{' '}
              <a href="/start">get-started page</a>, and what is stored where on the <a href="/trust">trust page</a>.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
