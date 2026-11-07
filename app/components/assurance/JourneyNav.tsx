import { availability, JOURNEY } from '../../lib/journey';
import { describeOrigin } from '../../lib/workspaceIdentity';
import styles from './workspace.module.css';

const ORIGIN = describeOrigin(process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '', 'NEXT_PUBLIC_ASSURANCE_API_URL');

// The route a customer takes, in order, and an honest answer for each step to "can I do this here?".
// Hosted means this build has an Assurance API address and the step is a call to it; the server still
// decides, per key, what the plan allows (a 402 is shown where it happens). Offline means the step is
// a command on the customer's own machine, which opens no sockets of its own.
export default function JourneyNav({ current }: { current?: string }) {
  return (
    <nav className={styles.journey} aria-label="Customer journey" data-testid="journey-nav">
      <strong>From machine to evidence pack</strong>
      <p className="aw-note" style={{ margin: '0.25rem 0 0' }}>
        {ORIGIN.configured
          ? `This deployment has a hosted API at ${ORIGIN.origin}. Steps marked hosted run there; the offline command does the same on your own machine.`
          : 'This deployment has no hosted API. Every step below is an offline command on your own machine; the workspace panels stay disabled rather than simulating an answer.'}
      </p>
      <ol>
        {JOURNEY.map((step) => {
          const where = availability(step, ORIGIN.configured);
          return (
            <li key={step.id} data-current={current === step.id ? 'true' : 'false'} data-step={step.id} data-availability={where}>
              {step.href ? (
                <a className={styles.stepLabel} href={step.href}>
                  {step.label}
                </a>
              ) : (
                <span className={styles.stepLabel}>{step.label}</span>
              )}{' '}
              <span className={styles.tag}>
                {step.id === 'collect' ? 'runs on your machine' : where === 'hosted' ? 'hosted on this deployment' : 'offline only here'}
              </span>
              <span className={styles.stepMeta}>{step.actor}. {step.hostedNote}</span>
              <span className={styles.stepMeta}>
                Hosted: {step.hosted.map((h, i) => (<span key={h}>{i ? ', ' : ''}<code>{h}</code></span>))}
              </span>
              <span className={styles.stepMeta}>
                Offline: {step.offline.map((v, i) => (<span key={v}>{i ? ', ' : ''}<code>assurance {v}</code></span>))}
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
