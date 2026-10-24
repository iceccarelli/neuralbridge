import type { Metadata } from 'next';
import EvidenceVerifier from '../components/EvidenceVerifier';
import { REPO } from '../lib/links';

export const metadata: Metadata = {
  title: 'Check an evidence file | Industrial Autonomous Assurance',
  description:
    'Drop in a ledger export, a machine verification bundle or a signed head attestation log and see exactly which facts a check established, what is taken on trust and what was not checked. Free, no account, nothing stored.',
  alternates: { canonical: '/verify' },
  openGraph: {
    title: 'Check an evidence file | Industrial Autonomous Assurance',
    description: 'Free, no account, stores nothing: what can and cannot be established from an evidence file you were handed.',
    url: '/verify',
    type: 'website',
  },
};

export default function VerifyPage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 2.5rem' }}>
        <div className="shell">
          <span className="kicker">FREE · NO ACCOUNT · NOTHING STORED</span>
          <h1 style={{ maxWidth: '26ch' }}>Check an evidence file you were handed</h1>
          <p className="hero-lead" style={{ maxWidth: '72ch' }}>
            An auditor, an insurer or a customer sends you a JSON export. This page tells you which facts can be
            established from the file alone &mdash; and, just as plainly, which cannot. It never shows a bare
            &ldquo;valid&rdquo;: a file can be perfectly self-consistent and still not be the operator&apos;s ledger,
            or say nothing about how the machine behaved.
          </p>
        </div>
      </section>

      <section className="section" style={{ paddingTop: 0 }}>
        <div className="shell">
          <EvidenceVerifier />
        </div>
      </section>

      <section className="section section-alt" id="kinds">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">What it can check</span>
            <h2>Three kinds of file, and the limit of each</h2>
          </div>
          <div className="tile-grid">
            <article className="tile">
              <div className="tile-body">
                <h3>Ledger export</h3>
                <p>
                  A case or whole-ledger export. Checked: every record&apos;s evidence still matches its hash, no
                  field was added outside the seal, the actor column agrees with the sealed actor, each link matches
                  its own content and its predecessor, and a one-case export exported with its optional skeleton
                  (which names every other entry&apos;s id, kind and time, so it is only there if the exporter asked
                  for it) chains to it with nothing missing. <strong>Not shown unless you paste the signer&apos;s
                  public key:</strong> that nothing was cut from the end or removed &mdash; a bundle can be rebuilt
                  consistently, so without a signed head the result says <em>completeness not checked</em>. With the
                  key, an export that is shorter than, or disagrees with, its signed head is rejected, as is a record
                  dated after that head was signed; a head that signs an empty ledger anchors nothing; and records
                  after the head are counted as covered by no signature, never as complete. Only a head the signer{' '}
                  <em>read from the ledger</em> (basis <code>read_from_ledger</code>) can anchor a file: a head the
                  signer was merely <em>told</em> (<code>declared_by_holder</code>, which any paid account can have
                  signed for numbers it invented) is reported as <em>declared</em> and is never &ldquo;anchored&rdquo;.
                  A one-case export can be shown complete only if it was exported with its skeleton (
                  <code>?skeleton=true</code>, which lists the id, kind and time of every other entry in that ledger);
                  without it, a key gets <em>&ldquo;completeness could not be established&rdquo;</em> &mdash; amber, and
                  not a finding of tampering. Never shown:
                  records after that head, that the signer did not also control the ledger (a hosted ledger&apos;s
                  operator holds both, so keep your own copy of a signed attestation), or who the named people are.
                </p>
              </div>
            </article>
            <article className="tile">
              <div className="tile-body">
                <h3>Machine verification bundle</h3>
                <p>
                  Checked: the sealed record still matches its hash, its verdict agrees with its own checks, and the
                  readable envelope and result copies match what was sealed. Reports the recorded assurance tier and
                  what it does and does not allow you to claim. <strong>Not shown:</strong> that the machine behaved
                  as recorded &mdash; that needs the original envelope and trace, run offline.
                </p>
              </div>
            </article>
            <article className="tile">
              <div className="tile-body">
                <h3>Signed head attestation log</h3>
                <p>
                  On its own, only structure can be checked: numbering, chaining, non-decreasing length. A signature
                  needs the issuer&apos;s public key from a channel other than the file; paste it to check
                  signatures. <strong>Not shown:</strong> that any ledger still holds what was signed for &mdash;
                  compare the head with a ledger export.
                </p>
              </div>
            </article>
          </div>
        </div>
      </section>

      <section className="section" id="offline">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Check it offline</span>
            <h2>Download the verifier &mdash; no trust in this page required</h2>
            <p>
              This page runs the same code as the commands below, on a server you do not control. For a result that
              does not depend on us, run it yourself. They read the file you name, open no network connection and need
              no account.
            </p>
          </div>
          <p className="code-panel-label">From a checkout of the source</p>
          <pre className="code-panel">{`git clone ${REPO}.git && cd neuralbridge
pip install -e '.[assurance-attest]'
python -m assurance evidence verify export.json                 # ledger export: completeness NOT checked
python -m assurance evidence verify export.json --public-key issuer.pub   # ...checked against its signed head (exit 0 only if anchored)
python -m assurance machine check bundle.json                   # machine bundle
python -m assurance attest verify --log attestations.jsonl --public-key issuer.pub`}</pre>
          <p className="hero-panel-note" style={{ maxWidth: '72ch' }}>
            Where the file comes from: a Register or Cell account downloads a case export from the{' '}
            <a href="/assurance">workspace</a> (<code>GET /v1/cases/&#123;id&#125;/export</code>). The same free check
            is <code>POST /v1/evidence/verify</code>, listed on <a href="/developers">/developers</a>: send the file
            as the body with <code>Content-Type: application/json</code>. In the answer, <code>ok</code> means only
            that no inconsistency was found in the checks that ran &mdash; read <code>completeness</code> (ledger
            exports: <code>anchored</code> is the only complete answer) and <code>level</code> (machine bundles:{' '}
            <code>integrity_only</code> is never a reproduction) beside it. An attestation log checked without the
            issuer&apos;s public key is never <code>ok</code>. If this site has no API configured, the button above
            says so rather than faking a result.
          </p>
        </div>
      </section>
    </main>
  );
}
