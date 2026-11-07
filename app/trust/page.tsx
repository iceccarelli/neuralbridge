import type { Metadata } from 'next';
import { buildMetadata } from '../lib/seo';
import { SALES } from '../lib/links';

export const metadata: Metadata = buildMetadata({
  title: 'Trust and data handling',
  description:
    'Where data lives, what each provenance class can support, who may decide, and the limits of a hash-chained record, checked against the code.',
  path: '/trust',
});

// Every statement here was checked against the code or the docs it names (src/assurance/machinery/manifest.py,
// core/tiers.py, deploy/assurance/CHANGE.md, KIT.md, TENANT.md, docs/GO-LIVE.md, docs/claims-registry.md).
// If one of them changes, this page is wrong until it is edited: there is no generated copy.

export default function TrustPage() {
  return (
    <main id="top">
      <section className="page-hero">
        <div className="shell">
          <span className="kicker">Trust and data handling</span>
          <h1>What is stored where, what a record can prove, and where it stops</h1>
          <p>
            Written against the code, not against a brochure. Where the software cannot know something, this page says
            so. For the cookies and browser storage of this website, see <a href="/privacy" style={{ color: '#ffffff', textDecoration: 'underline' }}>Privacy</a>.
          </p>
          <ul className="toc" aria-label="On this page">
            <li><a href="#data">Where data lives</a></li>
            <li><a href="#provenance">Provenance classes</a></li>
            <li><a href="#prove">What a record can prove</a></li>
            <li><a href="#permissions">Permissions and decisions</a></li>
            <li><a href="#architecture">Security architecture</a></li>
            <li><a href="#limits">Limitations</a></li>
            <li><a href="#not-claimed">Not claimed</a></li>
          </ul>
        </div>
      </section>

      <section className="section" id="data">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Data handling</span>
            <h2>Where data lives, by the way you use the product</h2>
          </div>
          <ul className="ruled">
            <li>
              <h3>Offline kit and CLI</h3>
              <div>
                <p>
                  Reads the files you name and writes a ledger, a report and an attestation request to a folder on your
                  disk. The run arms a guard over the process&apos;s socket layer and refuses every outbound
                  connection, including name resolution, and seals a record of any attempt into your own ledger. No
                  account, no key, no upload.
                </p>
                <p><span className="tag is-offline">runs on your machine</span></p>
              </div>
            </li>
            <li>
              <h3>Checking a file you were handed</h3>
              <div>
                <p>
                  <code>POST /v1/evidence/verify</code> and the <a href="/verify">/verify</a> page check a ledger
                  export, machine bundle or attestation log and store nothing. The same checks run offline with{' '}
                  <code>python -m assurance evidence verify</code>, which does not depend on trusting this site.
                </p>
                <p>
                  <span className="tag is-gap">online version needs a hosted API, none public today</span>{' '}
                  <span className="tag is-offline">offline version available</span>
                </p>
              </div>
            </li>
            <li>
              <h3>A hosted account</h3>
              <div>
                <p>
                  Where an operator deploys the Assurance API, each customer account has its own ledger; the shared
                  ledger is operator-only. One writer per ledger file keeps each hash chain linear. API keys are shown
                  once when issued and only a hash is kept, with one exception: a key issued at checkout waits in
                  the account store in plaintext until the browser collects it, or for up to 24 hours, and is then
                  deleted and revoked if uncollected, so the account store must be protected accordingly. Secrets
                  are never logged or printed.
                </p>
                <p>
                  The public-source intelligence store (KEV, NVD, EPSS, CSAF) is the operator&apos;s shared public
                  data, not tenant evidence. Fetching a feed is the operator&apos;s act, never the hosted
                  service&apos;s.
                </p>
                <p><span className="tag is-none">no public hosted API is deployed today</span></p>
              </div>
            </li>
            <li>
              <h3>Reporting watch results</h3>
              <div>
                <p>
                  Scheduled drift checks run in your own kit or cron. <code>watch push</code> is the one opt-in command
                  that reports the latest run to your own hosted ledger; nothing is pushed unless you run it.
                </p>
              </div>
            </li>
            <li>
              <h3>Leaving</h3>
              <div>
                <p>
                  Operator tooling exports one account (ledger, evidence bundle, attestation log, hashed manifest),
                  re-hashes the export against its manifest, and plans removal. It deletes nothing by default, and
                  executes a removal only after a verified export and a named person. It is not a hosted route.
                </p>
              </div>
            </li>
          </ul>
        </div>
      </section>

      <section className="section section-alt" id="provenance">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Provenance classes</span>
            <h2>How each item&apos;s identity was established is a ceiling on every claim about it</h2>
            <p>
              Every item in a safety-software manifest (firmware, safety program, safety configuration, parameter set,
              library) carries one of three classes. The class caps the assurance tier any conclusion can reach. No
              class reaches <em>certified</em>: that tier needs a certificate from an accredited body, which this
              software cannot supply.
            </p>
          </div>
          <div className="cmp-wrap" tabIndex={0} role="region" aria-label="Provenance classes, scrolls sideways on narrow screens">
            <table className="cmp">
              <thead>
                <tr>
                  <th scope="col">Class</th>
                  <th scope="col">What it means</th>
                  <th scope="col">Tier ceiling</th>
                  <th scope="col">Says something about this unit?</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row"><code>read_from_machine</code> (machine-read)</th>
                  <td>A hash computed from the artefact as it was read off the machine.</td>
                  <td>validated</td>
                  <td>Yes. The only class that does. But the software never sees where a hash was read: this is the filer&apos;s assertion, and an exported case says so beside the label.</td>
                </tr>
                <tr>
                  <th scope="row"><code>supplied_by_vendor</code> (vendor-supplied)</th>
                  <td>A hash computed from a file the supplier provided.</td>
                  <td>community</td>
                  <td>No. It says what should be there, not what is.</td>
                </tr>
                <tr>
                  <th scope="row"><code>declared</code></th>
                  <td>Somebody typed a version number. Nothing was hashed.</td>
                  <td>profile</td>
                  <td>No.</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="pricing-note">
            The ladder is <em>profile</em> (a datasheet; nothing run), <em>community</em> (a contract suite against a
            simulator or fake; no physical run), <em>validated</em> (recorded results from the physical system under
            stated conditions) and <em>certified</em> (an accredited body&apos;s certificate). A trace&apos;s
            declared provenance is capped at community unless a signed recorder attestation is accepted under a trust
            list the verifier holds.
          </p>
        </div>
      </section>

      <section className="section" id="prove">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">What a record can prove</span>
            <h2>Editing, deletion and authorship are three different questions</h2>
          </div>
          <ul className="ruled">
            <li>
              <h3>A hash chain catches editing</h3>
              <p>Each record is sealed to the one before it. Change a record and the chain from there on no longer verifies.</p>
            </li>
            <li>
              <h3>It does not catch deletion by itself</h3>
              <p>
                A chain rebuilt from the start after removing inconvenient records still verifies. A counter-signature
                over the ledger head, by a key the ledger&apos;s operator does not hold, is what can show a ledger was
                shortened. Records after the last signed head are covered by no signature.
              </p>
            </li>
            <li>
              <h3>A hosted operator holds both</h3>
              <p>
                A hosted ledger&apos;s operator holds the ledger and the signing key, so keep your own copy of a signed
                attestation. A head that was merely told to the signer (<code>declared_by_holder</code>) is reported as
                declared and never counts as anchored; only a head the signer read from the ledger can anchor a file.
                A counter-signing key is not configured on any deployment today.
              </p>
            </li>
            <li>
              <h3>Integrity is not authenticity is not safety</h3>
              <p>
                An accepted recorder attestation shows only that a key you trust signed those trace bytes. It does not
                show the recorder was honest, or that the machine behaved as recorded, or that it is physically safe.
                A named operator is a credential-to-name binding; there is no identity proofing.
              </p>
            </li>
          </ul>
        </div>
      </section>

      <section className="section section-alt" id="permissions">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Permissions and decisions</span>
            <h2>Entitlements are read on every request. Decisions are a named person&apos;s.</h2>
          </div>
          <ul className="ruled">
            <li>
              <h3>401 and 402 mean different things</h3>
              <p>
                No or an invalid key is 401. A valid key on a plan that does not include the route is 402, with the
                remedy named. The same domain function sits behind the CLI, the HTTP API and the MCP server.
              </p>
            </li>
            <li>
              <h3>Case decisions need an operator with the decider role</h3>
              <p>
                Closing, rejecting, deferring, resuming, answering an open question or waiving a re-verification needs a
                key issued to an individual operator with the <code>decider</code> role. The server attributes the
                action by credential: a different name in the body is refused, and an account-level key (what an agent,
                MCP client or watch holds) is refused. A waiver is recorded as a waiver, never as current evidence.
              </p>
            </li>
            <li>
              <h3>Awareness, the Article 14 track and case closure are human decisions</h3>
              <p>
                Software drafts. Detecting and reporting can be automated; deciding that evidence stands again cannot.
                An AI never decides a safety conclusion, and the MCP server exposes no tool to decide a case or change
                a key or trust decision.
              </p>
            </li>
            <li>
              <h3>Trust is set on your machine, not ours</h3>
              <p>
                Key and trust-file tooling (generating keys, recorder trust lists, pinning supplier keys) runs on the
                operator&apos;s own machine. No hosted route or tool can supply a key or a trust decision.
              </p>
            </li>
          </ul>
        </div>
      </section>

      <section className="section" id="architecture">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Security architecture</span>
            <h2>The design, in plain language</h2>
          </div>
          <ul className="ruled">
            <li>
              <h3>Stateless checks and stateful records are separate</h3>
              <p>
                Checks that take a file and answer (validate, diff, advisory check, bundle and passport re-check) hold
                nothing. Anything that writes goes to a ledger, behind an entitlement gate that the live application is
                tested against: a route without a stated gate fails the test suite.
              </p>
            </li>
            <li>
              <h3>Absent data is never a pass</h3>
              <p>
                <em>unchecked</em> and <em>incomplete</em> are valid outcomes. Missing, mocked or assumed data is never
                read as verification. A CVE no recorded source mentions is reported unknown, never clear, and absence
                from KEV is not evidence that a vulnerability is not exploited.
              </p>
            </li>
            <li>
              <h3>Supplier advisories are verified before they are believed</h3>
              <p>
                A feed signed under a key your account pinned can open a case without a named person; an unsigned or
                unpinned advisory cannot. A re-issued feed is checked against a rollback baseline. A vendor advisory
                describes a product, not what you installed.
              </p>
            </li>
            <li>
              <h3>The offline kit opens no sockets</h3>
              <p>
                That is enforced by a guard in the process, not asserted by a policy page. <code>kit check</code> lists
                every file a run would open and touches nothing, so your IT department can review it first.
              </p>
            </li>
          </ul>
        </div>
      </section>

      <section className="section" id="data-principles">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Data principles</span>
            <h2>How evidence data is treated, and what does not exist</h2>
          </div>
          <div className="note-box">
            <ul>
              <li>Your evidence is yours. Tenant records live in a per-account ledger; the shared ledger is operator-only.</li>
              <li>
                No dataset has been assembled from customer evidence and no model has been trained on it. None exists,
                and none is offered or priced.
              </li>
              <li>
                Any future use of evidence beyond serving the account that produced it, for example to calibrate
                thresholds, would be a principle first: opt-in per account, in writing, with the account able to
                withdraw, and stripped of machine and site identity. Until that is built and documented, nothing of
                the kind happens.
              </li>
              <li>Software never decides a safety conclusion, and a statistic from many fleets would not change that.</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="section section-alt" id="limits">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Limitations</span>
            <h2>What this does not do</h2>
          </div>
          <div className="note-box">
            <ul>
              <li>It does not make anyone compliant, certified or safe. People decide and file.</li>
              <li>It cannot tell where a hash was read. A machine-read item is the filer&apos;s statement.</li>
              <li>A recorded verification covers the configuration it named. It says nothing about how the machine behaves outside the declared envelope.</li>
              <li>Machine verification is a recorded run checked against a declared envelope. It is not a hazard analysis and not a substitute for one.</li>
              <li>Inventory, CSAF and public-source importers are file-based and evolving, not supported connectors. The adapters of the wider platform are marked evolving unless the README says Supported.</li>
              <li>The workspace screens show what the API returns and nothing else. A deployment with no API address shows that, rather than a placeholder.</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="section" id="not-claimed">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Not claimed</span>
            <h2>Things this page does not say, so you do not have to look for them</h2>
          </div>
          <div className="note-box">
            <ul>
              <li>No security certification, attestation report or independent audit of NeuralBridge is claimed or cited here.</li>
              <li>No uptime, availability or response-time commitment is made. The security policy states plainly that no acknowledgement or fix date is guaranteed.</li>
              <li>No customer, deployment or result is cited. None has been validated.</li>
            </ul>
            <p>
              To report a vulnerability, see <a href="/security">security reporting</a>. For anything else,{' '}
              <a href={SALES}>contact NeuralBridge</a>.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
