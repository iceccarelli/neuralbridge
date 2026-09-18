'use client';

import { useEffect, useRef, useState } from 'react';
import { DEPLOY_BLOB, DOCS, REPO, SALES, SRC } from './lib/links';
import { SOLUTIONS } from './lib/solutions';
import SearchOverlay from './components/SearchOverlay';

type MenuKey = 'products' | 'solutions' | 'pricing' | 'resources';
type ProductsPane = 'plans' | 'engines' | 'platform';
type MobileView = 'root' | 'products' | 'solutions' | 'resources';

const PRODUCTS_PANES: Record<ProductsPane, { label: string; cards: { name: string; blurb: string; href: string; external?: boolean }[] }> = {
  plans: {
    label: 'Plans',
    cards: [
      { name: 'Validator — free', blurb: 'Article 14 draft validation, calculators, offline kit. No account.', href: '#pricing' },
      { name: 'Register — €390/mo', blurb: 'The Article 14 register for one manufacturer.', href: '#pricing' },
      { name: 'Cell — €1,290/mo', blurb: 'Register, plus machine and fleet-level assurance.', href: '#pricing' },
    ],
  },
  engines: {
    label: 'Engines',
    cards: [
      { name: 'Machine safety verification', blurb: 'ISO/TS 15066 checks against a declared envelope.', href: `${DEPLOY_BLOB}/MACHINE.md`, external: true },
      { name: 'Machinery Annex III', blurb: 'The safety software manifest and the staleness join.', href: `${DEPLOY_BLOB}/MACHINERY.md`, external: true },
      { name: 'Fleet advisory', blurb: 'One advisory, fanned out by hash across a fleet.', href: `${DEPLOY_BLOB}/FLEET.md`, external: true },
      { name: 'Watch', blurb: 'The component that runs when nobody is looking.', href: `${DEPLOY_BLOB}/WATCH.md`, external: true },
      { name: 'Attest', blurb: 'Counter-signed head attestation; catches deletion.', href: `${DEPLOY_BLOB}/ATTEST.md`, external: true },
      { name: 'Offline enrolment kit', blurb: 'Your ledger, your disk. No account, no upload.', href: `${DEPLOY_BLOB}/KIT.md`, external: true },
    ],
  },
  platform: {
    label: 'Platform',
    cards: [
      { name: 'NeuralBridge FastAPI core', blurb: 'Connection management the assurance product is built on.', href: '#platform' },
      { name: 'MCP gateway', blurb: 'Tool listing and invocation for AI agents.', href: '#platform' },
      { name: 'Assurance API', blurb: '42 routes; GET /v1/plans mirrors enforced entitlements.', href: `${SRC}/api`, external: true },
      { name: 'Dashboard', blurb: 'Next.js console — not yet integrated with assurance.', href: '#platform' },
    ],
  },
};

export default function Header() {
  const [openMenu, setOpenMenu] = useState<MenuKey | null>(null);
  const [productsPane, setProductsPane] = useState<ProductsPane>('plans');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileView, setMobileView] = useState<MobileView>('root');
  const [searchOpen, setSearchOpen] = useState(false);
  const [langOpen, setLangOpen] = useState(false);
  const headerRef = useRef<HTMLElement>(null);

  const closeAll = () => {
    setOpenMenu(null);
    setLangOpen(false);
  };

  const toggle = (name: MenuKey) => {
    setLangOpen(false);
    setOpenMenu((current) => (current === name ? null : name));
  };

  // Escape closes whatever overlay is open; click outside the header closes megas/language.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (searchOpen) setSearchOpen(false);
      else if (mobileOpen) setMobileOpen(false);
      else closeAll();
    };
    const onClick = (e: MouseEvent) => {
      if (headerRef.current && !headerRef.current.contains(e.target as Node)) closeAll();
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('mousedown', onClick);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('mousedown', onClick);
    };
  }, [searchOpen, mobileOpen]);

  // Lock body scroll while a full-screen overlay is open.
  useEffect(() => {
    document.body.style.overflow = mobileOpen || searchOpen ? 'hidden' : '';
    return () => {
      document.body.style.overflow = '';
    };
  }, [mobileOpen, searchOpen]);

  const pane = PRODUCTS_PANES[productsPane];

  return (
    <header ref={headerRef}>
      <div className="sticky-chrome">
        <div className="utility-bar">
          <div className="shell utility-bar-inner">
            <span>Evidence infrastructure for CRA Art. 14 and Machinery Reg. 2023/1230</span>
            <div className="utility-links">
              <a href={`${REPO}/blob/main/deploy/assurance/README.md`} target="_blank" rel="noreferrer">Deploy docs</a>
              <a href={SALES} target="_blank" rel="noreferrer">Contact sales</a>
              <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
            </div>
          </div>
        </div>

        <div className="topbar">
          <div className="shell topbar-inner">
            <a className="brand-lockup" href="#top" onClick={closeAll}>
              <span className="brand-mark">IAA</span>
              <span className="brand-name">Industrial Autonomous Assurance</span>
            </a>

            <nav className="topbar-nav" aria-label="Primary">
              <div className={`nav-item ${openMenu === 'products' ? 'open' : ''}`}>
                <button onClick={() => toggle('products')} aria-expanded={openMenu === 'products'} aria-haspopup="true">
                  Products <span className="caret">▾</span>
                </button>
              </div>
              <div className={`nav-item ${openMenu === 'solutions' ? 'open' : ''}`}>
                <button onClick={() => toggle('solutions')} aria-expanded={openMenu === 'solutions'} aria-haspopup="true">
                  Solutions <span className="caret">▾</span>
                </button>
              </div>
              <div className={`nav-item ${openMenu === 'pricing' ? 'open' : ''}`}>
                <button onClick={() => toggle('pricing')} aria-expanded={openMenu === 'pricing'} aria-haspopup="true">
                  Pricing <span className="caret">▾</span>
                </button>
              </div>
              <div className={`nav-item ${openMenu === 'resources' ? 'open' : ''}`}>
                <button onClick={() => toggle('resources')} aria-expanded={openMenu === 'resources'} aria-haspopup="true">
                  Resources <span className="caret">▾</span>
                </button>
              </div>
            </nav>

            <div className="topbar-actions">
              <button className="icon-button" aria-label="Search" onClick={() => setSearchOpen(true)}>⌕</button>

              <div className={`nav-item lang-item ${langOpen ? 'open' : ''}`}>
                <button
                  className="icon-button lang-button"
                  aria-label="Language"
                  aria-expanded={langOpen}
                  onClick={() => {
                    setOpenMenu(null);
                    setLangOpen((v) => !v);
                  }}
                >
                  🌐 EN
                </button>
                <div className="mega-panel lang-panel">
                  <div className="mega-col">
                    <a href="#top" onClick={() => setLangOpen(false)}>English (detected)</a>
                    <span className="lang-stub">Deutsch — coming soon</span>
                  </div>
                </div>
              </div>

              <a className="nav-cta ghost" href={SALES} target="_blank" rel="noreferrer">Talk to sales</a>
              <a className="nav-cta primary" href="#pricing">Start free</a>

              <button
                className="hamburger"
                onClick={() => {
                  setMobileView('root');
                  setMobileOpen(true);
                }}
                aria-label="Open menu"
              >
                <span className="bar" />
                <span className="bar" />
                <span className="bar" />
              </button>
            </div>
          </div>

          {/* PRODUCTS mega: two-pane */}
          <div className={`mega-panel mega-panel-full two-pane ${openMenu === 'products' ? 'is-open' : ''}`}>
            <button className="mega-close" aria-label="Close menu" onClick={closeAll}>✕</button>
            <div className="shell two-pane-inner">
              <div className="pane-rail">
                {(Object.keys(PRODUCTS_PANES) as ProductsPane[]).map((key) => (
                  <button
                    key={key}
                    className={`pane-rail-item ${productsPane === key ? 'active' : ''}`}
                    onClick={() => setProductsPane(key)}
                  >
                    {PRODUCTS_PANES[key].label}
                  </button>
                ))}
              </div>
              <div className="pane-cards">
                <div className="mega-panel-grid cols-3">
                  {pane.cards.map((card) => (
                    <a
                      key={card.name}
                      className="mega-card"
                      href={card.href}
                      target={card.external ? '_blank' : undefined}
                      rel={card.external ? 'noreferrer' : undefined}
                      onClick={closeAll}
                    >
                      <strong>{card.name}</strong>
                      <span>{card.blurb}</span>
                    </a>
                  ))}
                </div>
                <div className="mega-promo-row">
                  <a className="mega-promo" href={DOCS} target="_blank" rel="noreferrer" onClick={closeAll}>
                    <span className="mega-promo-kicker">Docs</span>
                    <strong>Browse the docs site</strong>
                  </a>
                  <a className="mega-promo" href={`${REPO}/blob/main/ROADMAP.md`} target="_blank" rel="noreferrer" onClick={closeAll}>
                    <span className="mega-promo-kicker">Roadmap</span>
                    <strong>What&apos;s planned next</strong>
                  </a>
                </div>
              </div>
            </div>
          </div>

          {/* SOLUTIONS mega: editorial */}
          <div className={`mega-panel mega-panel-full editorial ${openMenu === 'solutions' ? 'is-open' : ''}`}>
            <button className="mega-close" aria-label="Close menu" onClick={closeAll}>✕</button>
            <div className="shell editorial-inner">
              <div className="editorial-cards">
                {SOLUTIONS.map((item) => (
                  <a className="editorial-card" href={`/solutions/${item.slug}`} key={item.slug} onClick={closeAll}>
                    <strong>{item.role}</strong>
                    <span>{item.headline}</span>
                    <span className="editorial-cta">View solution →</span>
                  </a>
                ))}
              </div>
              <div className="editorial-about">
                <span className="mega-promo-kicker">About</span>
                <h4>Why this exists</h4>
                <p>Two regulations turned a quality problem into a legal one. Read the case in full.</p>
                <a href={`${REPO}#readme`} target="_blank" rel="noreferrer" onClick={closeAll}>Read the README →</a>
              </div>
            </div>
          </div>

          {/* PRICING mega: finder-style */}
          <div className={`mega-panel mega-panel-full finder ${openMenu === 'pricing' ? 'is-open' : ''}`}>
            <button className="mega-close" aria-label="Close menu" onClick={closeAll}>✕</button>
            <div className="shell finder-inner">
              <a className="finder-item" href="#pricing" onClick={closeAll}>
                <strong>Free tier</strong>
                <span>Validator — Article 14 validation and calculators, no account.</span>
              </a>
              <a className="finder-item" href="#pricing" onClick={closeAll}>
                <strong>Compare plans</strong>
                <span>Validator, Register, Cell — full capability table.</span>
              </a>
              <a className="finder-item" href={SALES} target="_blank" rel="noreferrer" onClick={closeAll}>
                <strong>Talk to sales</strong>
                <span>Register and Cell route to a real inquiry — checkout isn&apos;t live yet.</span>
              </a>
            </div>
          </div>

          {/* RESOURCES mega */}
          <div className={`mega-panel mega-panel-full finder ${openMenu === 'resources' ? 'is-open' : ''}`}>
            <button className="mega-close" aria-label="Close menu" onClick={closeAll}>✕</button>
            <div className="shell finder-inner">
              <a className="finder-item" href={DOCS} target="_blank" rel="noreferrer" onClick={closeAll}>
                <strong>Documentation</strong>
                <span>The full docs site — getting started, every engine, deploying.</span>
              </a>
              <a className="finder-item" href={`${REPO}/blob/main/ROADMAP.md`} target="_blank" rel="noreferrer" onClick={closeAll}>
                <strong>Roadmap</strong>
                <span>What is planned and not yet built.</span>
              </a>
              <a className="finder-item" href={`${REPO}/blob/main/SECURITY.md`} target="_blank" rel="noreferrer" onClick={closeAll}>
                <strong>Security</strong>
                <span>How to report a vulnerability.</span>
              </a>
              <a className="finder-item" href={`${REPO}/blob/main/CONTRIBUTING.md`} target="_blank" rel="noreferrer" onClick={closeAll}>
                <strong>Contributing</strong>
                <span>How to propose a change to this repository.</span>
              </a>
            </div>
          </div>
        </div>
      </div>

      <button
        className={`mega-backdrop ${openMenu ? 'is-open' : ''}`}
        aria-hidden={openMenu === null}
        tabIndex={-1}
        onClick={closeAll}
      />

      <SearchOverlay open={searchOpen} onClose={() => setSearchOpen(false)} />

      {/* MOBILE: full-screen drill-in */}
      <div className={`mobile-drill ${mobileOpen ? 'open' : ''}`}>
        <div className="mobile-drill-header">
          {mobileView !== 'root' ? (
            <button className="mobile-back" onClick={() => setMobileView('root')}>‹ Back</button>
          ) : (
            <span className="brand-name">Menu</span>
          )}
          <button className="mobile-drill-close" aria-label="Close menu" onClick={() => setMobileOpen(false)}>✕</button>
        </div>

        <div className="mobile-drill-body">
          {mobileView === 'root' && (
            <>
              <button className="mobile-drill-item" onClick={() => setMobileView('products')}>Products <span>›</span></button>
              <button className="mobile-drill-item" onClick={() => setMobileView('solutions')}>Solutions <span>›</span></button>
              <a className="mobile-drill-item" href="#pricing" onClick={() => setMobileOpen(false)}>Pricing</a>
              <button className="mobile-drill-item" onClick={() => setMobileView('resources')}>Resources <span>›</span></button>
              <a className="mobile-drill-item" href="/privacy" onClick={() => setMobileOpen(false)}>Privacy</a>
            </>
          )}
          {mobileView === 'products' && (
            <>
              <a className="mobile-drill-item" href="#pricing" onClick={() => setMobileOpen(false)}>Validator — free</a>
              <a className="mobile-drill-item" href="#pricing" onClick={() => setMobileOpen(false)}>Register — €390/mo</a>
              <a className="mobile-drill-item" href="#pricing" onClick={() => setMobileOpen(false)}>Cell — €1,290/mo</a>
              <a className="mobile-drill-item" href="#products" onClick={() => setMobileOpen(false)}>All engines</a>
              <a className="mobile-drill-item" href="#platform" onClick={() => setMobileOpen(false)}>Platform</a>
            </>
          )}
          {mobileView === 'solutions' && (
            <>
              {SOLUTIONS.map((item) => (
                <a
                  className="mobile-drill-item"
                  href={`/solutions/${item.slug}`}
                  key={item.slug}
                  onClick={() => setMobileOpen(false)}
                >
                  {item.role}
                </a>
              ))}
            </>
          )}
          {mobileView === 'resources' && (
            <>
              <a className="mobile-drill-item" href={DOCS} target="_blank" rel="noreferrer">Documentation</a>
              <a className="mobile-drill-item" href={`${REPO}/blob/main/ROADMAP.md`} target="_blank" rel="noreferrer">Roadmap</a>
              <a className="mobile-drill-item" href={`${REPO}/blob/main/SECURITY.md`} target="_blank" rel="noreferrer">Security</a>
              <a className="mobile-drill-item" href={`${REPO}/blob/main/CONTRIBUTING.md`} target="_blank" rel="noreferrer">Contributing</a>
            </>
          )}
        </div>

        <div className="mobile-drill-sticky">
          <a className="btn btn-outline" href={SALES} target="_blank" rel="noreferrer" onClick={() => setMobileOpen(false)}>Talk to sales</a>
          <a className="btn btn-primary" href="#pricing" onClick={() => setMobileOpen(false)}>Start free</a>
        </div>
      </div>
    </header>
  );
}
