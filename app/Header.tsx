'use client';

import { useState } from 'react';

const REPO = 'https://github.com/iceccarelli/neuralbridge';

export default function Header() {
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const toggle = (name: string) => setOpenMenu((current) => (current === name ? null : name));

  return (
    <header>
      <div className="utility-bar">
        <div className="shell utility-bar-inner">
          <span>Evidence infrastructure for CRA Art. 14 and Machinery Reg. 2023/1230</span>
          <div className="utility-links">
            <a href={`${REPO}/blob/main/deploy/assurance/README.md`} target="_blank" rel="noreferrer">
              Deploy docs
            </a>
            <a href={`${REPO}/issues/new?title=Sales+inquiry`} target="_blank" rel="noreferrer">
              Contact sales
            </a>
            <a href={REPO} target="_blank" rel="noreferrer">
              GitHub
            </a>
          </div>
        </div>
      </div>

      <div className="topbar" onMouseLeave={() => setOpenMenu(null)}>
        <div className="shell topbar-inner">
          <a className="brand-lockup" href="#top">
            <span className="brand-mark">IAA</span>
            <span className="brand-name">Industrial Autonomous Assurance</span>
          </a>

          <nav className="topbar-nav" aria-label="Primary">
            <div className={`nav-item ${openMenu === 'products' ? 'open' : ''}`}>
              <button onClick={() => toggle('products')} aria-expanded={openMenu === 'products'}>
                Products <span className="caret">▾</span>
              </button>
              <div className="mega-panel cols-3">
                <div className="mega-col">
                  <h4>Assurance plans</h4>
                  <a href="#pricing">Validator — free</a>
                  <a href="#pricing">Register — €390/mo</a>
                  <a href="#pricing">Cell — €1,290/mo</a>
                </div>
                <div className="mega-col">
                  <h4>Assurance engines</h4>
                  <a href="#products">Machine safety verification</a>
                  <a href="#products">Machinery Annex III</a>
                  <a href="#products">Fleet advisory</a>
                  <a href="#products">Attest &amp; watch</a>
                </div>
                <div className="mega-col">
                  <h4>Platform</h4>
                  <a href="#platform">NeuralBridge FastAPI core</a>
                  <a href="#platform">MCP gateway</a>
                  <a href="#platform">Dashboard</a>
                  <p style={{ marginTop: '0.5rem' }}>The integration layer the assurance product is built on.</p>
                </div>
              </div>
            </div>

            <div className={`nav-item ${openMenu === 'solutions' ? 'open' : ''}`}>
              <button onClick={() => toggle('solutions')} aria-expanded={openMenu === 'solutions'}>
                Solutions <span className="caret">▾</span>
              </button>
              <div className="mega-panel cols-2">
                <div className="mega-col">
                  <h4>By buyer</h4>
                  <a href="#solutions">Manufacturer</a>
                  <a href="#solutions">Plant operator</a>
                  <a href="#solutions">Compliance officer</a>
                </div>
                <div className="mega-col">
                  <h4>&nbsp;</h4>
                  <a href="#solutions">Insurer / auditor</a>
                  <a href="#solutions">AI / ops platform team</a>
                </div>
              </div>
            </div>

            <a href="#pricing">Pricing</a>
            <a href={`${REPO}#readme`} target="_blank" rel="noreferrer">
              Docs
            </a>
            <a href={`${REPO}/blob/main/CONTRIBUTING.md`} target="_blank" rel="noreferrer">
              Partners
            </a>
            <a href={`${REPO}/blob/main/ROADMAP.md`} target="_blank" rel="noreferrer">
              Resources
            </a>
          </nav>

          <div className="topbar-actions">
            <a className="nav-cta ghost" href={`${REPO}/issues/new?title=Sales+inquiry`} target="_blank" rel="noreferrer">
              Talk to sales
            </a>
            <a className="nav-cta primary" href="#pricing">
              Start free
            </a>
            <button className="hamburger" onClick={() => setMobileMenuOpen((v) => !v)} aria-label="Toggle menu">
              <span className="bar" />
              <span className="bar" />
              <span className="bar" />
            </button>
          </div>
        </div>

        <div className={`mobile-menu ${mobileMenuOpen ? 'open' : ''}`}>
          <a href="#products" onClick={() => setMobileMenuOpen(false)}>Products</a>
          <a href="#solutions" onClick={() => setMobileMenuOpen(false)}>Solutions</a>
          <a href="#pricing" onClick={() => setMobileMenuOpen(false)}>Pricing</a>
          <a href="#platform" onClick={() => setMobileMenuOpen(false)}>Platform</a>
          <a href={`${REPO}#readme`} target="_blank" rel="noreferrer">Docs</a>
          <a href={`${REPO}/issues/new?title=Sales+inquiry`} target="_blank" rel="noreferrer">Contact sales</a>
        </div>
      </div>
    </header>
  );
}
