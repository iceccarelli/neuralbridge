'use client';

import { useState, useEffect } from 'react';

function useScrollDirection() {
  const [scrollDirection, setScrollDirection] = useState<'up' | 'down' | null>(null);
  const [lastScrollY, setLastScrollY] = useState(0);

  useEffect(() => {
    let ticking = false;
    const update = () => {
      const current = window.scrollY;
      if (Math.abs(current - lastScrollY) > 50) {
        setScrollDirection(current > lastScrollY ? 'down' : 'up');
        setLastScrollY(current);
      }
      ticking = false;
    };

    const onScroll = () => {
      if (!ticking) {
        requestAnimationFrame(update);
        ticking = true;
      }
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, [lastScrollY]);

  return scrollDirection;
}

export default function Header() {
  const scrollDirection = useScrollDirection();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const isNavbarHidden = scrollDirection === 'down';

  useEffect(() => {
    if (mobileMenuOpen && window.scrollY > 300) setMobileMenuOpen(false);
  }, [mobileMenuOpen]);

  const navigation = [
    { label: 'Features', href: '#features' },
    { label: 'Architecture', href: '#architecture' },
    { label: 'Adapters', href: '#adapters' },
    { label: 'Live Hub', href: '#live-hub' },
    { label: 'Docs', href: 'https://github.com/iceccarelli/neuralbridge#readme', external: true },
  ];

  return (
    <header className={`topbar ${isNavbarHidden ? 'hidden' : ''}`}>
      <div className="topbar-inner">
        {/* Brand Lockup */}
        <a className="brand-lockup" href="#top">
          <span className="brand-monogram" style={{ background: 'linear-gradient(135deg, #34d399, #10b981)' }}>NB</span>
          <span className="brand-copy">
            <strong>NeuralBridge</strong>
            <small>AI Integration Middleware</small>
          </span>
        </a>

        {/* Primary Navigation */}
        <nav className="topbar-nav" aria-label="Primary navigation">
          {navigation.map((item) => (
            item.external ? (
              <a 
                key={item.href} 
                href={item.href} 
                target="_blank" 
                rel="noopener noreferrer"
                className="flex items-center gap-1"
              >
                {item.label}
              </a>
            ) : (
              <a key={item.href} href={item.href}>
                {item.label}
              </a>
            )
          ))}
        </nav>

        <div className="flex items-center gap-4">
          {/* GitHub CTA */}
          <a
            className="topbar-button"
            href="https://github.com/iceccarelli/neuralbridge"
            target="_blank"
            rel="noopener noreferrer"
          >
            ★ Star on GitHub
          </a>

          {/* Mobile Hamburger */}
          <button
            className="hamburger"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle mobile menu"
          >
            <span className="bar" />
            <span className="bar" />
            <span className="bar" />
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      <div className={`mobile-menu ${mobileMenuOpen ? 'open' : ''}`}>
        {navigation.map((item) => (
          item.external ? (
            <a
              key={item.href}
              href={item.href}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => setMobileMenuOpen(false)}
            >
              {item.label}
            </a>
          ) : (
            <a
              key={item.href}
              href={item.href}
              onClick={() => setMobileMenuOpen(false)}
            >
              {item.label}
            </a>
          )
        ))}
        <a
          href="https://github.com/iceccarelli/neuralbridge"
          target="_blank"
          rel="noopener noreferrer"
          onClick={() => setMobileMenuOpen(false)}
          style={{ marginTop: '1rem', fontWeight: 600 }}
        >
          ★ Star on GitHub →
        </a>
      </div>
    </header>
  );
}
