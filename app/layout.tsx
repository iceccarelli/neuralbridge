import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import Header from './Header';
import './globals.css';

export const metadata: Metadata = {
  metadataBase: new URL('https://neuralbridge.vercel.app'),
  title: 'NeuralBridge | Lightweight Integration Hub for AI Agents & External Systems',
  description:
    'Open-source middleware that lets any AI agent (LangChain, AutoGPT, OpenClaw, Claude, ChatGPT) securely connect to any API, database, or enterprise system via simple YAML configuration. FastAPI backend • MCP Gateway • React Dashboard • 22+ Adapters • Audit Trail • Zero-Trust Foundations. Production-ready foundation for deterministic agentic workflows.',
  keywords: [
    'NeuralBridge',
    'AI Integration Middleware',
    'MCP Gateway',
    'LangChain Tools',
    'AutoGPT Integration',
    'OpenClaw Plugin',
    'FastAPI Backend',
    'YAML Configuration',
    'Agentic AI Infrastructure',
    'Secure AI Adapters',
    'Audit Trail for AI',
    'Model Context Protocol',
    'Deterministic AI Workflows',
    'Enterprise System Connectors',
    'PostgreSQL Adapter',
    'REST API Gateway for AI',
  ],
  authors: [{ name: 'Vincenzo Grimaldi', url: 'https://github.com/iceccarelli' }],
  creator: 'Vincenzo Grimaldi',
  publisher: 'NeuralBridge Project',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'NeuralBridge | Lightweight Integration Hub for AI Agents',
    description: 'The missing infrastructure layer for agentic AI. Securely bridge AI reasoning to real-world systems with YAML config, MCP gateway, and full auditability. Open source on GitHub.',
    url: 'https://neuralbridge.vercel.app/',
    siteName: 'NeuralBridge',
    locale: 'en_GB',
    type: 'website',
    images: [
      {
        url: 'https://neuralbridge.vercel.app/og-image.jpg',
        width: 1200,
        height: 630,
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'NeuralBridge | AI Integration Middleware',
    description: 'Connect any AI agent to any system. FastAPI • MCP • Adapters • Dashboard. Open source.',
  },
};

const structuredData = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'NeuralBridge',
  url: 'https://neuralbridge.vercel.app/',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Cross-platform',
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
  },
  description:
    'Lightweight open-source integration hub that enables AI agents to securely interact with external systems through a clean backend, MCP gateway, modular adapters, and comprehensive audit trail.',
  creator: {
    '@type': 'Person',
    name: 'Vincenzo Grimaldi',
    url: 'https://github.com/iceccarelli',
  },
  sameAs: ['https://github.com/iceccarelli/neuralbridge'],
  featureList: [
    '22+ Production Adapters (PostgreSQL, REST, Slack, Notion, and more)',
    'MCP Gateway for AI Tool Exposure',
    'FastAPI Backend with Connection Management',
    'React + TypeScript Dashboard',
    'Built-in Audit Trail & Observability',
    'YAML-Driven Configuration',
    'Zero-Trust Security Foundations',
    'EU CRA & Compliance Building Blocks',
  ],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="site-chrome">
          <div className="background-orb orb-one" />
          <div className="background-orb orb-two" />
          <div className="background-orb orb-three" />

          <Header />

          {children}

          <footer className="site-footer">
            <div className="section-shell">
              <div className="footer-content">
                {/* Column 1 – Entity */}
                <div>
                  <div className="brand-lockup" style={{ marginBottom: '1rem' }}>
                    <span className="brand-monogram" style={{ width: '42px', height: '42px', fontSize: '1.25rem', background: 'linear-gradient(135deg, #34d399, #10b981)' }}>NB</span>
                    <span className="brand-copy"><strong>NeuralBridge</strong></span>
                  </div>
                  <p style={{ color: 'var(--muted-strong)', lineHeight: '1.6', fontSize: '0.95rem' }}>
                    Lightweight Integration Hub for Agentic AI<br />
                    Connect AI reasoning to real-world systems — deterministically, audibly, and securely.<br />
                    <span style={{ color: '#34d399' }}>Open source • Self-hostable • Production foundation</span>
                  </p>
                  <p style={{ marginTop: '2rem', fontSize: '0.85rem', color: 'var(--muted)' }}>
                    © 2026 NeuralBridge Project • MIT Licensed • Built by Vincenzo Grimaldi
                  </p>
                </div>

                {/* Column 2 – Platform */}
                <div className="footer-column">
                  <h4>Platform</h4>
                  <div className="footer-links" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <a className="footer-link" href="#architecture">Architecture</a>
                    <a className="footer-link" href="#adapters">Supported Adapters</a>
                    <a className="footer-link" href="#live-hub">Live Intelligence</a>
                    <a className="footer-link" href="https://github.com/iceccarelli/neuralbridge#readme" target="_blank" rel="noopener noreferrer">Documentation</a>
                    <a className="footer-link" href="https://github.com/iceccarelli/neuralbridge/blob/main/ROADMAP.md" target="_blank" rel="noopener noreferrer">Roadmap</a>
                  </div>
                </div>

                {/* Column 3 – Ecosystem */}
                <div className="footer-column">
                  <h4>Ecosystem</h4>
                  <div className="footer-links" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <a className="footer-link" href="https://github.com/iceccarelli/neuralbridge" target="_blank" rel="noopener noreferrer">GitHub Repository</a>
                    <a className="footer-link" href="https://github.com/iceccarelli/neuralbridge/stargazers" target="_blank" rel="noopener noreferrer">Star on GitHub ★</a>
                    <a className="footer-link" href="https://openclawdir.com/plugins/neuralbridge-cdez2o" target="_blank" rel="noopener noreferrer">OpenClaw Plugin</a>
                    <div className="footer-status">
                      <span className="live-dot" />
                      <span>Active Development • v0.1.1</span>
                    </div>
                  </div>
                </div>

                {/* Column 4 – System Status */}
                <div className="footer-column">
                  <h4>System Status</h4>
                  <div className="footer-status" style={{ marginBottom: '1rem' }}>
                    <span className="live-dot" />
                    <span style={{ color: 'var(--success)', fontWeight: 600 }}>Ready for Production Use</span>
                  </div>
                  <p style={{ color: 'var(--muted)', fontSize: '0.9rem', lineHeight: '1.55' }}>
                    Self-host anywhere • Docker ready<br />
                    Connect your AI agents today.
                  </p>
                  <a 
                    href="https://github.com/iceccarelli/neuralbridge" 
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: 'var(--accent-strong)', marginTop: '1.5rem', display: 'inline-block' }}
                  >
                    Clone &amp; Deploy on GitHub →
                  </a>
                </div>
              </div>
            </div>
          </footer>
        </div>

        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
        />
      </body>
    </html>
  );
}
