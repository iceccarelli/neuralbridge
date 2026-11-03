import { ImageResponse } from 'next/og';
import { BRAND, BRAND_SHORT, SITE_URL } from './seo';

// The 1200x630 card every social crawler (Facebook, LinkedIn, WhatsApp, Slack, iMessage, X) shows when a
// link is shared. One renderer for the site-wide card and the per-page cards, so the mark, colours and
// layout cannot drift. Flat colours and system text only: the PNG stays far below WhatsApp's size limit
// (tests/test_site_seo.py holds it under 300 KB). Nothing here is a claim: the words are the page's own.

export const OG_SIZE = { width: 1200, height: 630 } as const;
export const OG_CONTENT_TYPE = 'image/png';

export interface OgCardText {
  /** Small orange line above the headline (a page kind or regulation). */
  kicker: string;
  /** The headline; kept short by the caller (cut with `clip`). */
  title: string;
}

/** Cut at a word boundary so a long headline never overflows the card. */
export function clip(text: string, max: number): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  if (flat.length <= max) return flat;
  return `${flat.slice(0, max - 1).replace(/[\s,;:—-]+\S*$/, '')}…`;
}

export function ogCard({ kicker, title }: OgCardText): ImageResponse {
  const long = title.length > 80;
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '72px',
          background: '#0f1b2d',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '56px',
              height: '56px',
              borderRadius: '10px',
              background: '#ec7211',
              color: '#16191f',
              fontSize: '22px',
              fontWeight: 800,
            }}
          >
            {BRAND_SHORT}
          </div>
          <div style={{ color: '#ffffff', fontSize: '26px', fontWeight: 650 }}>{BRAND}</div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div
            style={{
              color: '#ec7211',
              fontSize: '22px',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '2px',
            }}
          >
            {kicker}
          </div>
          <div
            style={{
              color: '#ffffff',
              fontSize: long ? '46px' : '56px',
              fontWeight: 750,
              lineHeight: 1.15,
              maxWidth: '1000px',
            }}
          >
            {title}
          </div>
        </div>

        <div style={{ display: 'flex', color: '#9fb2c8', fontSize: '22px' }}>
          {SITE_URL.replace('https://', '')}
        </div>
      </div>
    ),
    { ...OG_SIZE }
  );
}

/** The app icon at any size: the same mark as app/icon.svg. `maskable` fills the square and keeps the mark inside the safe zone. */
export function iconImage(px: number, maskable = false): ImageResponse {
  const mark = Math.round(px * (maskable ? 0.34 : 0.4));
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#ec7211',
          color: '#16191f',
          fontSize: `${mark}px`,
          fontWeight: 800,
          fontFamily: 'sans-serif',
          borderRadius: maskable ? '0' : `${Math.round(px * 0.1875)}px`,
        }}
      >
        {BRAND_SHORT}
      </div>
    ),
    { width: px, height: px }
  );
}
