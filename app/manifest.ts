import type { MetadataRoute } from 'next';
import { BRAND } from './lib/seo';

// Name, colours and icons for "add to home screen" and for browsers that read a manifest. `display` is
// `browser` on purpose: the site has no service worker and no offline mode, so it does not claim to be
// an installed app. The colours match viewport.themeColor in app/layout.tsx.
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: BRAND,
    short_name: 'IAA',
    description:
      'Evidence infrastructure for CRA Article 14 and Machinery Regulation Annex III 1.1.9: a hash-chained record of what is on each machine, which checks were run against it, and when.',
    start_url: '/',
    scope: '/',
    display: 'browser',
    lang: 'en',
    background_color: '#0f1b2d',
    theme_color: '#0f1b2d',
    icons: [
      { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/icons/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
  };
}
