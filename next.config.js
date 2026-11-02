/** @type {import('next').NextConfig} */
const nextConfig = {
  // tests/test_site_repo_links.py builds into its own directory so it never clobbers `.next`.
  distDir: process.env.NEXT_DIST_DIR || '.next',
  reactStrictMode: true,
  // Always define the flag (exactly 'true' or 'false') so Next inlines it at build time even when it
  // is unset; the dead branch, and the repository URL in it, is then dropped from the bundles.
  env: { NEXT_PUBLIC_REPO_PUBLIC: process.env.NEXT_PUBLIC_REPO_PUBLIC === 'true' ? 'true' : 'false' },
  // Next 16 raised the image optimizer's default cache TTL from 60 s to 4 h, so a replaced image at
  // the same URL would stay stale that long. Keep the 14.x behaviour explicitly.
  images: { minimumCacheTTL: 60 },
  // Next 16's dev server refuses dev resources (HMR, client chunks) requested from an origin it
  // does not know, so a page opened at http://127.0.0.1:<port> never hydrates. The browser e2e
  // (scripts/e2e-assurance.sh) and the documented local stack use 127.0.0.1. This setting has no
  // effect on `next build` / `next start`.
  allowedDevOrigins: ['127.0.0.1', 'localhost'],
  // Do not advertise the framework in a response header.
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          // The site is never meant to be framed. Both forms: X-Frame-Options for old browsers,
          // frame-ancestors for current ones. This is the ONLY CSP directive set: a script/style policy
          // would have to allow Next's inline bootstrap scripts and the inline JSON-LD, and has not been
          // verified in a real browser here (see scripts/seo_audit.mjs), so none is claimed.
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Content-Security-Policy', value: "frame-ancestors 'none'" },
          // Nothing on the site uses these; deny them rather than leave them to an embedded script.
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
      {
        // Files in public/images are served as-is and never carry a hash in the name, so cache for a day
        // and let a stale copy be served while it revalidates; /_next/static is already immutable.
        source: '/images/:path*',
        headers: [{ key: 'Cache-Control', value: 'public, max-age=86400, stale-while-revalidate=604800' }],
      },
    ];
  },
};

module.exports = nextConfig;
