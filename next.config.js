/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Next 16's dev server refuses dev resources (HMR, client chunks) requested from an origin it
  // does not know, so a page opened at http://127.0.0.1:<port> never hydrates. The browser e2e
  // (scripts/e2e-assurance.sh) and the documented local stack use 127.0.0.1. This setting has no
  // effect on `next build` / `next start`.
  allowedDevOrigins: ['127.0.0.1', 'localhost'],
};

module.exports = nextConfig;
