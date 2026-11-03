// Whether this build of the site has a hosted Assurance API behind it.
//
// NEXT_PUBLIC_ASSURANCE_API_URL is inlined at build time. When it is unset the "try it right here"
// playgrounds have nowhere to send a request, so any copy that promises an anonymous online check
// ("free, no account", "try it right here") would be false until the visitor clicks Run. Copy that
// makes that promise must branch on this flag; tests/test_site_cta_hosting.py fails if it does not.
export const HOSTED_API = Boolean(process.env.NEXT_PUBLIC_ASSURANCE_API_URL);
