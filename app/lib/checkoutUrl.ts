// Where the checkout API may send the buyer. The address comes from an API response, so it is
// checked before the page navigates: only an https address (or plain http on a loopback host,
// for local development) is followed. Anything else (`javascript:`, `data:`, `file:`, a relative
// or malformed value, an http address on a real host) is refused and the caller shows an error.
export function safeCheckoutUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.trim() === '' || value.length > 2048) return null;
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    return null;
  }
  if (url.username || url.password) return null;
  if (url.protocol === 'https:') return url.toString();
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol === 'http:' && loopback) return url.toString();
  return null;
}
