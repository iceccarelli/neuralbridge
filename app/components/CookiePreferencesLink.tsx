'use client';

export default function CookiePreferencesLink({ className }: { className?: string }) {
  return (
    <button
      type="button"
      className={className}
      onClick={() => window.dispatchEvent(new Event('iaa:open-cookie-preferences'))}
    >
      Cookie Preferences
    </button>
  );
}
