'use client';

// "Skip to main content" that also moves keyboard focus: following a #hash alone scrolls, but in
// some browsers leaves the next Tab starting from the top of the page again (WCAG 2.4.1 / 2.4.3).
export default function SkipLink() {
  return (
    <a
      className="skip-link"
      href="#top"
      onClick={() => {
        const main = document.getElementById('top');
        if (!main) return;
        main.setAttribute('tabindex', '-1');
        main.focus({ preventScroll: true });
      }}
    >
      Skip to main content
    </a>
  );
}
