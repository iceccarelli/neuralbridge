// The pictures on this site are generated illustrations (app/lib/images.ts), not photographs of any
// machine, plant or customer. Rendered once, as visible text, at the foot of every page that shows
// rotating imagery; tests/test_site_honesty.py::TestGeneratedImageryIsDisclosed finds those pages by
// following imports to RotatingImage and fails if one lacks this component.
export default function ImageryNote() {
  return (
    <p className="imagery-note">
      Illustrative images, not photographs of a customer site. The images are generated.
    </p>
  );
}
