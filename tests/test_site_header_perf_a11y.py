"""Header, image delivery and form behaviours found by the browser audit, pinned in source.

The behaviour itself (focus return, inert background, lazy search) is exercised in a real browser by
tests-e2e/header-a11y.spec.ts; these tests keep the structure that makes it work from regressing in a
place a browser run is not part of CI, and pin the bundle-size decision.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _t(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


HEADER = _t("app/Header.tsx")


def test_header_does_not_import_the_page_data_modules():
    # Importing productPages.ts (80 KB of text) or solutions.ts into a client component ships them in
    # every route. The server layout passes only the links the Header renders.
    assert not re.search(r"from '\./lib/(productPages|solutions)'", HEADER)
    assert "productLinks" in HEADER and "solutionLinks" in HEADER


def test_search_overlay_is_loaded_on_first_open_only():
    assert re.search(r"dynamic\(\(\) => import\('\./components/SearchOverlay'\)", HEADER)
    assert "searchLoaded &&" in HEADER
    assert not re.search(r"^import SearchOverlay", HEADER, re.M)


def test_mobile_drawer_is_a_modal_dialog_with_a_labelled_trigger():
    assert 'role="dialog"' in HEADER and 'aria-modal="true"' in HEADER and 'id="mobile-menu"' in HEADER
    assert 'aria-controls="mobile-menu"' in HEADER and "aria-expanded={mobileOpen}" in HEADER
    assert "setAttribute('inert', '')" in HEADER  # the page behind a modal is inert


def test_mega_menus_are_disclosures_not_menus_and_not_focus_traps():
    assert "aria-haspopup" not in HEADER
    assert len(re.findall(r"aria-controls=\"mega-\w+\"", HEADER)) == 4
    assert len(re.findall(r'<div id="mega-\w+"', HEADER)) == 4
    # Focus is returned to the trigger on Escape, and leaving the header closes the panel.
    assert "triggerRef.current?.focus()" in HEADER and "onHeaderBlur" in HEADER


def test_focus_returns_to_the_opener_when_a_modal_closes():
    assert "hamburgerRef.current?.focus()" in HEADER and "searchBtnRef.current?.focus()" in HEADER


def test_alternate_image_frame_is_not_downloaded_until_needed():
    src = _t("app/components/RotatingImage.tsx")
    assert "armed && !reducedMotion" in src  # not for reduced-motion visitors, not before its first use
    assert "bLoaded.current" in src  # never crossfade to a frame that has not loaded


def test_next_image_serves_avif_before_webp():
    assert re.search(r"formats: \['image/avif', 'image/webp'\]", _t("next.config.js"))


def test_primary_mobile_controls_have_44px_targets():
    css = _t("app/globals.css")
    block = re.search(r"\.hamburger,\s*\.icon-button,\s*\.mobile-drill-close,\s*\.mobile-back \{([^}]*)\}", css)
    assert block and "min-width: 44px" in block.group(1) and "min-height: 44px" in block.group(1)
    assert re.search(r"prefers-reduced-motion: reduce\) \{\s*html \{\s*scroll-behavior: auto", css)


def test_contact_form_validates_on_submit_instead_of_disabling_the_button():
    form = _t("app/components/ContactForm.tsx")
    assert "disabled={!canSend}" not in form and "noValidate" in form
    assert 'role="alert"' in form and "aria-invalid" in form and "aria-describedby" in form
    assert 'autoComplete="email"' in form and 'autoComplete="name"' in form
