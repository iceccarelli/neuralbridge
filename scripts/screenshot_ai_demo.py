"""One-off script to capture Phase 1 demo screenshots for reports/. Not a
test — run manually against a live dev server + API. See docs/ai-local-setup.md.
"""
from __future__ import annotations

import sys
import time

from playwright.sync_api import sync_playwright

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ai-screens"


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.goto("http://127.0.0.1:3000/ai")
        page.wait_for_selector("text=Discover, read, plan, approve")
        page.wait_for_selector("select[aria-label='Connection']")
        time.sleep(0.5)
        page.screenshot(path=f"{OUT_DIR}/01-discover.png", full_page=True)

        page.fill("input[aria-label='Message']", "list tables")
        page.press("input[aria-label='Message']", "Enter")
        page.wait_for_selector("text=Read OK", timeout=10000)
        time.sleep(0.3)
        page.screenshot(path=f"{OUT_DIR}/02-real-read.png", full_page=True)

        page.fill("input[aria-label='Message']", "UPDATE demo_customers SET plan='register' WHERE id=1")
        page.press("input[aria-label='Message']", "Enter")
        page.wait_for_selector("text=approval required", timeout=10000)
        time.sleep(0.3)
        page.screenshot(path=f"{OUT_DIR}/03-approval-card.png", full_page=True)

        page.click("button:has-text('Approve & execute')")
        page.wait_for_selector("text=Execution receipt", timeout=10000)
        time.sleep(0.3)
        page.screenshot(path=f"{OUT_DIR}/04-execution-receipt.png", full_page=True)

        # Mobile viewport pass.
        mobile_page = browser.new_page(viewport={"width": 390, "height": 844})
        mobile_page.goto("http://127.0.0.1:3000/ai")
        mobile_page.wait_for_selector("select[aria-label='Connection']")
        time.sleep(0.5)
        mobile_page.screenshot(path=f"{OUT_DIR}/05-mobile.png", full_page=True)

        browser.close()
        print("done")


if __name__ == "__main__":
    main()
