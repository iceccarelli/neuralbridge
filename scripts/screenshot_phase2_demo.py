"""One-off script capturing Phase 2 demo screenshots: free 402 upgrade path
and paid approve path. Not a test — run manually against a live dev server
+ API. See docs/ai-local-setup.md.
"""
from __future__ import annotations

import sys
import time

from playwright.sync_api import sync_playwright

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/phase2-screens"
PAID_KEY = "demo-cell-key-12345"


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")

        # --- Free path: attempt a write, see the 402 upgrade card ---
        free_page = browser.new_page(viewport={"width": 1280, "height": 1000})
        free_page.goto("http://127.0.0.1:3000/ai")
        free_page.wait_for_selector("select[aria-label='Connection']")
        time.sleep(0.5)
        free_page.screenshot(path=f"{OUT_DIR}/01-free-context.png", full_page=True)

        free_page.fill("input[aria-label='Message']", "UPDATE demo_customers SET plan='register' WHERE id=1")
        free_page.press("input[aria-label='Message']", "Enter")
        free_page.wait_for_selector("text=Register or Cell required", timeout=10000)
        time.sleep(0.3)
        free_page.screenshot(path=f"{OUT_DIR}/02-free-write-402-upgrade.png", full_page=True)

        # --- Paid path: paste API key, same write now plans + approves ---
        paid_page = browser.new_page(viewport={"width": 1280, "height": 1000})
        paid_page.goto("http://127.0.0.1:3000/ai")
        paid_page.wait_for_selector("input[aria-label='API key']")
        paid_page.fill("input[aria-label='API key']", PAID_KEY)
        time.sleep(0.8)  # session re-fetch on apiKey change
        paid_page.screenshot(path=f"{OUT_DIR}/03-paid-context.png", full_page=True)

        paid_page.fill("input[aria-label='Message']", "UPDATE demo_customers SET plan='cell' WHERE id=1")
        paid_page.press("input[aria-label='Message']", "Enter")
        paid_page.wait_for_selector("text=approval required", timeout=10000)
        time.sleep(0.3)
        paid_page.screenshot(path=f"{OUT_DIR}/04-paid-approval-card.png", full_page=True)

        paid_page.click("button:has-text('Approve & execute')")
        paid_page.wait_for_selector("text=Execution receipt", timeout=10000)
        time.sleep(0.3)
        paid_page.screenshot(path=f"{OUT_DIR}/05-paid-execution-receipt.png", full_page=True)

        # --- Pricing page: AI control plane row live from GET /v1/plans (or fallback) ---
        pricing_page = browser.new_page(viewport={"width": 1280, "height": 1400})
        pricing_page.goto("http://127.0.0.1:3000/#pricing")
        time.sleep(1)
        pricing_page.screenshot(path=f"{OUT_DIR}/06-pricing-ai-control-plane.png", full_page=False)

        browser.close()
        print("done")


if __name__ == "__main__":
    main()
