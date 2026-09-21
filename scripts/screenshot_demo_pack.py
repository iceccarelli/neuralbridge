"""Sales demo pack screenshots — real captures of the running stack, not
mocked images. Run against a live Next dev server + both FastAPI APIs
(see docs/ai-local-setup.md and scripts/demo-walkthrough.sh for how to
bring that stack up; this script assumes it's already running and does
not start anything itself).

Usage:
    python scripts/screenshot_demo_pack.py [out_dir]

Requires the Next dev server on :3000 (NEXT_PUBLIC_NEURALBRIDGE_API_URL
pointed at a real /ai API, NEXT_PUBLIC_ASSURANCE_API_URL at a real
assurance API) and the operator key this script pastes (PAID_KEY) to
resolve to a Cell-tier principal on that assurance API's ASSURANCE_API_KEYS.
"""
from __future__ import annotations

import sys
import time

from playwright.sync_api import sync_playwright

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "reports/demo"
PAID_KEY = "demo-cell-key-12345"
CHROMIUM = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM)

        # 1. Pricing — the €390/€1,290 tiers with the live "first 10
        #    minutes" sentence computed from GET /v1/plans.
        page = browser.new_page(viewport={"width": 1280, "height": 1400})
        page.goto("http://127.0.0.1:3000/#pricing")
        time.sleep(1)
        page.screenshot(path=f"{OUT_DIR}/01-pricing.png", full_page=False)
        page.close()

        # 2. Free caller on /ai: propose a write, real 402 upgrade card.
        free_page = browser.new_page(viewport={"width": 1280, "height": 1000})
        free_page.goto("http://127.0.0.1:3000/ai")
        free_page.wait_for_selector("select[aria-label='Connection']")
        time.sleep(0.5)
        free_page.screenshot(path=f"{OUT_DIR}/02-ai-free-context.png", full_page=True)

        free_page.fill("input[aria-label='Message']", "UPDATE demo_customers SET plan='register' WHERE id=1")
        free_page.press("input[aria-label='Message']", "Enter")
        free_page.wait_for_selector("text=Register or Cell required", timeout=10000)
        time.sleep(0.3)
        free_page.screenshot(path=f"{OUT_DIR}/03-ai-free-write-402-upgrade.png", full_page=True)

        # 3. Paste the Cell-tier key — the same 402'd write retries with
        #    no reload and no retyping (this phase's fix).
        free_page.fill("input[aria-label='API key']", PAID_KEY)
        free_page.wait_for_selector(".ai-plan-pill.cell", timeout=10000)
        time.sleep(0.5)
        free_page.click("button:has-text('Retry now with your key')")
        free_page.wait_for_selector("text=approval required", timeout=10000)
        time.sleep(0.3)
        free_page.screenshot(path=f"{OUT_DIR}/04-ai-key-pasted-auto-retry-approval.png", full_page=True)

        free_page.click("button:has-text('Approve & execute')")
        free_page.wait_for_selector("text=Execution receipt", timeout=10000)
        time.sleep(0.3)
        free_page.screenshot(path=f"{OUT_DIR}/05-ai-execution-receipt.png", full_page=True)
        free_page.close()

        # 4. Checkout-success next-step panel (mocked checkout/complete
        #    response — no live Stripe anywhere in this repo; see the page's
        #    own comments and tests-e2e/phase3-first-euro.spec.ts).
        success_page = browser.new_page(viewport={"width": 1280, "height": 1200})
        success_page.route(
            "**/v1/checkout/complete*",
            lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=(
                    '{"api_key":"asr_demo_screenshot_only","tier":"cell",'
                    '"account_id":"acct_demo","keep_this":"This is shown once — copy it now.",'
                    '"use_it":{"header":"X-API-Key","start_here":"GET /v1/cases"}}'
                ),
            ),
        )
        success_page.goto("http://127.0.0.1:3000/checkout/success?session_id=cs_demo_screenshot")
        success_page.wait_for_selector("text=Your Cell key", timeout=10000)
        time.sleep(0.3)
        success_page.screenshot(path=f"{OUT_DIR}/06-checkout-success-next-steps.png", full_page=True)
        success_page.close()

        # 5. Connectors/MCP page — the one-key story for agent tooling.
        mcp_page = browser.new_page(viewport={"width": 1280, "height": 1400})
        mcp_page.goto("http://127.0.0.1:3000/connectors/mcp")
        time.sleep(1)
        mcp_page.screenshot(path=f"{OUT_DIR}/07-connectors-mcp.png", full_page=False)
        mcp_page.close()

        browser.close()
        print(f"done — screenshots in {OUT_DIR}")


if __name__ == "__main__":
    main()
