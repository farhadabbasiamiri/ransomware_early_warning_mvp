"""Capture dashboard screenshots for the README/report with Playwright.

1) python app.py           (in another terminal, Ollama running if you want LLM mode)
2) pip install playwright && playwright install chromium
3) python scripts/capture_screenshots.py [--mode offline|ollama]
Saves docs/screenshots/01_fleet.png ... 05_monitoring.png
"""
import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
URL = "http://127.0.0.1:7860"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="ollama")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1440, "height": 1000})
        pg.goto(URL)
        pg.wait_for_selector("text=hosts", timeout=60000)
        pg.wait_for_timeout(2500)
        pg.screenshot(path=str(OUT / "01_fleet.png"), full_page=True)
        pg.get_by_role("tab", name="2 · Investigate host (agent)").click()
        if a.mode == "offline":
            pg.get_by_label("Agent mode").click()
            pg.get_by_role("option", name="offline").click()
        pg.get_by_role("button", name="🔎 Run agent investigation").click()
        pg.wait_for_selector("text=decision:", timeout=240000)
        pg.wait_for_timeout(2000)
        pg.screenshot(path=str(OUT / "02_investigation.png"), full_page=True)
        pg.get_by_role("tab", name="3 · Human approval").click()
        pg.wait_for_timeout(800)
        boxes = pg.locator("input[type=checkbox]")
        for i in range(min(3, boxes.count())):
            boxes.nth(i).check()
        pg.get_by_label("Analyst name (required)").fill("Demo Analyst")
        pg.get_by_label("Justification (required for sensitive actions)").fill("Backup deletion by unsigned binary from Temp confirmed.")
        pg.screenshot(path=str(OUT / "03_approval_pending.png"), full_page=True)
        pg.get_by_role("button", name="✅ Approve selected (simulate tickets)").click()
        pg.wait_for_timeout(1500)
        pg.screenshot(path=str(OUT / "04_approval_logged.png"), full_page=True)
        pg.get_by_role("tab", name="4 · Evaluation").click()
        pg.wait_for_timeout(1500)
        pg.screenshot(path=str(OUT / "05_evaluation.png"), full_page=True)
        pg.get_by_role("tab", name="5 · System & monitoring").click()
        pg.get_by_role("button", name="Refresh").first.click()
        pg.wait_for_timeout(1000)
        pg.screenshot(path=str(OUT / "06_monitoring.png"), full_page=True)
        b.close()
    print("Saved to", OUT)


if __name__ == "__main__":
    main()
