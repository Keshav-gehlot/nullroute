"""Validate CSS selectors with a real browser CSS parser.

One invalid selector inside a grouped ``a, b, c { display:none }`` rule makes
the browser drop the *whole* group, and on Safari it makes the entire content
blocker fail to compile. So every selector is checked individually with
Chromium's ``CSSStyleSheet.insertRule`` before it is shipped.
"""
from __future__ import annotations

_JS = """
(sels) => {
  const bad = [];
  const sheet = new CSSStyleSheet();
  for (const s of sels) {
    try { sheet.insertRule(s + '{display:none!important}', 0); sheet.deleteRule(0); }
    catch (e) { bad.push(s); }
  }
  return bad;
}
"""


def validate_selectors(selectors: list[str]) -> set[str]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:  # pragma: no cover - environment dependent
        raise RuntimeError("playwright not installed (pip install playwright && "
                           "playwright install chromium)") from e
    bad: set[str] = set()
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # pragma: no cover
            raise RuntimeError(f"could not launch Chromium: {e}") from e
        page = browser.new_page()
        for i in range(0, len(selectors), 5000):
            bad.update(page.evaluate(_JS, selectors[i:i + 5000]))
        browser.close()
    return bad
