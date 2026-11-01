"""End-to-end test: load the real extension into Chromium and browse a page
that embeds real ad/tracker URLs.

Every hostname is mapped to a local HTTP server with --host-resolver-rules,
so the browser genuinely requests pagead2.googlesyndication.com etc. and
the server records which requests actually made it out of the browser.

    pip install pytest playwright && playwright install chromium
    pytest extension/tests -v
"""
from __future__ import annotations

import http.server
import ssl
import subprocess
import json
import threading
import time
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

EXT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
PAGE = "http://news.test/page.html"
AD_SCRIPT = "pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"
ANALYTICS = "cdn.bgalytics.com/track.js"
AD_PATH = "cdn.content.test/ads/get-ads-by-zones/"
APP = "cdn.content.test/app.js"
PIXEL = "ad.doubleclick.net/pixel.gif"


class Recorder(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []
    cookies: dict[str, str] = {}   # "host/path" -> Cookie header received
    dynamic: bytes = b""
    files: dict[str, bytes] = {}   # served verbatim for host lists.test (list updates)

    def do_GET(self):  # noqa: N802
        host = self.headers.get("Host", "").split(":")[0]
        Recorder.hits.append(f"{host}{self.path.split('?')[0]}")
        Recorder.cookies[f"{host}{self.path.split('?')[0]}"] = self.headers.get("Cookie", "")
        if host == "lists.test":
            body = Recorder.files.get(self.path.split("?")[0])
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Length", str(len(body or b"")))
            self.end_headers()
            self.wfile.write(body or b"")
            return
        if self.path.startswith("/dynamic.html"):
            body, ctype = Recorder.dynamic, "text/html"
        elif self.path.startswith("/page.html"):
            body, ctype = (FIXTURES / "page.html").read_bytes(), "text/html"
        elif self.path.endswith(".js"):
            body = f"window.__loaded = (window.__loaded||[]).concat('{host}');".encode()
            ctype = "application/javascript"
        else:
            body, ctype = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;", "image/gif"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self.path.startswith("/setcookie"):
            name = self.path.split("name=")[-1] if "name=" in self.path else "tid"
            secure = isinstance(self.connection, ssl.SSLSocket)
            # Over HTTPS, issue a real cross-site cookie (SameSite=None requires Secure).
            attrs = "; SameSite=None; Secure" if secure else ""
            self.send_header("Set-Cookie", f"{name}=1; Path=/; Max-Age=3600{attrs}")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    """HTTPS twin of `server` for *.tls hosts: real cross-site cookies need Secure."""
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"),
                    "-out", str(d / "c.pem"), "-days", "1", "-subj", "/CN=nullroute-test"],
                   check=True, capture_output=True)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(d / "c.pem", d / "k.pem")
    srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture(scope="module")
def browser(server, tls_server, tmp_path_factory):
    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            str(tmp_path_factory.mktemp("profile")),
            channel="chromium",
            headless=True,
            args=[
                f"--disable-extensions-except={EXT}",
                f"--load-extension={EXT}",
                f"--host-resolver-rules=MAP *.tls 127.0.0.1:{tls_server},MAP * 127.0.0.1:{server}",
                "--ignore-certificate-errors",   # self-signed cert for *.tls
                "--no-proxy-server",             # talk to the local servers directly
            ],
        )
        sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker")
        ext_id = sw.url.split("/")[2]
        # Wait until onInstalled has reconciled settings into Chrome.
        # Wait until onInstalled has finished reconciling: generic stylesheet,
        # MAIN-world scriptlets and fingerprint protection are all registered.
        for _ in range(200):
            if sw.evaluate("chrome.scripting.getRegisteredContentScripts().then(s => s.length)") >= 3:
                break
            time.sleep(0.1)
        yield ctx, sw, ext_id
        ctx.close()


def visit(ctx, url=PAGE):
    Recorder.hits.clear()
    page = ctx.new_page()
    page.goto(url, wait_until="load")
    page.wait_for_timeout(600)  # let user-origin CSS land
    return page


def wait_for_hit(path, timeout=10.0):
    """Wait until the local server has received a request for host+path."""
    end = time.time() + timeout
    while time.time() < end:
        if path in Recorder.hits:
            return
        time.sleep(0.1)
    raise AssertionError(f"{path} never requested; got {Recorder.hits}")


def settings(ctx, ext_id, msg):
    """Send a message to the service worker from an extension page, like the UI does."""
    page = ctx.new_page()
    page.goto(f"chrome-extension://{ext_id}/src/options.html")
    res = page.evaluate("m => chrome.runtime.sendMessage(m)", msg)
    page.close()
    assert res["ok"], res
    return res


def test_rulesets_enabled(browser):
    _, sw, _ = browser
    enabled = sw.evaluate("chrome.declarativeNetRequest.getEnabledRulesets()")
    assert sorted(enabled) == ["ads", "cname", "hosts", "params", "privacy", "ublock"]


def test_blocks_ads_trackers_and_hosts(browser):
    ctx, _, _ = browser
    page = visit(ctx)
    assert AD_SCRIPT not in Recorder.hits, "EasyList should block adsbygoogle.js"
    assert ANALYTICS not in Recorder.hits, "EasyPrivacy should block analytics.js"
    assert PIXEL not in Recorder.hits, "hosts list should block doubleclick"
    assert AD_PATH not in Recorder.hits, "EasyList URL pattern should block on any domain"
    assert APP in Recorder.hits, "first-party script must load"
    assert page.evaluate("window.__loaded") == ["cdn.content.test"]
    page.close()


def test_generic_cosmetic_hiding(browser):
    ctx, _, _ = browser
    page = visit(ctx)
    assert page.evaluate("getComputedStyle(document.getElementById('slot')).display") == "none"
    assert page.evaluate("getComputedStyle(document.getElementById('story')).display") == "block"
    page.close()


def _pick_specific_rule():
    """A real site-specific EasyList rule with a plain .class or #id selector."""
    import re
    cos = json.loads((EXT / "rulesets" / "cosmetic.json").read_text())
    excluded = set(json.loads((EXT / "rulesets" / "generic-excluded.json").read_text()))
    for domain, sels in cos["specific"].items():
        if domain.count(".") != 1 or domain in excluded or domain in cos["exceptions"]:
            continue
        for s in sels:
            if re.fullmatch(r"[.#][A-Za-z][\w-]{3,}", s) and s not in cos["generic"]:
                return domain, s
    raise AssertionError("no simple site-specific rule found")


def test_site_specific_cosmetic_hiding(browser):
    ctx, _, _ = browser
    domain, selector = _pick_specific_rule()
    attr = f'class="{selector[1:]}"' if selector[0] == "." else f'id="{selector[1:]}"'
    Recorder.dynamic = (f'<!doctype html><div {attr}>ad</div>'
                        f'<div id="control" class="nr-control">content</div>').encode()
    display = f"getComputedStyle(document.querySelector({json.dumps(selector)})).display"
    page = visit(ctx, f"http://{domain}/dynamic.html")
    assert page.evaluate(display) == "none", (domain, selector)
    assert page.evaluate("getComputedStyle(document.getElementById('control')).display") == "block"
    page.close()
    # Subdomains inherit the site's rules...
    page = visit(ctx, f"http://www.{domain}/dynamic.html")
    assert page.evaluate(display) == "none"
    page.close()
    # ...but the same markup on an unrelated site is untouched.
    page = visit(ctx, "http://unrelated-site.test/dynamic.html")
    assert page.evaluate(display) == "block"
    page.close()


def test_matched_rules_counted_per_list(browser):
    ctx, sw, ext_id = browser
    page = visit(ctx)
    tab_id = sw.evaluate("chrome.tabs.query({url: 'http://news.test/*'}).then(t => t[t.length-1].id)")
    # Chrome records matched rules asynchronously, so poll briefly.
    for _ in range(20):
        status = settings(ctx, ext_id, {"type": "getStatus", "tabId": tab_id, "url": PAGE})
        if sum((status["counts"] or {}).values()) >= 4:
            break
        page.wait_for_timeout(250)
    # A URL listed by several rulesets is attributed to just one of them, so
    # check the lists that uniquely cover a fixture URL plus the total.
    assert status["counts"].get("ads", 0) >= 1      # AD_PATH
    assert status["counts"].get("privacy", 0) >= 1  # ANALYTICS
    assert sum(status["counts"].values()) >= 4
    assert status["allowlisted"] is False
    page.close()


def test_site_allowlist(browser):
    ctx, sw, ext_id = browser
    settings(ctx, ext_id, {"type": "setSiteAllowed", "site": "news.test", "allowed": True})
    for _ in range(50):  # the allow rule is applied asynchronously after the reply
        if sw.evaluate("chrome.declarativeNetRequest.getDynamicRules().then(r => r.some(x => x.id === 1))"):
            break
        time.sleep(0.1)
    try:
        page = visit(ctx)
        assert AD_SCRIPT in Recorder.hits and PIXEL in Recorder.hits
        assert page.evaluate("getComputedStyle(document.getElementById('slot')).display") == "block"
        page.close()
    finally:
        settings(ctx, ext_id, {"type": "setSiteAllowed", "site": "news.test", "allowed": False})
    page = visit(ctx)
    assert AD_SCRIPT not in Recorder.hits
    page.close()


def test_user_filters(browser):
    ctx, _, ext_id = browser
    res = settings(ctx, ext_id, {"type": "saveSettings", "allowlist": [],
                                 "userFilters": "! mine\ncdn.content.test\nnews.test##article.content\nbad line ##{"})
    assert res["counts"] == {"domains": 1, "patterns": 0, "selectors": 1}
    assert len(res["errors"]) == 1
    try:
        page = visit(ctx)
        assert APP not in Recorder.hits, "custom domain rule should block"
        assert page.evaluate("getComputedStyle(document.getElementById('story')).display") == "none"
        page.close()
    finally:
        settings(ctx, ext_id, {"type": "saveSettings", "allowlist": [], "userFilters": ""})


def test_pause_everywhere(browser):
    ctx, sw, ext_id = browser
    settings(ctx, ext_id, {"type": "setPaused", "paused": True})
    try:
        assert sw.evaluate("chrome.declarativeNetRequest.getEnabledRulesets()") == []
        page = visit(ctx)
        assert AD_SCRIPT in Recorder.hits and ANALYTICS in Recorder.hits
        page.close()
    finally:
        settings(ctx, ext_id, {"type": "setPaused", "paused": False})
    page = visit(ctx)
    assert AD_SCRIPT not in Recorder.hits
    page.close()


def test_toggle_single_list(browser):
    ctx, sw, ext_id = browser
    settings(ctx, ext_id, {"type": "setRulesetEnabled", "id": "privacy", "enabled": False})
    try:
        page = visit(ctx)
        assert ANALYTICS in Recorder.hits, "privacy list off: tracker must load"
        assert AD_PATH not in Recorder.hits, "other lists stay on"
        page.close()
    finally:
        settings(ctx, ext_id, {"type": "setRulesetEnabled", "id": "privacy", "enabled": True})
    assert "privacy" in sw.evaluate("chrome.declarativeNetRequest.getEnabledRulesets()")


def test_element_picker(browser):
    ctx, sw, ext_id = browser
    page = visit(ctx)
    tab_id = sw.evaluate("chrome.tabs.query({url: 'http://news.test/*'}).then(t => t[t.length-1].id)")
    settings(ctx, ext_id, {"type": "startPicker", "tabId": tab_id})
    page.wait_for_selector("nullroute-picker", state="attached")
    box = page.locator("#story h1").bounding_box()
    page.mouse.move(box["x"] + 5, box["y"] + 5)
    page.mouse.click(box["x"] + 5, box["y"] + 5)
    out = Path(__file__).parent / "screenshots"
    out.mkdir(exist_ok=True)
    page.screenshot(path=str(out / "picker.png"))
    page.keyboard.press("Enter")
    page.wait_for_selector("nullroute-picker", state="detached")
    assert page.evaluate("getComputedStyle(document.querySelector('#story h1')).display") == "none"
    assert page.evaluate("getComputedStyle(document.querySelector('#story p')).display") == "block"
    saved = sw.evaluate("chrome.storage.local.get('userFilters').then(s => s.userFilters)")
    assert saved.startswith("news.test##") and "h1" in saved
    # Persisted: a fresh load of the site keeps it hidden.
    page.close()
    page = visit(ctx)
    assert page.evaluate("getComputedStyle(document.querySelector('#story h1')).display") == "none"
    page.close()
    settings(ctx, ext_id, {"type": "saveSettings", "allowlist": [], "userFilters": ""})


# ---------------------------------------------------------------- research-driven features
def _real_scriptlet(name, value=None):
    import re
    data = json.loads((EXT / "rulesets" / "scriptlets-main.js").read_text().rsplit("__nullrouteScriptlets(", 1)[1].rstrip(");\n"))
    for domain, entries in data["byDomain"].items():
        if domain.count(".") != 1 or domain in data["disabled"]:
            continue
        for e in entries:
            if e[0] == name and re.fullmatch(r"[A-Za-z_$][\w$]*", e[1]) and (value is None or e[2:3] == [value]):
                return domain, e
    raise AssertionError(f"no simple {name} rule")


def test_scriptlet_set_constant_runs_before_page_scripts(browser):
    ctx, _, _ = browser
    domain, (_, prop, value) = _real_scriptlet("set-constant", "false")
    # The page sets the flag to true and reads it back; the scriptlet must win.
    Recorder.dynamic = (f"<!doctype html><script>window.{prop} = true;"
                        f"document.title = 'value:' + String(window.{prop});</script>").encode()
    page = visit(ctx, f"http://{domain}/dynamic.html")
    assert page.title() == "value:false", (domain, prop)
    page.close()
    page = visit(ctx, "http://unrelated-site.test/dynamic.html")
    assert page.title() == "value:true", "scriptlets must only run on their own sites"
    page.close()


def test_scriptlet_abort_on_property_read(browser):
    ctx, _, ext_id = browser
    domain, (_, prop) = _real_scriptlet("abort-on-property-read")
    Recorder.dynamic = (f"<!doctype html><script>try {{ window.{prop}; document.title = 'read-ok'; }}"
                        f" catch (e) {{ document.title = 'aborted:' + e.name; }}</script>").encode()
    page = visit(ctx, f"http://{domain}/dynamic.html")
    assert page.title() == "aborted:ReferenceError", (domain, prop)
    page.close()
    # Allowlisting the site turns its scriptlets off too.
    settings(ctx, ext_id, {"type": "setSiteAllowed", "site": domain, "allowed": True})
    try:
        page = visit(ctx, f"http://{domain}/dynamic.html")
        assert page.title() == "read-ok"
        page.close()
    finally:
        settings(ctx, ext_id, {"type": "setSiteAllowed", "site": domain, "allowed": False})


def test_click_ids_stripped_campaign_tags_kept(browser):
    ctx, _, _ = browser
    page = visit(ctx, "http://news.test/page.html?id=7&gclid=TRACK123&utm_source=mail&fbclid=X9")
    assert page.url == "http://news.test/page.html?id=7&utm_source=mail"
    page.close()


def test_cname_cloaked_tracker_blocked(browser):
    ctx, _, _ = browser
    rules = json.loads((EXT / "rulesets" / "rules_cname.json").read_text())
    cloaked = next(d for r in rules for d in r["condition"].get("requestDomains", []) if d.count(".") >= 2)
    Recorder.dynamic = f'<!doctype html><img src="http://{cloaked}/pixel.gif">'.encode()
    page = visit(ctx, "http://unrelated-site.test/dynamic.html")
    assert f"{cloaked}/pixel.gif" not in Recorder.hits, cloaked
    page.close()


def test_all_regex_rules_supported_by_chrome(browser):
    _, sw, _ = browser
    for f in (EXT / "rulesets").glob("rules_*.json"):
        for r in json.loads(f.read_text()):
            rx = r["condition"].get("regexFilter")
            if rx:
                res = sw.evaluate("rx => chrome.declarativeNetRequest.isRegexSupported({regex: rx})", rx)
                assert res["isSupported"], (f.name, rx, res)


# ---------------------------------------------------------------- per-site controls (Brave Shields model)
def control(ctx, ext_id, site, key, value):
    settings(ctx, ext_id, {"type": "setSiteControl", "site": site, "key": key, "value": value})


def test_aggressive_mode_blocks_third_party_scripts_per_site(browser):
    ctx, _, ext_id = browser
    Recorder.dynamic = (b'<!doctype html><script src="http://widgets.othervendor.test/w.js"></script>'
                        b'<script src="/own.js"></script>')
    visit(ctx, "http://agg.test/dynamic.html").close()
    assert "widgets.othervendor.test/w.js" in Recorder.hits, "standard mode leaves unlisted 3p scripts alone"
    control(ctx, ext_id, "agg.test", "trackers", "aggressive")
    try:
        visit(ctx, "http://agg.test/dynamic.html").close()
        assert "widgets.othervendor.test/w.js" not in Recorder.hits
        assert "agg.test/own.js" in Recorder.hits, "first-party scripts still load"
        visit(ctx, "http://calm.test/dynamic.html").close()
        assert "widgets.othervendor.test/w.js" in Recorder.hits, "other sites unaffected"
    finally:
        control(ctx, ext_id, "agg.test", "trackers", None)


def test_block_scripts_per_site_and_shields_down_wins(browser):
    ctx, _, ext_id = browser
    Recorder.dynamic = b"<!doctype html><title>static</title><script>document.title = 'ran'</script>"
    control(ctx, ext_id, "nojs.test", "blockScripts", True)
    try:
        page = visit(ctx, "http://nojs.test/dynamic.html")
        assert page.title() == "static", "inline script must not run"
        page.close()
        page = visit(ctx, "http://yesjs.test/dynamic.html")
        assert page.title() == "ran"
        page.close()
        # "Site broken? Turn NullRoute off for this site" must override everything.
        settings(ctx, ext_id, {"type": "setSiteAllowed", "site": "nojs.test", "allowed": True})
        page = visit(ctx, "http://nojs.test/dynamic.html")
        assert page.title() == "ran"
        page.close()
    finally:
        settings(ctx, ext_id, {"type": "setSiteAllowed", "site": "nojs.test", "allowed": False})
        control(ctx, ext_id, "nojs.test", "blockScripts", None)


def test_cross_site_cookies_stripped_per_site(browser):
    ctx, _, ext_id = browser
    T = "https://tracker.tls"
    visit(ctx, f"{T}/setcookie?name=tid").close()          # tracker's own cookie (SameSite=None; Secure)
    Recorder.dynamic = (f'<!doctype html><img src="{T}/pixel.gif">'
                        f'<img src="{T}/setcookie?name=planted">').encode()
    visit(ctx, "https://cookies-allowed.tls/dynamic.html").close()
    assert "tid=1" in Recorder.cookies["tracker.tls/pixel.gif"], "baseline: cookie flows cross-site"
    ctx.clear_cookies(domain="tracker.tls")
    visit(ctx, f"{T}/setcookie?name=tid").close()
    control(ctx, ext_id, "cookies-blocked.tls", "cookies", "block3p")
    try:
        visit(ctx, "https://cookies-blocked.tls/dynamic.html").close()
        assert Recorder.cookies["tracker.tls/pixel.gif"] == "", "Cookie header stripped"
        names = {c["name"] for c in ctx.cookies(T)}
        assert "tid" in names and "planted" not in names, "Set-Cookie from the 3p response stripped"
        visit(ctx, f"{T}/pixel.gif").close()
        assert "tid=1" in Recorder.cookies["tracker.tls/pixel.gif"], "first-party visits keep their cookies"
    finally:
        control(ctx, ext_id, "cookies-blocked.tls", "cookies", None)


FP_PAGE = b"""<!doctype html><script>
const c = document.createElement('canvas'); c.width = 220; c.height = 60;
const x = c.getContext('2d');
x.fillStyle = '#f60'; x.fillRect(10, 10, 100, 40);
x.fillStyle = '#069'; x.font = '18px Arial'; x.fillText('NullRoute fingerprint', 4, 30);
const a = c.toDataURL(), b = c.toDataURL();
const d1 = x.getImageData(0, 0, 220, 60).data, d2 = x.getImageData(0, 0, 220, 60).data;
window.fp = { a, b, sameRead: a === b, sameData: d1.every((v, i) => v === d2[i]),
              cores: navigator.hardwareConcurrency,
              native: Function.prototype.toString.call(HTMLCanvasElement.prototype.toDataURL) };
</script>"""


def test_fingerprinting_noise_consistent_within_page_but_not_real(browser):
    ctx, _, ext_id = browser
    Recorder.dynamic = FP_PAGE
    control(ctx, ext_id, "real.test", "fingerprinting", False)
    try:
        page = visit(ctx, "http://real.test/dynamic.html")
        real = page.evaluate("window.fp")
        real_cores = page.evaluate("navigator.hardwareConcurrency")
        page.close()
        page = visit(ctx, "http://protected.test/dynamic.html")
        fp1 = page.evaluate("window.fp")
        page.close()
        page = visit(ctx, "http://protected.test/dynamic.html")
        fp2 = page.evaluate("window.fp")
        page.close()
    finally:
        control(ctx, ext_id, "real.test", "fingerprinting", None)
    assert fp1["sameRead"] and fp1["sameData"], "double-render check must not detect noise"
    assert fp1["a"] != real["a"], "readback differs from the real fingerprint"
    assert fp1["a"] != fp2["a"], "fingerprint can't be linked across page loads"
    assert "[native code]" in fp1["native"], "wrapped function still looks native"
    assert 2 <= fp1["cores"] <= max(real_cores, 2)


def test_forget_site_data_now_and_on_close(browser):
    ctx, _, ext_id = browser
    Recorder.dynamic = (b"<!doctype html><script>if (location.search === '?set') {"
                        b"localStorage.setItem('k', 'v'); document.cookie = 'sid=42; Max-Age=3600; Path=/'; }"
                        b"window.state = [localStorage.getItem('k'), document.cookie];</script>")
    page = visit(ctx, "http://shred.test/dynamic.html?set")
    assert page.evaluate("window.state") == ["v", "sid=42"]
    settings(ctx, ext_id, {"type": "shredSite", "site": "shred.test"})
    page.goto("http://shred.test/dynamic.html")      # no ?set: just read what survived
    assert page.evaluate("window.state") == [None, ""], "manual forget clears storage and cookies"
    page.close()

    control(ctx, ext_id, "autoshred.test", "autoShred", True)
    try:
        page = visit(ctx, "http://autoshred.test/dynamic.html?set")
        assert page.evaluate("window.state") == ["v", "sid=42"]
        page.close()                                  # last tab for the site closes
        time.sleep(1.5)
        page = visit(ctx, "http://autoshred.test/dynamic.html")
        assert page.evaluate("window.state") == [None, ""], "auto-forget on close"
        page.close()
    finally:
        control(ctx, ext_id, "autoshred.test", "autoShred", None)


def test_ui_pages_render(browser, tmp_path):
    ctx, sw, ext_id = browser
    page = visit(ctx)
    tab_id = sw.evaluate("chrome.tabs.query({url: 'http://news.test/*'}).then(t => t[t.length-1].id)")
    errors = []
    popup = ctx.new_page()
    popup.on("pageerror", lambda e: errors.append(str(e)))
    popup.set_viewport_size({"width": 340, "height": 480})
    popup.goto(f"chrome-extension://{ext_id}/src/popup.html?tab={tab_id}")
    popup.wait_for_function("document.querySelector('.popup').dataset.state === 'on'")
    assert popup.inner_text("#host") == "news.test"
    assert int(popup.inner_text("#count")) >= 3
    out = Path(__file__).parent / "screenshots"
    out.mkdir(exist_ok=True)
    popup.screenshot(path=str(out / "popup.png"))
    opts = ctx.new_page()
    opts.on("pageerror", lambda e: errors.append(str(e)))
    opts.goto(f"chrome-extension://{ext_id}/src/options.html")
    opts.wait_for_selector(".list")
    assert opts.locator("#lists .list").count() == 6
    assert opts.locator("#defaults .list").count() == 5
    opts.screenshot(path=str(out / "options.png"), full_page=True)
    assert not errors, errors
    for p in (page, popup, opts):
        p.close()


def test_dangerous_site_interstitial_with_private_lookup(browser, tmp_path):
    """Reputation end to end: verified list update, local prefix check, shard
    confirmation, warning page, proceed, and a clean prefix collision."""
    import hashlib
    import re
    import sys
    sys.path.insert(0, str(EXT.parent / "compiler"))
    from nullroute_compiler import reputation as rep

    ctx, _, ext_id = browser
    rep.build(["phish-login.test", "evil-bank.test"], tmp_path)
    prefixes = rep.rice_decode((tmp_path / "rep/prefixes.rice").read_bytes())
    # A clean host whose 32-bit prefix collides locally: the shard must clear it.
    prefixes = sorted(set(prefixes) | {rep.prefix32(rep.digest("collides.test"))})
    blob = rep.rice_encode(prefixes)
    files = {"/lists/rep/prefixes.rice": blob,
             "/lists/report.json": json.dumps({"files": {"rep/prefixes.rice": hashlib.sha256(blob).hexdigest()}}).encode()}
    for f in (tmp_path / "rep/shards").iterdir():
        files[f"/lists/rep/shards/{f.name}"] = f.read_bytes()
    Recorder.files = files

    settings(ctx, ext_id, {"type": "setReputationSettings", "listsBaseUrl": "http://lists.test/lists/"})
    Recorder.files = {**files, "/lists/report.json": b'{"files": {"rep/prefixes.rice": "' + b"0" * 64 + b'"}}'}
    bad = ctx.new_page()
    bad.goto(f"chrome-extension://{ext_id}/src/options.html")
    res = bad.evaluate("m => chrome.runtime.sendMessage(m)", {"type": "repUpdate"})
    assert not res["ok"] and "Checksum" in res["error"], "a tampered download must be refused"
    bad.close()
    Recorder.files = files
    assert settings(ctx, ext_id, {"type": "repUpdate"})["changed"]

    page = ctx.new_page()
    page.goto("http://news.test/page.html")
    Recorder.hits.clear()
    try:
        page.goto("http://www.phish-login.test/signin")
    except Exception:  # the navigation is replaced by the interstitial
        pass
    for _ in range(100):  # wait_for_url would raise on the replaced (aborted) navigation
        if re.match(r"chrome-extension://.*/src/warning\.html", page.url):
            break
        time.sleep(0.1)
    page.wait_for_selector('#card[data-state="danger"]', timeout=10000)
    assert "phish-login.test" in page.inner_text("#host")
    shots = Path(__file__).parent / "screenshots"
    shots.mkdir(exist_ok=True)
    page.set_viewport_size({"width": 760, "height": 520})
    page.screenshot(path=str(shots / "warning.png"))
    lookups = [h for h in Recorder.hits if h.startswith("lists.test")]
    assert lookups and all(re.fullmatch(r"lists\.test/lists/rep/shards/[0-9a-f]{3}\.bin", h) for h in lookups), \
        f"only an anonymous 12-bit bucket may be requested, got {lookups}"
    Recorder.hits.clear()
    page.click("#proceed")
    # The server receiving the request is the ground truth: Playwright can lose
    # track of a tab that moves from an extension page to a web page.
    wait_for_hit("www.phish-login.test/signin")
    page.close()

    page = ctx.new_page()
    Recorder.hits.clear()
    try:
        page.goto("http://collides.test/page.html")
    except Exception:  # briefly interrupted by the "checking" interstitial
        pass
    wait_for_hit("collides.test/page.html")
    shard_hits = [h for h in Recorder.hits if h.startswith("lists.test/lists/rep/shards/")]
    assert len(shard_hits) <= 1, Recorder.hits
    assert "collides.test/page.html" in Recorder.hits

    page.close()
    page = ctx.new_page()
    Recorder.hits.clear()
    page.goto("http://plain-site.test/page.html")
    assert not [h for h in Recorder.hits if h.startswith("lists.test")], "a clean site must not contact the server"
    page.close()



def test_cross_site_tracker_detected_then_blocked(browser):
    """An unlisted third party receiving one ID from two sites is flagged; blocking is opt-in."""
    ctx, _, ext_id = browser
    pixel = "http://edge.unlisted-tracker.test/v1/img?uid=a8f3c2d1e9b74f60&cb=1730419200000"
    Recorder.dynamic = f'<html><body><img src="{pixel}"></body></html>'.encode()
    settings(ctx, ext_id, {"type": "setCrossSiteSettings", "enabled": True, "block": False})
    for site in ("first-site.test", "second-site.test"):
        page = visit(ctx, f"http://{site}/dynamic.html")
        page.close()
    assert "edge.unlisted-tracker.test/v1/img" in Recorder.hits, "detection alone must never block"
    status = settings(ctx, ext_id, {"type": "getCrossSiteStatus"})
    for _ in range(30):
        if "unlisted-tracker.test" in status["flagged"]:
            break
        time.sleep(0.2)
        status = settings(ctx, ext_id, {"type": "getCrossSiteStatus"})
    assert sorted(status["flagged"]["unlisted-tracker.test"]["sites"]) == ["first-site.test", "second-site.test"]
    opts = ctx.new_page()
    opts.goto(f"chrome-extension://{ext_id}/src/options.html")
    opts.wait_for_selector("#xsiteList li strong")
    assert "unlisted-tracker.test" in opts.inner_text("#xsiteList")
    shots = Path(__file__).parent / "screenshots"
    shots.mkdir(exist_ok=True)
    opts.set_viewport_size({"width": 900, "height": 900})
    opts.add_style_tag(content=".savebar{display:none!important}")
    opts.locator('section[aria-labelledby="xsiteTitle"]').screenshot(path=str(shots / "options-crosssite.png"))
    opts.close()

    # A benign third party whose IDs differ per site is never flagged.
    Recorder.dynamic = b'<html><body><img src="http://widgets.benign.test/v1/img?session=FIRSTk2m9x7q3w8"></body></html>'
    visit(ctx, "http://first-site.test/dynamic.html").close()
    Recorder.dynamic = b'<html><body><img src="http://widgets.benign.test/v1/img?session=SECONDp4z6r1t5y0"></body></html>'
    visit(ctx, "http://second-site.test/dynamic.html").close()
    assert "benign.test" not in settings(ctx, ext_id, {"type": "getCrossSiteStatus"})["flagged"]

    settings(ctx, ext_id, {"type": "setCrossSiteSettings", "block": True})
    Recorder.dynamic = f'<html><body><img src="{pixel}"></body></html>'.encode()
    page = visit(ctx, "http://third-site.test/dynamic.html")
    assert "edge.unlisted-tracker.test/v1/img" not in Recorder.hits
    page.close()
    settings(ctx, ext_id, {"type": "setCrossSiteSettings", "block": False, "forget": "unlisted-tracker.test"})
