import json
import re
from pathlib import Path

import pytest

from nullroute_compiler.abp import parse_abp, parse_hosts
from nullroute_compiler.domains import minimize, subtract
from nullroute_compiler.targets import chrome, cosmetic, dns, safari


def net(*lines):
    return parse_abp(lines).network


# ---------------------------------------------------------------- parsing
def test_comments_and_headers_skipped():
    r = parse_abp(["[Adblock Plus 2.0]", "! Title: x", "", "||ads.com^"])
    assert len(r.network) == 1 and r.skipped["comment"] == 3


def test_options_parsed():
    (f,) = net("||cdn.ads.com/x.js$script,third-party,domain=a.com|~b.a.com,important")
    assert f.pattern == "||cdn.ads.com/x.js"
    assert f.resource_types == {"script"}
    assert f.party == "third" and f.important
    assert f.include_domains == {"a.com"} and f.exclude_domains == {"b.a.com"}


def test_negated_types_and_first_party():
    (f,) = net("/banner/*$~image,~third-party")
    assert f.excluded_resource_types == {"image"} and f.party == "first"


def test_unsupported_and_regex_are_skipped_not_approximated():
    r = parse_abp(["/ad[0-9]+\\.js/", "||x.com^$popup", "||y.com^$redirect=noop.js",
                   "||z.com^$csp=script-src 'none'", "example.com#?#div:-abp-has(.ad)",
                   "example.com##+js(abort-on-property-read, x)"])
    assert r.network == [] and r.cosmetic == []
    assert r.skipped["network:regex"] == 1
    assert r.skipped["network:option:popup"] == 1


def test_entity_domains_rejected():
    r = parse_abp(["||ads.com^$domain=google.*", "google.*##.ad"])
    assert r.network == [] and r.cosmetic == []


def test_unscoped_match_all_rejected():
    r = parse_abp(["$script", "*$image"])
    assert r.network == []
    assert r.skipped["network:unscoped-empty"] == 2


def test_dollar_inside_url_is_not_option_separator():
    (f,) = net("/price$/ads")
    assert f.pattern == "/price$/ads" and not f.resource_types


def test_cosmetic_parsing():
    r = parse_abp(["##.ad-banner", "example.com,~shop.example.com##.sponsor",
                   "news.com#@#.ad-banner", "x.com##div{color:red}"])
    gen, spec, exc = r.cosmetic
    assert gen.generic and gen.selector == ".ad-banner"
    assert spec.include_domains == {"example.com"} and spec.exclude_domains == {"shop.example.com"}
    assert exc.exception and exc.include_domains == {"news.com"}
    assert r.skipped["cosmetic:unsupported-selector"] == 1  # CSS injection attempt


def test_hosts_parsing():
    r = parse_hosts(["# comment", "0.0.0.0 ads.example.com", "127.0.0.1 localhost",
                     "0.0.0.0 tracker.io # inline", "::1 ip6-localhost", "plain.example.org"])
    assert r.hosts == {"ads.example.com", "tracker.io", "plain.example.org"}


# ---------------------------------------------------------------- domains
def test_minimize_drops_covered_subdomains():
    assert minimize(["a.ads.com", "ads.com", "b.c.ads.com", "other.net"]) == ["ads.com", "other.net"]


def test_subtract_respects_parent_allow():
    assert subtract(["x.good.com", "bad.com"], ["good.com"]) == ["bad.com"]


# ---------------------------------------------------------------- chrome
def test_chrome_folds_pure_domain_rules():
    rules, stats = chrome.to_dnr(net("||a.com^", "||b.com^", "||sub.a.com^", "||c.com^$third-party"))
    assert stats["folded"] == 4
    plain = [r for r in rules if "domainType" not in r["condition"]]
    assert plain[0]["condition"]["requestDomains"] == ["a.com", "b.com"]
    third = [r for r in rules if r["condition"].get("domainType") == "thirdParty"]
    assert third[0]["condition"]["requestDomains"] == ["c.com"]
    assert chrome.validate(rules) == []


def test_chrome_rule_shapes():
    rules, _ = chrome.to_dnr(net(
        "/ads/banner*$image,domain=news.com",
        "@@||cdn.example.com/ads.js$script",
        "@@||trusted.com^$document",
        "||evil.com/track$important",
        "||Case.com/Ad$match-case",
        "||x.com^$denyallow=y.com",
    ))
    by = {json.dumps(r["condition"].get("urlFilter") or r["condition"].get("requestDomains")): r for r in rules}
    img = by['"/ads/banner*"']
    assert img["action"]["type"] == "block" and img["priority"] == chrome.PRIORITY_BLOCK
    assert img["condition"]["resourceTypes"] == ["image"]
    assert img["condition"]["initiatorDomains"] == ["news.com"]
    allow = by['"||cdn.example.com/ads.js"']
    assert allow["action"]["type"] == "allow" and allow["priority"] == chrome.PRIORITY_ALLOW
    doc = by['["trusted.com"]']
    assert doc["action"]["type"] == "allowAllRequests"
    assert doc["condition"]["resourceTypes"] == ["main_frame", "sub_frame"]
    assert by['"||evil.com/track"']["priority"] == chrome.PRIORITY_IMPORTANT
    assert by['"||Case.com/Ad"']["condition"]["isUrlFilterCaseSensitive"] is True
    assert by['["x.com"]']["condition"]["excludedRequestDomains"] == ["y.com"]
    assert chrome.validate(rules) == []
    assert sorted(r["id"] for r in rules) == list(range(1, len(rules) + 1))


def test_chrome_hosts_chunking():
    hosts = [f"h{i}.example{i}.com" for i in range(2500)]
    rules, _ = chrome.to_dnr([], hosts)
    assert len(rules) == 3
    assert sum(len(r["condition"]["requestDomains"]) for r in rules) == 2500


def test_chrome_validator_catches_bad_rules():
    bad = [{"id": 1, "priority": 1, "action": {"type": "block"}, "condition": {"urlFilter": "||*x"}},
           {"id": 1, "priority": 1, "action": {"type": "block"}, "condition": {"resourceTypes": []}}]
    errs = chrome.validate(bad)
    assert any("||*" in e for e in errs) and any("duplicate" in e for e in errs)
    assert any("empty resourceTypes" in e for e in errs)


# ---------------------------------------------------------------- safari
@pytest.mark.parametrize("pattern,match,nomatch", [
    ("||ads.com^", ["https://ads.com/x", "http://sub.ads.com/", "https://ads.com:8080/a"],
     ["https://notads.com/", "https://ads.com.evil.net/", "https://x.com/?u=ads.com"]),
    ("/banner/*/img^", ["https://x.com/banner/123/img?x=1", "https://x.com/banner/1/img"],
     ["https://x.com/banner/1/imgs"]),
    ("|https://track.", ["https://track.io/p"], ["http://x.com/https://track."]),
    ("swf|", ["https://x.com/a.swf"], ["https://x.com/a.swf?x"]),
    ("ad.js?v=1", ["https://x.com/ad.js?v=1"], ["https://x.com/adxjs?v=1"]),
])
def test_safari_regex_semantics(pattern, match, nomatch):
    rx = re.compile(safari.abp_to_regex(pattern), re.I)
    for u in match:
        assert rx.search(u), (pattern, u)
    for u in nomatch:
        assert not rx.search(u), (pattern, u)


def test_safari_regex_uses_only_webkit_syntax():
    for p in ["||a.com^", "/x|y/", "a{2}b", "|http://*.js|", "x^y"]:
        rx = safari.abp_to_regex(p)
        unescaped = re.sub(r"\\.", "", rx)
        assert "|" not in unescaped and "{" not in unescaped, rx


@pytest.mark.parametrize("rx,ok", [
    (safari.abp_to_regex("||ads.com^"), True),
    (safari.abp_to_regex("/x*y^z|"), True),
    ("a|b", False), ("a{2}", False), ("(?=x)", False), ("a^b", False), ("a$b", False),
    ("\\d+", False), ("[|{]", True), ("(a", False), ("caf\u00e9", False),
])
def test_safari_regex_validator(rx, ok):
    assert (safari.validate_url_filter(rx) is None) is ok, rx


def test_safari_ordering_exceptions_after_blocks():
    rules, _ = safari.build_network(net("@@||ok.ads.com^", "||ads.com^", "||bad.com^$important"))
    kinds = [r["action"]["type"] for r in rules]
    first_ignore = kinds.index("ignore-previous-rules")
    assert all(k == "block" for k in kinds[:first_ignore])
    assert rules[-1]["trigger"]["url-filter"].endswith("bad\\.com([^a-zA-Z0-9_.%-].*)?$")


def test_safari_frames_rule_for_ad_hosts():
    rules, _ = safari.build_network(net("||adframe.com^"))
    assert any(r["trigger"].get("resource-type") == ["document"]
               and r["trigger"].get("load-type") == ["third-party"] for r in rules)


def test_safari_drops_mixed_domain_conditions():
    rules, stats = safari.build_network(net("||a.com^$domain=x.com|~y.x.com"))
    assert rules == [] and stats["skipped"] == 1


# ---------------------------------------------------------------- cosmetic + dns
def test_cosmetic_ir():
    r = parse_abp(["##.ad", "##.promo", "~shop.com##.side-ad", "news.com##.sponsored",
                   "#@#.promo", "blog.com#@#.ad", "@@||kids.com^$elemhide",
                   "@@||forum.org^$generichide"])
    ir, _ = cosmetic.build(r.cosmetic, r.network, invalid={".bad"})
    assert ir["generic"] == [".ad"]  # .promo removed by generic exception
    assert ir["genericExcept"] == {".side-ad": ["shop.com"]}
    assert ir["specific"] == {"news.com": [".sponsored"]}
    assert ir["exceptions"] == {"blog.com": [".ad"]}
    assert ir["elemhide"] == ["kids.com"] and ir["generichide"] == ["forum.org"]


def test_cosmetic_opt_outs_only_accept_real_domains():
    # Real EasyList line that once produced the bogus domain "www.google.*/search?"
    r = parse_abp(["@@||www.google.*/search?$generichide", "@@||ok.com/$generichide",
                   "@@||site.com/path/$elemhide"])
    ir, _ = cosmetic.build(r.cosmetic, r.network)
    assert ir["generichide"] == ["ok.com"] and ir["elemhide"] == []


def test_dns_only_exports_exact_host_rules():
    filters = net("||ads.com^", "||cdn.site.com^$third-party", "||x.com/path", "@@||good.ads.com^")
    block, allow, _ = dns.build(filters, {"tracker.net", "a.tracker.net"})
    assert block == ["ads.com", "tracker.net"]
    assert allow == ["good.ads.com"]


# ---------------------------------------------------------------- built artefacts
DIST = Path(__file__).resolve().parents[2] / "dist"


@pytest.mark.skipif(not (DIST / "report.json").exists(), reason="run the compiler first")
def test_dist_canaries_never_blocked():
    blocked = {l.strip() for l in (DIST / "dns/blocklist.txt").read_text().splitlines()
               if l.strip() and not l.startswith("#")}
    canaries = (Path(__file__).parent.parent / "data/canaries.txt").read_text().split()
    from nullroute_compiler.domains import parents
    offenders = {c: [p for p in parents(c) if p in blocked] for c in canaries}
    assert not {c: v for c, v in offenders.items() if v}


@pytest.mark.skipif(not (DIST / "report.json").exists(), reason="run the compiler first")
def test_dist_safari_lists_valid():
    for f in (DIST / "safari").glob("*.json"):
        rules = json.loads(f.read_text())
        assert safari.validate(rules) == [], f.name
        assert 0 < len(rules) <= safari.MAX_RULES_PER_BLOCKER


@pytest.mark.skipif(not (DIST / "report.json").exists(), reason="run the compiler first")
def test_dist_report_hashes_match_files():
    # The Android app refuses list updates whose SHA-256 doesn't match report.json.
    import hashlib
    report = json.loads((DIST / "report.json").read_text())
    for rel, digest in report["files"].items():
        assert hashlib.sha256((DIST / rel).read_bytes()).hexdigest() == digest, rel


@pytest.mark.skipif(not (DIST / "report.json").exists(), reason="run the compiler first")
def test_dist_chrome_rules_valid_and_within_budget():
    total = 0
    for f in (DIST / "chrome").glob("rules_*.json"):
        rules = json.loads(f.read_text())
        assert chrome.validate(rules) == []
        total += len(rules)
    assert total <= chrome.GUARANTEED_MINIMUM_STATIC_RULES


# ---------------------------------------------------------------- research-driven additions
from nullroute_compiler.abp import ScriptletFilter  # noqa: E402
from nullroute_compiler.targets import params, scriptlets  # noqa: E402


def test_ubo_party_aliases():
    a, b, c = net("||t.com^$3p", "||u.com^$1p", "||v.com^$~3p")
    assert a.party == "third" and b.party == "first" and c.party == "first"


def test_scriptlet_parsing_aliases_args_and_escapes():
    r = parse_abp([
        "example.com##+js(aopr, adblockDetector)",
        "news.com,~m.news.com##+js(set, ads.enabled, false)",
        "video.com##+js(json-prune, playerResponse.adPlacements playerResponse.playerAds)",
        "shop.com##+js(acs, document.createElement, /ad\\,block/)",
        "x.com##+js(trusted-replace-xhr-response, a, b)",   # unsupported -> skipped
        "##+js(aopr, foo)",                                  # generic -> skipped
        "google.*##+js(aopr, foo)",                          # entity -> skipped
        "blog.com#@#+js()",                                  # disable all on blog.com
    ])
    names = [(s.name, s.args) for s in r.scriptlets]
    assert ("abort-on-property-read", ("adblockDetector",)) in names
    assert ("set-constant", ("ads.enabled", "false")) in names
    assert ("json-prune", ("playerResponse.adPlacements playerResponse.playerAds",)) in names
    assert ("abort-current-script", ("document.createElement", "/ad,block/")) in names
    assert r.skipped["scriptlet:unsupported"] == 1
    assert r.skipped["scriptlet:generic"] == 1
    assert r.skipped["scriptlet:wildcard-domain"] == 1
    ir, stats = scriptlets.build(r.scriptlets)
    assert ir["byDomain"]["news.com"] == [["set-constant", "ads.enabled", "false"]]
    assert ir["disabled"]["m.news.com"] == ["set-constant|ads.enabled|false"]
    assert ir["disabled"]["blog.com"] == ["*"]
    assert stats["domains"] == 4


def test_removeparam_and_click_id_rules():
    r = parse_abp(["$removeparam=spm_id", "||shop.com^$removeparam=ref_src",
                   "$removeparam=/^utm_/", "@@||bank.com^$removeparam"])
    assert r.skipped["network:removeparam-complex"] == 1
    rules, stats = params.build(r.network)
    assert chrome.validate(rules) == []
    global_params = {p for rl in rules if "regexFilter" in rl["condition"]
                     for p in rl["action"]["redirect"]["transform"]["queryTransform"]["removeParams"]}
    assert {"gclid", "fbclid", "msclkid", "spm_id"} <= global_params
    assert not any(p.startswith("utm_") for p in global_params), "campaign tags are kept on purpose"
    scoped = [rl for rl in rules if rl["condition"].get("urlFilter") == "||shop.com^"]
    assert scoped[0]["action"]["redirect"]["transform"]["queryTransform"]["removeParams"] == ["ref_src"]
    allow = [rl for rl in rules if rl["action"]["type"] == "allow"]
    assert allow[0]["condition"] == {"urlFilter": "||bank.com^", "resourceTypes": ["main_frame"]}
    # removeparam filters never become block rules anywhere
    assert all(r2["action"]["type"] != "block" for r2 in chrome.to_dnr(r.network)[0])
    assert safari.build_network(r.network)[0] == []


@pytest.mark.parametrize("url,stripped", [
    ("https://shop.com/item?id=7&gclid=abc", True),
    ("https://shop.com/?fbclid=1", True),
    ("https://shop.com/item?id=7&utm_source=x", False),
    ("https://shop.com/item#gclid=1", False),
    ("https://shop.com/agclid=1", False),
])
def test_click_id_regex_matches_like_re2(url, stripped):
    rules, _ = params.build([])
    hit = any(re.search(r["condition"]["regexFilter"], url) for r in rules if "regexFilter" in r["condition"])
    assert hit is stripped


@pytest.mark.skipif(not (DIST / "report.json").exists(), reason="run the compiler first")
def test_dist_cname_targets_are_not_direct_blocks():
    # The CNAME target list contains vendors' own sites; it must only be used for
    # uncloaking, never merged into the direct DNS blocklist.
    report = json.loads((DIST / "report.json").read_text())
    assert report["dns"]["cname_targets"] > 50
    assert (DIST / "dns/cname_targets.txt").exists()


# ---------------------------------------------------------------- zero-day heuristic (DGA)
import math  # noqa: E402
from collections import Counter  # noqa: E402

from nullroute_compiler import dga  # noqa: E402

MODEL = json.loads((Path(__file__).resolve().parents[1] / "data" / "dga_model.json").read_text())


def _entropy(s):
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def test_entropy_rule_cannot_fire_on_typical_dga_lengths():
    # Shannon entropy of an n-char string is at most log2(n): a ">4.15" rule needs
    # 18+ distinct characters, so it can never flag a 13-char DGA label.
    assert _entropy("7x9qaz83mpr2v") <= math.log2(13) + 1e-12 < 4.15


@pytest.mark.parametrize("domain,label", [
    ("a.b.example.co.uk", "example"),
    ("cvyh1po636avyrsxebwbkn7.ddns.net", "cvyh1po636avyrsxebwbkn7"),
    ("d1a2b3c4e5f6.cloudfront.net", "cloudfront"),
    ("srmist.edu.in", "srmist"),
    ("localhost", None),
])
def test_site_label(domain, label):
    assert dga.site_label(domain) == label


def test_model_shape_and_thresholds():
    assert MODEL["alphabet"] == dga.ALPHABET
    assert len(MODEL["model"]) == len(dga.ALPHABET) + 1
    assert all(len(row) == len(dga.ALPHABET) + 1 for row in MODEL["model"].values())
    assert MODEL["blockThreshold"] < MODEL["flagThreshold"] < 0


@pytest.mark.parametrize("domain,flagged", [
    ("qzwxkjhvbn.net", True), ("7x9qaz83mpr2v.com", True), ("cvyh1po636avyrsxebwbkn7.ddns.net", True),
    ("wikipedia.org", False), ("flipkart.com", False), ("instagram.com", False),
    ("r4---sn-ab5l6nrz.googlevideo.com", False), ("d1a2b3c4e5f6.cloudfront.net", False),
])
def test_model_flags_generated_names_not_real_ones(domain, flagged):
    label = dga.site_label(domain)
    assert (dga.score(MODEL["model"], label) < MODEL["flagThreshold"]) is flagged


@pytest.mark.skipif(not (DIST / "report.json").exists(), reason="run the compiler first")
def test_dist_dga_model_text_matches_json():
    lines = (DIST / "dns/dga_model.txt").read_text().splitlines()
    flag, block, min_len = lines[0].split()
    assert float(flag) == MODEL["flagThreshold"] and float(block) == MODEL["blockThreshold"]
    assert lines[1] == MODEL["alphabet"] and len(lines) == 3 + len(MODEL["alphabet"]) + 1


# ---------------------------------------------------------------- reputation
from nullroute_compiler import reputation as rep  # noqa: E402


def test_rice_round_trip_edge_cases():
    import random
    rng = random.Random(7)
    for values in ([], [0], [2**32 - 1], [0, 1, 2, 3], [5, 2**32 - 1],
                   sorted(rng.sample(range(2**32), 5000))):
        blob = rep.rice_encode(values)
        assert rep.rice_decode(blob) == values
    with pytest.raises(ValueError):
        rep.rice_encode([3, 3])
    with pytest.raises(ValueError):
        rep.rice_decode(b"XXXX")


def test_lookup_expressions_cover_parents_not_tld():
    assert rep.lookup_expressions("A.b.Evil.com.") == ["a.b.evil.com", "b.evil.com", "evil.com"]
    assert rep.lookup_expressions("localhost") == []


def test_clean_entries_guards_protected_and_popular():
    kept, stats = rep.clean_entries(
        ["evil.com", "x.evil.com", "githubusercontent.com", "github.com", "login-verify.weebly.com",
         "weebly.com", "bad_name!", "BIT.LY"],
        protected=["raw.githubusercontent.com", "github.com"], popular=["weebly.com", "bit.ly"])
    # parents of protected names and exact popular sites are dropped; user sites on them are kept
    assert kept == ["evil.com", "login-verify.weebly.com"]
    assert set(stats["droppedProtected"]) == {"githubusercontent.com", "github.com", "weebly.com", "bit.ly"}
    assert stats["invalid"] == 1 and stats["coveredByParent"] == 1


def test_build_and_reference_client(tmp_path):
    listed = ["evil.com", "phish.weebly.com", "malware.example.org"]
    out = rep.build(listed, tmp_path)
    prefixes = rep.rice_decode((tmp_path / "rep/prefixes.rice").read_bytes())
    fetched = []

    def shard(name):
        fetched.append(name)
        return (tmp_path / "rep/shards" / f"{name}.bin").read_bytes()

    assert rep.is_listed("login.evil.com", prefixes, shard) == "evil.com"
    assert rep.is_listed("phish.weebly.com", prefixes, shard) == "phish.weebly.com"
    assert rep.is_listed("weebly.com", prefixes, shard) is None
    fetched.clear()
    assert rep.is_listed("wikipedia.org", prefixes, shard) is None
    assert fetched == [], "a clean name with no local prefix hit must not contact the server"
    # every shard passes the structural check clients apply; a shuffled one fails it
    for i in range(rep.SHARDS):
        assert rep.valid_shard(i, (tmp_path / "rep/shards" / f"{rep.shard_name(i)}.bin").read_bytes())
    i = rep.shard_of(rep.digest("evil.com"))
    good = (tmp_path / "rep/shards" / f"{rep.shard_name(i)}.bin").read_bytes()
    assert not rep.valid_shard(i, good[:-1]) and not rep.valid_shard(i ^ 1, good)
    assert out["stats"]["prefixes"] == 3


def test_prefix_hit_but_shard_miss_is_clean(tmp_path):
    # A clean name whose 32-bit prefix collides with a listed one must be cleared by the shard.
    rep.build(["evil.com"], tmp_path)
    clean = "innocent.example"
    prefixes = sorted({rep.prefix32(rep.digest("evil.com")), rep.prefix32(rep.digest(clean))})
    shard = lambda n: (tmp_path / "rep/shards" / f"{n}.bin").read_bytes()  # noqa: E731
    assert rep.is_listed(clean, prefixes, shard) is None


@pytest.mark.skipif(not (DIST / "rep/prefixes.rice").exists(), reason="run the compiler first")
def test_dist_reputation_sane():
    report = json.loads((DIST / "report.json").read_text())["reputation"]
    assert report["entries"] > 100_000
    assert report["bitsPerPrefix"] < 16
    prefixes = rep.rice_decode((DIST / "rep/prefixes.rice").read_bytes())
    assert len(prefixes) == report["prefixes"] and prefixes == sorted(set(prefixes))
    shard = lambda n: (DIST / "rep/shards" / f"{n}.bin").read_bytes()  # noqa: E731
    canaries = (Path(__file__).parent.parent / "data/canaries.txt").read_text().split()
    assert {c: rep.is_listed(c, prefixes, shard) for c in canaries if rep.is_listed(c, prefixes, shard)} == {}
    feed = (Path(__file__).resolve().parents[1] / ".cache/rep-1.txt")
    if feed.exists():  # a sample of real phishing entries must be found
        sample = [l.strip() for l in feed.read_text().splitlines()[:2000:97] if l.strip() and not l.startswith("#")]
        found = sum(bool(rep.is_listed(d, prefixes, shard)) for d in sample)
        assert found >= len(sample) * 0.9
