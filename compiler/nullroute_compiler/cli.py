"""nullroute-compile: fetch filter lists and emit per-platform rule files.

    python -m nullroute_compiler --sources sources.json --out ../dist

Outputs:
    dist/chrome/rules_<ruleset>.json   declarativeNetRequest static rulesets
    dist/chrome/cosmetic.json          element-hiding data for the extension
    dist/chrome/rulesets.json          ruleset metadata (names, counts)
    dist/safari/<blocker>.json         WebKit content-blocker lists
    dist/dns/blocklist.txt             one domain per line (Android sinkhole)
    dist/dns/allowlist.txt
    dist/rep/...                       phishing/malware hash-prefix set + shards
    dist/report.json                   stats, list versions, sha256 of outputs
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .abp import ParseResult, detect_format, parse_abp, parse_hosts
from . import reputation
from .targets import chrome, cosmetic, dns, params, safari, scriptlets

ALL_TARGETS = ("chrome", "safari", "dns")
from .validate import validate_selectors

USER_AGENT = "NullRoute-Compiler/1.0 (+https://github.com/Keshav-gehlot/nullroute)"


def fetch(url: str, cache: Path | None, offline: bool, name: str) -> str:
    cached = cache / f"{name}.txt" if cache else None
    if offline:
        if not cached or not cached.exists():
            raise SystemExit(f"--offline but no cached copy of {url} at {cached}")
        return cached.read_text(encoding="utf-8", errors="replace")
    last_err = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as r:
                text = r.read().decode("utf-8", errors="replace")
            if len(text) < 1000:
                raise ValueError(f"suspiciously small response ({len(text)} bytes)")
            if cached:
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_text(text, encoding="utf-8")
            return text
        except Exception as e:  # noqa: BLE001 - retried, then reported
            last_err = e
            time.sleep(2 ** attempt)
    if cached and cached.exists():
        print(f"  ! fetch failed ({last_err}); using cached {cached.name}", file=sys.stderr)
        return cached.read_text(encoding="utf-8", errors="replace")
    raise SystemExit(f"failed to fetch {url}: {last_err}")


def list_version(text: str) -> str | None:
    m = re.search(r"^!\s*(?:Version|Last modified):\s*(.+)$", text, re.M) or \
        re.search(r"^#\s*(?:Date|Last modified|Version):\s*(.+)$", text, re.M)
    return m.group(1).strip() if m else None


def write_json(path: Path, data, pretty: bool = False) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, indent=1 if pretty else None, separators=None if pretty else (",", ":"),
                     ensure_ascii=True) + "\n"
    blob = raw.encode("utf-8")
    path.write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()  # hash of the exact bytes on disk


def write_lines(path: Path, lines: list[str], header: list[str]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = ("\n".join([f"# {h}" for h in header] + lines) + "\n").encode("utf-8")
    path.write_bytes(blob)  # write_bytes: no newline translation, so the hash always matches
    return hashlib.sha256(blob).hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nullroute-compile", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", type=Path, default=Path(__file__).parent.parent / "sources.json")
    ap.add_argument("--out", type=Path, default=Path("dist"))
    ap.add_argument("--cache", type=Path, default=Path(".cache"))
    ap.add_argument("--offline", action="store_true", help="use cached lists only")
    ap.add_argument("--validate-selectors", choices=["auto", "on", "off"], default="auto",
                    help="check every CSS selector with a real Chromium CSS parser (Playwright)")
    args = ap.parse_args(argv)

    config = json.loads(args.sources.read_text())
    out: Path = args.out
    report: dict = {"generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "rulesets": {}, "files": {}}

    parsed: dict[str, ParseResult] = {}
    for rs in config["rulesets"]:
        result = ParseResult()
        versions = []
        for i, src in enumerate(rs["sources"]):
            name = f"{rs['id']}-{i}"
            if "file" in src:  # a list maintained in this repository
                text = (args.sources.resolve().parent / src["file"]).read_text(encoding="utf-8")
                origin = src["file"]
            else:
                text = fetch(src["url"], args.cache, args.offline, name)
                origin = src["url"]
            print(f"• {rs['id']}: {origin}")
            fmt = src.get("format") or detect_format(text[:4096])
            result.extend(parse_abp(text.splitlines()) if fmt == "abp" else parse_hosts(text.splitlines()))
            versions.append({"url": origin, "version": list_version(text),
                             "license": src.get("license"), "format": fmt})
        parsed[rs["id"]] = result
        report["rulesets"][rs["id"]] = {
            "sources": versions,
            "parse": {"lines": result.total_lines, "network": len(result.network),
                      "cosmetic": len(result.cosmetic), "scriptlets": len(result.scriptlets),
                      "hosts": len(result.hosts),
                      "skipped": dict(result.skipped.most_common())},
        }

    def targeting(platform: str) -> list[dict]:
        return [rs for rs in config["rulesets"] if platform in rs.get("targets", ALL_TARGETS)]

    chrome_sets, safari_sets, dns_sets = targeting("chrome"), targeting("safari"), targeting("dns")

    # ---- Cosmetic: validate every selector once, build per-platform IR ------
    all_cosmetic = [c for r in parsed.values() for c in r.cosmetic]
    invalid: set[str] = set()
    if args.validate_selectors != "off" and all_cosmetic:
        selectors = sorted({c.selector for c in all_cosmetic})
        try:
            invalid = validate_selectors(selectors)
            print(f"• validated {len(selectors)} selectors in Chromium: {len(invalid)} invalid")
            report["selectorValidation"] = {"checked": len(selectors), "invalid": sorted(invalid)}
        except RuntimeError as e:
            if args.validate_selectors == "on":
                raise SystemExit(str(e))
            print(f"  ! selector validation skipped: {e}", file=sys.stderr)

    def cosmetic_for(sets: list[dict]):
        return cosmetic.build([c for rs in sets for c in parsed[rs["id"]].cosmetic],
                              [n for rs in sets for n in parsed[rs["id"]].network], invalid)

    cosmetic_ir, cstats = cosmetic_for(chrome_sets)
    report["cosmetic"] = cstats
    report["files"]["chrome/cosmetic.json"] = write_json(out / "chrome" / "cosmetic.json", cosmetic_ir)

    # ---- Chrome DNR ---------------------------------------------------------
    meta = []
    total_rules = 0

    def emit_chrome(rs_id: str, name: str, description: str, enabled: bool, rules: list[dict], stats: dict):
        nonlocal total_rules
        errors = chrome.validate(rules)
        if errors:
            for e in errors[:20]:
                print("  ✗", e, file=sys.stderr)
            raise SystemExit(f"{len(errors)} invalid DNR rules in {rs_id}")
        total_rules += len(rules)
        fname = f"rules_{rs_id}.json"
        report["files"][f"chrome/{fname}"] = write_json(out / "chrome" / fname, rules)
        report["rulesets"].setdefault(rs_id, {})["chrome"] = stats
        meta.append({"id": rs_id, "name": name, "description": description, "enabled": enabled,
                     "path": f"rulesets/{fname}", "rules": len(rules)})

    for rs in chrome_sets:
        r = parsed[rs["id"]]
        rules, stats = chrome.to_dnr(r.network, r.hosts)
        emit_chrome(rs["id"], rs["name"], rs["description"], rs["enabledByDefault"], rules, stats)

    # Link-decoration stripping, from built-in click IDs + lists' $removeparam.
    prules, pstats = params.build(n for rs in chrome_sets for n in parsed[rs["id"]].network)
    emit_chrome("params", "Link tracking", "Removes click IDs such as gclid and fbclid from links",
                True, prules, pstats)

    if total_rules > chrome.GUARANTEED_MINIMUM_STATIC_RULES:
        print(f"  ! {total_rules} static rules exceeds Chrome's guaranteed "
              f"{chrome.GUARANTEED_MINIMUM_STATIC_RULES}; extra rulesets use the shared pool",
              file=sys.stderr)
    report["chromeTotalRules"] = total_rules
    report["files"]["chrome/rulesets.json"] = write_json(
        out / "chrome" / "rulesets.json",
        {"generatedAt": report["generatedAt"], "rulesets": meta}, pretty=True)

    # ---- Chrome scriptlets (MAIN-world defusers) ------------------------------
    sc_ir, sc_stats = scriptlets.build(s for rs in chrome_sets for s in parsed[rs["id"]].scriptlets)
    report["files"]["chrome/scriptlets.json"] = write_json(out / "chrome" / "scriptlets.json", sc_ir)
    report["scriptlets"] = sc_stats

    # ---- Safari ---------------------------------------------------------------
    for rs in safari_sets:
        r = parsed[rs["id"]]
        rules, stats = safari.build_network(r.network, r.hosts)
        errors = safari.validate(rules)
        if errors:
            for e in errors[:20]:
                print("  ✗", e, file=sys.stderr)
            raise SystemExit(f"{len(errors)} invalid Safari rules in {rs['id']}")
        report["files"][f"safari/{rs['id']}.json"] = write_json(out / "safari" / f"{rs['id']}.json", rules)
        report["rulesets"][rs["id"]]["safari"] = stats
    safari_cosmetic_ir, _ = cosmetic_for(safari_sets)
    srules, sstats = safari.build_cosmetic(safari_cosmetic_ir)
    errors = safari.validate(srules)
    if errors:
        raise SystemExit(f"{len(errors)} invalid Safari cosmetic rules, e.g. {errors[0]}")
    report["files"]["safari/cosmetic.json"] = write_json(out / "safari" / "cosmetic.json", srules)
    report["safariCosmetic"] = sstats

    # ---- DNS --------------------------------------------------------------------
    hosts = set().union(*(parsed[rs["id"]].hosts for rs in dns_sets))
    block, allow, dstats = dns.build([n for rs in dns_sets for n in parsed[rs["id"]].network], hosts)
    header = [f"NullRoute DNS blocklist — generated {report['generatedAt']}",
              "Sources: " + ", ".join(s.get("url") or s["file"] for rs in dns_sets for s in rs["sources"])]
    report["files"]["dns/blocklist.txt"] = write_lines(out / "dns" / "blocklist.txt", block, header)
    report["files"]["dns/allowlist.txt"] = write_lines(out / "dns" / "allowlist.txt", allow, header)
    report["dns"] = dstats

    # CNAME-uncloaking targets: only consulted when a lookup's answer aliases to them.
    if "cnameTargets" in config:
        src = config["cnameTargets"]
        text = fetch(src["url"], args.cache, args.offline, "cnametargets-0")
        targets = {n.pure_domain for n in parse_abp(text.splitlines()).network
                   if n.pure_domain and not n.exception} | parse_hosts(
                       l for l in text.splitlines() if not l.startswith(("||", "!", "@@"))).hosts
        report["files"]["dns/cname_targets.txt"] = write_lines(
            out / "dns" / "cname_targets.txt", sorted(targets),
            ["CNAME targets: block a lookup only when its answer aliases to one of these", src["url"]])
        report["dns"]["cname_targets"] = len(targets)

    # DGA heuristic model (trained offline by `python -m nullroute_compiler.dga train`).
    model_path = Path(__file__).resolve().parent.parent / "data" / "dga_model.json"
    if model_path.exists():
        m = json.loads(model_path.read_text())
        lines = [f"{m['flagThreshold']} {m['blockThreshold']} {m['minLength']}", m["alphabet"],
                 " ".join(m["dynamicDnsSuffixes"] + m["multiPartSuffixes"])]
        lines += [" ".join(str(v) for v in m["model"][a]) for a in "^" + m["alphabet"]]
        blob = ("\n".join(lines) + "\n").encode()
        (out / "dns").mkdir(parents=True, exist_ok=True)
        (out / "dns" / "dga_model.txt").write_bytes(blob)
        report["files"]["dns/dga_model.txt"] = hashlib.sha256(blob).hexdigest()
        report["dns"]["dga"] = {"flagThreshold": m["flagThreshold"], "blockThreshold": m["blockThreshold"]}

    # ---- Reputation (hash-prefix set + shards) --------------------------------
    if "reputation" in config:
        rc = config["reputation"]
        feed: list[str] = []
        rep_sources = []
        for i, src in enumerate(rc["sources"]):
            print(f"• reputation: {src['url']}")
            text = fetch(src["url"], args.cache, args.offline, f"rep-{i}")
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    parts = line.split()
                    feed.append(parts[1] if len(parts) > 1 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0])
            rep_sources.append({"url": src["url"], "version": list_version(text), "license": src.get("license")})
        popular = fetch(rc["popular"]["url"], args.cache, args.offline, "rep-popular").split()
        canaries = (Path(__file__).resolve().parent.parent / "data" / "canaries.txt").read_text().split()
        entries, rstats = reputation.clean_entries(feed, canaries, popular)
        built = reputation.build(entries, out)
        report["files"].update(built["files"])
        report["reputation"] = {"sources": rep_sources, **rstats, **built["stats"]}
        write_json(out / "rep" / "meta.json", {
            "generatedAt": report["generatedAt"], "format": "see nullroute_compiler/reputation.py",
            "shardBits": reputation.SHARD_BITS, "headBytes": reputation.HEAD_BYTES,
            "entries": rstats["entries"], "prefixes": built["stats"]["prefixes"]}, pretty=True)

    write_json(out / "report.json", report, pretty=True)
    print(f"✓ Chrome: {total_rules} DNR rules | cosmetic: {cstats['generic']} generic + "
          f"{cstats['specific_selectors']} site-specific selectors")
    print(f"✓ Link tracking: {pstats['global_params']} click-ID params, {pstats['rules']} rules | "
          f"scriptlets: {sc_stats['rules']} on {sc_stats['domains']} sites")
    print(f"✓ Safari: " + ", ".join(f"{k}={v['safari']['rules']}" for k, v in report["rulesets"].items()
                                    if "safari" in v) + f", cosmetic={sstats['rules']}")
    print(f"✓ DNS: {dstats['domains']} blocked domains, {dstats['allow']} allowlisted")
    if "reputation" in report:
        r = report["reputation"]
        print(f"✓ Reputation: {r['entries']} domains -> {r['prefixes']} prefixes, "
              f"{r['prefixBytes'] / 1e6:.1f} MB ({r['bitsPerPrefix']} bits each), "
              f"{len(r['droppedProtected'])} popular/protected entries dropped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
