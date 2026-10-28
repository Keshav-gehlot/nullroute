"""nullroute-compile: fetch filter lists and emit per-platform rule files.

    python -m nullroute_compiler --sources sources.json --out ../dist

Outputs:
    dist/chrome/rules_<ruleset>.json   declarativeNetRequest static rulesets
    dist/chrome/cosmetic.json          element-hiding data for the extension
    dist/chrome/rulesets.json          ruleset metadata (names, counts)
    dist/safari/<blocker>.json         WebKit content-blocker lists
    dist/dns/blocklist.txt             one domain per line (Android sinkhole)
    dist/dns/allowlist.txt
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
from .targets import chrome, cosmetic, dns, safari
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
            print(f"• {rs['id']}: {src['url']}")
            text = fetch(src["url"], args.cache, args.offline, name)
            fmt = src.get("format") or detect_format(text[:4096])
            result.extend(parse_abp(text.splitlines()) if fmt == "abp" else parse_hosts(text.splitlines()))
            versions.append({"url": src["url"], "version": list_version(text),
                             "license": src.get("license"), "format": fmt})
        parsed[rs["id"]] = result
        report["rulesets"][rs["id"]] = {
            "sources": versions,
            "parse": {"lines": result.total_lines, "network": len(result.network),
                      "cosmetic": len(result.cosmetic), "hosts": len(result.hosts),
                      "skipped": dict(result.skipped.most_common())},
        }

    # ---- Cosmetic (shared by Chrome + Safari) -----------------------------
    all_cosmetic = [c for r in parsed.values() for c in r.cosmetic]
    all_network = [n for r in parsed.values() for n in r.network]
    invalid: set[str] = set()
    if args.validate_selectors != "off":
        selectors = sorted({c.selector for c in all_cosmetic})
        try:
            invalid = validate_selectors(selectors)
            print(f"• validated {len(selectors)} selectors in Chromium: {len(invalid)} invalid")
            report["selectorValidation"] = {"checked": len(selectors), "invalid": sorted(invalid)}
        except RuntimeError as e:
            if args.validate_selectors == "on":
                raise SystemExit(str(e))
            print(f"  ! selector validation skipped: {e}", file=sys.stderr)
    cosmetic_ir, cstats = cosmetic.build(all_cosmetic, all_network, invalid)
    report["cosmetic"] = cstats
    report["files"]["chrome/cosmetic.json"] = write_json(out / "chrome" / "cosmetic.json", cosmetic_ir)

    # ---- Chrome DNR ---------------------------------------------------------
    meta = []
    total_rules = 0
    for rs in config["rulesets"]:
        r = parsed[rs["id"]]
        rules, stats = chrome.to_dnr(r.network, r.hosts)
        errors = chrome.validate(rules)
        if errors:
            for e in errors[:20]:
                print("  ✗", e, file=sys.stderr)
            raise SystemExit(f"{len(errors)} invalid DNR rules in {rs['id']}")
        total_rules += len(rules)
        fname = f"rules_{rs['id']}.json"
        report["files"][f"chrome/{fname}"] = write_json(out / "chrome" / fname, rules)
        report["rulesets"][rs["id"]]["chrome"] = stats
        meta.append({"id": rs["id"], "name": rs["name"], "description": rs["description"],
                     "enabled": rs["enabledByDefault"], "path": f"rulesets/{fname}",
                     "rules": len(rules)})
    if total_rules > chrome.GUARANTEED_MINIMUM_STATIC_RULES:
        print(f"  ! {total_rules} static rules exceeds Chrome's guaranteed "
              f"{chrome.GUARANTEED_MINIMUM_STATIC_RULES}; extra rulesets use the shared pool",
              file=sys.stderr)
    report["chromeTotalRules"] = total_rules
    report["files"]["chrome/rulesets.json"] = write_json(
        out / "chrome" / "rulesets.json",
        {"generatedAt": report["generatedAt"], "rulesets": meta}, pretty=True)

    # ---- Safari ---------------------------------------------------------------
    for rs in config["rulesets"]:
        r = parsed[rs["id"]]
        rules, stats = safari.build_network(r.network, r.hosts)
        errors = safari.validate(rules)
        if errors:
            for e in errors[:20]:
                print("  ✗", e, file=sys.stderr)
            raise SystemExit(f"{len(errors)} invalid Safari rules in {rs['id']}")
        if stats["over_limit"]:
            raise SystemExit(f"Safari blocker '{rs['id']}' has {len(rules)} rules "
                             f"(limit {safari.MAX_RULES_PER_BLOCKER})")
        report["files"][f"safari/{rs['id']}.json"] = write_json(out / "safari" / f"{rs['id']}.json", rules)
        report["rulesets"][rs["id"]]["safari"] = stats
    srules, sstats = safari.build_cosmetic(cosmetic_ir)
    errors = safari.validate(srules)
    if errors:
        raise SystemExit(f"{len(errors)} invalid Safari cosmetic rules, e.g. {errors[0]}")
    report["files"]["safari/cosmetic.json"] = write_json(out / "safari" / "cosmetic.json", srules)
    report["safariCosmetic"] = sstats

    # ---- DNS --------------------------------------------------------------------
    hosts = set().union(*(r.hosts for r in parsed.values()))
    block, allow, dstats = dns.build(all_network, hosts)
    header = [f"NullRoute DNS blocklist — generated {report['generatedAt']}",
              "Sources: " + ", ".join(s["url"] for rs in config["rulesets"] for s in rs["sources"])]
    report["files"]["dns/blocklist.txt"] = write_lines(out / "dns" / "blocklist.txt", block, header)
    report["files"]["dns/allowlist.txt"] = write_lines(out / "dns" / "allowlist.txt", allow, header)
    report["dns"] = dstats

    write_json(out / "report.json", report, pretty=True)
    print(f"✓ Chrome: {total_rules} DNR rules | cosmetic: {cstats['generic']} generic + "
          f"{cstats['specific_selectors']} site-specific selectors")
    print(f"✓ Safari: " + ", ".join(f"{k}={v['safari']['rules']}" for k, v in report["rulesets"].items())
          + f", cosmetic={sstats['rules']}")
    print(f"✓ DNS: {dstats['domains']} blocked domains, {dstats['allow']} allowlisted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
