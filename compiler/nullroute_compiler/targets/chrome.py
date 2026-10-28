"""Chrome Manifest V3 ``declarativeNetRequest`` target.

Key optimisation: every ``||domain^`` filter that shares the same options
is folded into a single rule using ``requestDomains``. On real EasyList this
turns ~40k filters into a few thousand rules, which is what lets the full
list fit inside Chrome's guaranteed static-rule budget.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Iterable

from ..abp import NetworkFilter
from ..domains import minimize

PRIORITY_BLOCK = 1
PRIORITY_ALLOW = 2
PRIORITY_IMPORTANT = 3
DOMAINS_PER_RULE = 1000

# Chrome limits (https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)
GUARANTEED_MINIMUM_STATIC_RULES = 30_000
MAX_NUMBER_OF_REGEX_RULES = 1_000


def _condition_key(f: NetworkFilter) -> dict:
    cond: dict = {}
    if f.resource_types:
        cond["resourceTypes"] = sorted(f.resource_types)
    elif f.excluded_resource_types:
        cond["excludedResourceTypes"] = sorted(f.excluded_resource_types)
    if f.party == "third":
        cond["domainType"] = "thirdParty"
    elif f.party == "first":
        cond["domainType"] = "firstParty"
    if f.include_domains:
        cond["initiatorDomains"] = sorted(f.include_domains)
    if f.exclude_domains:
        cond["excludedInitiatorDomains"] = sorted(f.exclude_domains)
    if f.exclude_request_domains:
        cond["excludedRequestDomains"] = sorted(f.exclude_request_domains)
    if f.match_case:
        cond["isUrlFilterCaseSensitive"] = True
    return cond


def _action_and_priority(f: NetworkFilter) -> tuple[dict, int, dict]:
    """Returns (action, priority, condition overrides)."""
    if f.exception and f.document:
        return ({"type": "allowAllRequests"}, PRIORITY_ALLOW,
                {"resourceTypes": ["main_frame", "sub_frame"]})
    if f.exception:
        return {"type": "allow"}, PRIORITY_ALLOW, {}
    if f.important:
        return {"type": "block"}, PRIORITY_IMPORTANT, {}
    return {"type": "block"}, PRIORITY_BLOCK, {}


def to_dnr(filters: Iterable[NetworkFilter], hosts: Iterable[str] = ()) -> tuple[list[dict], dict]:
    """Compile filters (+ optional hosts domains) into DNR rules.

    Returns (rules, stats). Rule ids are assigned 1..n.
    """
    grouped: dict[str, set[str]] = defaultdict(set)  # key -> request domains
    singles: dict[str, dict] = {}                     # dedupe key -> rule body
    stats = defaultdict(int)

    for f in filters:
        if (f.elemhide or f.generichide) and not f.document:
            stats["cosmetic_only"] += 1
            continue  # handled by the cosmetic target
        if f.removeparam is not None:
            stats["removeparam"] += 1
            continue  # handled by the params target
        action, priority, override = _action_and_priority(f)
        cond = _condition_key(f)
        cond.update(override)
        domain = f.pure_domain
        if domain and not f.match_case:
            key = json.dumps({"a": action, "p": priority, "c": cond}, sort_keys=True)
            grouped[key].add(domain)
            stats["folded"] += 1
            continue
        if f.pattern:
            cond["urlFilter"] = f.pattern
        body = {"priority": priority, "action": action, "condition": cond}
        singles[json.dumps(body, sort_keys=True)] = body
        stats["url_filter"] += 1

    host_list = list(hosts)
    if host_list:
        key = json.dumps({"a": {"type": "block"}, "p": PRIORITY_BLOCK, "c": {}}, sort_keys=True)
        grouped[key].update(host_list)
        stats["hosts"] += len(host_list)

    rules: list[dict] = []
    for key, domains in sorted(grouped.items()):
        spec = json.loads(key)
        doms = minimize(domains)
        for i in range(0, len(doms), DOMAINS_PER_RULE):
            cond = dict(spec["c"])
            cond["requestDomains"] = doms[i:i + DOMAINS_PER_RULE]
            rules.append({"priority": spec["p"], "action": spec["a"], "condition": cond})
    rules.extend(singles[k] for k in sorted(singles))

    for i, r in enumerate(rules, 1):
        r["id"] = i
        # Stable key order makes diffs between list updates readable.
        rules[i - 1] = {"id": i, "priority": r["priority"], "action": r["action"],
                        "condition": r["condition"]}
    stats["rules"] = len(rules)
    return rules, dict(stats)


def validate(rules: list[dict]) -> list[str]:
    """Static checks mirroring Chrome's ruleset loader. Returns error strings."""
    errors: list[str] = []
    seen_ids: set[int] = set()
    if sum(1 for r in rules if "regexFilter" in r["condition"]) > MAX_NUMBER_OF_REGEX_RULES:
        errors.append("too many regex rules")
    allowed_types = {"main_frame", "sub_frame", "stylesheet", "script", "image", "font",
                     "object", "xmlhttprequest", "ping", "csp_report", "media",
                     "websocket", "webtransport", "webbundle", "other"}
    for r in rules:
        rid = r.get("id")
        if not isinstance(rid, int) or rid < 1 or rid in seen_ids:
            errors.append(f"rule {rid}: bad or duplicate id")
        seen_ids.add(rid)
        c = r["condition"]
        uf = c.get("urlFilter")
        if uf is not None:
            if not uf:
                errors.append(f"rule {rid}: empty urlFilter")
            if uf.startswith("||*"):
                errors.append(f"rule {rid}: urlFilter starts with ||*")
            if any(ord(ch) > 127 for ch in uf):
                errors.append(f"rule {rid}: non-ascii urlFilter")
        for k in ("resourceTypes", "excludedResourceTypes"):
            if k in c:
                if not c[k]:
                    errors.append(f"rule {rid}: empty {k}")
                bad = set(c[k]) - allowed_types
                if bad:
                    errors.append(f"rule {rid}: unknown resource types {bad}")
        if "resourceTypes" in c and "excludedResourceTypes" in c:
            errors.append(f"rule {rid}: both resourceTypes and excludedResourceTypes")
        for k in ("requestDomains", "initiatorDomains", "excludedRequestDomains",
                  "excludedInitiatorDomains"):
            if k in c and not c[k]:
                errors.append(f"rule {rid}: empty {k}")
        if r["action"]["type"] == "allowAllRequests":
            rt = set(c.get("resourceTypes", []))
            if not rt or not rt <= {"main_frame", "sub_frame"}:
                errors.append(f"rule {rid}: allowAllRequests needs only frame types")
        if "urlFilter" in c and "regexFilter" in c:
            errors.append(f"rule {rid}: both urlFilter and regexFilter")
        if "regexFilter" in c and len(c["regexFilter"]) > 1000:
            errors.append(f"rule {rid}: regexFilter suspiciously long")
        if r["action"]["type"] == "redirect":
            red = r["action"].get("redirect", {})
            if not (red.get("url") or red.get("extensionPath") or red.get("transform")):
                errors.append(f"rule {rid}: redirect without target")
        if r["action"]["type"] not in ("block", "allow", "allowAllRequests", "redirect", "upgradeScheme"):
            errors.append(f"rule {rid}: unsupported action {r['action']['type']}")
    return errors
