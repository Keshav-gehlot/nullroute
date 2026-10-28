"""Safari / WebKit content-blocker JSON target (iOS + macOS).

WebKit evaluates rules in order, and ``ignore-previous-rules`` only cancels
rules that came *before* it in the same list, so output order is:

    block rules -> exception rules -> $important block rules

WebKit's url-filter regex dialect has no alternation (``|``) and no
quantifier ranges, so ABP's separator ``^`` is expanded into a character
class rather than the ``(x|$)`` form other converters emit.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from ..abp import CosmeticFilter, NetworkFilter
from ..domains import minimize

# Safari 15+ allows 150k rules per content blocker extension.
MAX_RULES_PER_BLOCKER = 150_000
SELECTORS_PER_RULE = 250

TYPE_MAP = {
    "script": "script",
    "image": "image",
    "stylesheet": "style-sheet",
    "font": "font",
    "media": "media",
    "xmlhttprequest": "raw",
    "websocket": "raw",
    "ping": "raw",
    "other": "raw",
    "object": "raw",
}
# Everything a page loads, minus top-level navigation and popups.
DEFAULT_TYPES = ["font", "image", "media", "raw", "script", "style-sheet", "svg-document"]

_SEP = "[^a-zA-Z0-9_.%-]"
_HOST_PREFIX = "^[a-z][a-z0-9.+-]*:(//)?([^/:?#]+\\.)?"
_REGEX_SPECIALS = set(".+?()[]{}|\\$/")


def abp_to_regex(pattern: str) -> str:
    """Translate an ABP pattern to a WebKit url-filter regex."""
    if not pattern:
        return ".*"
    out: list[str] = []
    p = pattern
    if p.startswith("||"):
        out.append(_HOST_PREFIX)
        p = p[2:]
    elif p.startswith("|"):
        out.append("^")
        p = p[1:]
    end_anchor = p.endswith("|")
    if end_anchor:
        p = p[:-1]
    for i, ch in enumerate(p):
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append(f"({_SEP}.*)?$" if i == len(p) - 1 and not end_anchor else _SEP)
        elif ch in _REGEX_SPECIALS:
            out.append("\\" + ch)
        else:
            out.append(ch)
    if end_anchor:
        out.append("$")
    regex = "".join(out)
    while regex.startswith(".*.*"):
        regex = regex[2:]
    return regex or ".*"


def _star(domains: Iterable[str]) -> list[str]:
    return [f"*{d}" for d in sorted(domains)]


def _network_rule(f: NetworkFilter) -> list[dict] | None:
    if f.exclude_request_domains:
        return None  # WebKit has no request-domain exclusion
    if f.include_domains and f.exclude_domains:
        return None  # WebKit cannot combine if-domain and unless-domain
    trigger: dict = {"url-filter": abp_to_regex(f.pattern)}
    if f.match_case:
        trigger["url-filter-is-case-sensitive"] = True

    if f.exception and f.document:
        if not f.pure_domain:
            return None
        return [{"trigger": {"url-filter": ".*", "if-domain": [f"*{f.pure_domain}"]},
                 "action": {"type": "ignore-previous-rules"}}]

    if f.resource_types:
        types = sorted({TYPE_MAP[t] for t in f.resource_types if t in TYPE_MAP})
        frames = "sub_frame" in f.resource_types
    elif f.excluded_resource_types:
        excluded = {TYPE_MAP.get(t) for t in f.excluded_resource_types}
        types = [t for t in DEFAULT_TYPES if t not in excluded]
        frames = "sub_frame" not in f.excluded_resource_types
    else:
        types, frames = list(DEFAULT_TYPES), bool(f.pure_domain)

    if f.party == "third":
        trigger["load-type"] = ["third-party"]
    elif f.party == "first":
        trigger["load-type"] = ["first-party"]
    if f.include_domains:
        trigger["if-domain"] = _star(f.include_domains)
    elif f.exclude_domains:
        trigger["unless-domain"] = _star(f.exclude_domains)

    action = {"type": "ignore-previous-rules" if f.exception else "block"}
    rules = []
    if types:
        rules.append({"trigger": {**trigger, "resource-type": types}, "action": action})
    if frames and f.party != "first":
        # A third-party "document" load can only be a frame, never the tab.
        rules.append({"trigger": {**trigger, "resource-type": ["document"],
                                  "load-type": ["third-party"]}, "action": action})
    return rules or None


def build_network(filters: Iterable[NetworkFilter], hosts: Iterable[str] = ()) -> tuple[list[dict], dict]:
    blocks, exceptions, important = [], [], []
    skipped = 0
    seen: set[str] = set()
    for f in filters:
        if (f.elemhide or f.generichide) and not f.document:
            continue
        if f.removeparam is not None:
            continue  # WebKit content blockers cannot rewrite URLs
        rules = _network_rule(f)
        if not rules:
            skipped += 1
            continue
        bucket = exceptions if f.exception else important if f.important else blocks
        for r in rules:
            key = repr(r)
            if key not in seen:
                seen.add(key)
                bucket.append(r)
    for d in minimize(hosts):
        r = {"trigger": {"url-filter": abp_to_regex(f"||{d}^"), "resource-type": DEFAULT_TYPES},
             "action": {"type": "block"}}
        if repr(r) not in seen:
            seen.add(repr(r))
            blocks.append(r)
    rules = blocks + exceptions + important
    return rules, {"rules": len(rules), "skipped": skipped,
                   "over_limit": len(rules) > MAX_RULES_PER_BLOCKER}


_ALLOWED_TYPES = {"document", "image", "style-sheet", "script", "font", "raw", "svg-document",
                  "media", "popup", "ping", "fetch", "websocket", "other"}
_ALLOWED_ACTIONS = {"block", "block-cookies", "css-display-none", "ignore-previous-rules",
                    "make-https"}
_DOMAIN_RE = re.compile(r"^\*?[a-z0-9.-]+$")


def validate_url_filter(rx: str) -> str | None:
    """Mirror WebKit's URLFilterParser restrictions. Returns an error or None."""
    if not rx:
        return "empty url-filter"
    if any(ord(c) > 127 for c in rx):
        return "non-ASCII"
    i, depth, in_set = 0, 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            if i + 1 >= len(rx):
                return "dangling escape"
            if rx[i + 1].isdigit() or rx[i + 1] in "bBdDsSwW":
                return f"unsupported escape \\{rx[i + 1]}"
            i += 2
            continue
        if in_set:
            if c == "]":
                in_set = False
        elif c == "[":
            in_set = True
        elif c == "|":
            return "disjunction (|) is not supported"
        elif c == "{":
            return "counted repetition ({n,m}) is not supported"
        elif c == "(":
            if rx[i + 1:i + 2] == "?":
                return "lookaround / non-capturing syntax is not supported"
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return "unbalanced parentheses"
        elif c == "^" and i != 0:
            return "^ is only allowed at the start"
        elif c == "$" and i != len(rx) - 1:
            return "$ is only allowed at the end"
        i += 1
    if depth or in_set:
        return "unbalanced group or set"
    return None


def validate(rules: list[dict]) -> list[str]:
    """Structural checks matching WebKit's ContentExtensionParser."""
    errors: list[str] = []
    if len(rules) > MAX_RULES_PER_BLOCKER:
        errors.append(f"{len(rules)} rules exceeds {MAX_RULES_PER_BLOCKER}")
    for n, r in enumerate(rules):
        t, a = r.get("trigger", {}), r.get("action", {})
        if a.get("type") not in _ALLOWED_ACTIONS:
            errors.append(f"#{n}: bad action {a.get('type')}")
        if a.get("type") == "css-display-none" and not a.get("selector"):
            errors.append(f"#{n}: css-display-none without selector")
        err = validate_url_filter(t.get("url-filter", ""))
        if err:
            errors.append(f"#{n}: {err}: {t.get('url-filter')!r}")
        if "if-domain" in t and "unless-domain" in t:
            errors.append(f"#{n}: if-domain and unless-domain together")
        for k in ("if-domain", "unless-domain"):
            if k in t and (not t[k] or not all(_DOMAIN_RE.match(d) for d in t[k])):
                errors.append(f"#{n}: bad {k}")
        bad_types = set(t.get("resource-type", [])) - _ALLOWED_TYPES
        if bad_types:
            errors.append(f"#{n}: unknown resource types {bad_types}")
        if "resource-type" in t and not t["resource-type"]:
            errors.append(f"#{n}: empty resource-type")
    return errors


def build_cosmetic(cosmetic_ir: dict) -> tuple[list[dict], dict]:
    """Build from the shared cosmetic IR produced by targets.cosmetic.build."""
    rules: list[dict] = []
    exc_by_sel: dict[str, set[str]] = defaultdict(set)
    for d, sels in cosmetic_ir["exceptions"].items():
        for s in sels:
            exc_by_sel[s].add(d)

    def hide(selectors: list[str], **trigger_extra) -> None:
        for i in range(0, len(selectors), SELECTORS_PER_RULE):
            rules.append({"trigger": {"url-filter": ".*", **trigger_extra},
                          "action": {"type": "css-display-none",
                                     "selector": ", ".join(selectors[i:i + SELECTORS_PER_RULE])}})

    # 1. Generic selectors with no exceptions, batched.
    plain = [s for s in cosmetic_ir["generic"] if s not in exc_by_sel]
    hide(plain)
    # 2. Generic selectors that some sites exempt -> unless-domain.
    excepted: dict[tuple, list[str]] = defaultdict(list)
    for s in cosmetic_ir["generic"]:
        if s in exc_by_sel:
            excepted[tuple(sorted(exc_by_sel[s]))].append(s)
    for s, doms in cosmetic_ir["genericExcept"].items():
        excepted[tuple(sorted(set(doms) | exc_by_sel.get(s, set())))].append(s)
    for doms, sels in excepted.items():
        hide(sels, **{"unless-domain": _star(minimize(doms))})
    # 3. Sites that opted out of generic hiding.
    if cosmetic_ir["generichide"]:
        rules.append({"trigger": {"url-filter": ".*", "if-domain": _star(cosmetic_ir["generichide"])},
                      "action": {"type": "ignore-previous-rules"}})
    # 4. Site-specific selectors, one batch per domain.
    for d, sels in cosmetic_ir["specific"].items():
        keep = [s for s in sels if s not in cosmetic_ir["exceptions"].get(d, ())]
        if keep:
            hide(keep, **{"if-domain": [f"*{d}"]})
    # 5. Sites that opted out of all hiding.
    if cosmetic_ir["elemhide"]:
        rules.append({"trigger": {"url-filter": ".*", "if-domain": _star(cosmetic_ir["elemhide"])},
                      "action": {"type": "ignore-previous-rules"}})
    return rules, {"rules": len(rules), "over_limit": len(rules) > MAX_RULES_PER_BLOCKER}
