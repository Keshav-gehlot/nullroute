"""Element-hiding (cosmetic) target shared by the Chrome extension.

Output schema (cosmetic.json):

    {
      "generic":        [selector, ...],          # hide everywhere
      "genericExcept":  {selector: [domain,...]},  # generic, but not on these
      "specific":       {domain: [selector,...]},  # only on domain + subdomains
      "exceptions":     {domain: [selector,...]},  # never hide these here
      "elemhide":       [domain, ...],            # no cosmetic filtering at all
      "generichide":    [domain, ...]             # no *generic* filtering
    }

The extension resolves a page's hostname against this at navigation time and
injects one user-origin stylesheet, so pages can neither see nor remove it.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from ..abp import CosmeticFilter, NetworkFilter, is_valid_domain


def build(cosmetic: Iterable[CosmeticFilter], network: Iterable[NetworkFilter],
          invalid: set[str] | None = None) -> tuple[dict, dict]:
    invalid = invalid or set()
    generic: set[str] = set()
    generic_except: dict[str, set[str]] = defaultdict(set)
    specific: dict[str, set[str]] = defaultdict(set)
    exceptions: dict[str, set[str]] = defaultdict(set)
    generic_exceptions: set[str] = set()
    dropped_invalid = 0

    for f in cosmetic:
        if f.selector in invalid:
            dropped_invalid += 1
            continue
        if f.exception:
            if f.include_domains:
                for d in f.include_domains:
                    exceptions[d].add(f.selector)
            else:
                generic_exceptions.add(f.selector)
            continue
        if f.include_domains:
            for d in f.include_domains:
                specific[d].add(f.selector)
            # "example.com,~shop.example.com##.ad" -> exception on the subdomain
            for d in f.exclude_domains:
                exceptions[d].add(f.selector)
        elif f.exclude_domains:
            generic_except[f.selector].update(f.exclude_domains)
        else:
            generic.add(f.selector)

    generic -= generic_exceptions
    for sel in list(generic_except):
        if sel in generic_exceptions:
            del generic_except[sel]
        elif sel in generic:
            # Same selector also listed unconditionally: unconditional wins.
            del generic_except[sel]

    elemhide, generichide = set(), set()
    for f in network:
        if not f.exception or not (f.elemhide or f.generichide):
            continue
        d = None
        if f.pattern.startswith("||"):
            # "||example.com^" or "||example.com/" -> example.com. Anything
            # with wildcards or a path ("||www.google.*/search?") has no exact
            # domain meaning and is ignored rather than guessed at.
            host = re.split(r"[\^/]", f.pattern[2:], maxsplit=1)[0]
            rest = f.pattern[2 + len(host):]
            if is_valid_domain(host) and rest in ("", "^", "/", "^|"):
                d = host
        targets = set(f.include_domains)
        if d and not f.include_domains:
            targets.add(d)
        for t in targets:
            (elemhide if f.elemhide else generichide).add(t)

    out = {
        "generic": sorted(generic),
        "genericExcept": {s: sorted(d) for s, d in sorted(generic_except.items())},
        "specific": {d: sorted(s) for d, s in sorted(specific.items())},
        "exceptions": {d: sorted(s) for d, s in sorted(exceptions.items())},
        "elemhide": sorted(elemhide),
        "generichide": sorted(generichide),
    }
    stats = {
        "generic": len(out["generic"]),
        "generic_except": len(out["genericExcept"]),
        "specific_domains": len(out["specific"]),
        "specific_selectors": sum(len(v) for v in out["specific"].values()),
        "exception_domains": len(out["exceptions"]),
        "dropped_invalid_selectors": dropped_invalid,
    }
    return out, stats
