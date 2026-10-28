"""DNS sinkhole target used by the Android app (and usable by Pi-hole etc.).

Only filters that are *exactly* equivalent to "this whole hostname is bad"
are exported: ``||domain^`` with no options, plus hosts-file entries. A
filter like ``||cdn.example.com^$third-party`` is NOT exported, because a
resolver cannot know whether a lookup is third-party, and sinkholing it
would break the first-party site.
"""
from __future__ import annotations

from typing import Iterable

from ..abp import NetworkFilter
from ..domains import minimize, subtract


def build(network: Iterable[NetworkFilter], hosts: Iterable[str]) -> tuple[list[str], list[str], dict]:
    blocked: set[str] = set(hosts)
    allowed: set[str] = set()
    from_filters = 0
    for f in network:
        d = f.pure_domain
        if not d:
            continue
        if f.exception:
            # @@||domain^ and @@||domain^$document both mean "this host is fine".
            only_doc = f.document and not (f.resource_types or f.party or f.include_domains
                                           or f.exclude_domains)
            if not f.has_modifiers or only_doc:
                allowed.add(d)
        elif not f.has_modifiers:
            blocked.add(d)
            from_filters += 1

    minimal = minimize(blocked)
    final = subtract(minimal, allowed)
    stats = {
        "from_filters": from_filters,
        "candidates": len(blocked),
        "after_minimize": len(minimal),
        "allowlisted_removed": len(minimal) - len(final),
        "domains": len(final),
        "allow": len(allowed),
    }
    return final, sorted(allowed), stats
