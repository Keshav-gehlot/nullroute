"""Domain-set utilities shared by every target."""
from __future__ import annotations

from typing import Iterable


def parents(domain: str) -> list[str]:
    """``a.b.example.com`` -> [a.b.example.com, b.example.com, example.com, com]."""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def minimize(domains: Iterable[str]) -> list[str]:
    """Drop domains already covered by a listed parent domain.

    Blocking ``example.com`` already blocks ``ads.example.com`` on every
    target we compile to (DNR ``requestDomains``, Safari ``if-domain``
    with ``*``, and the DNS sinkhole's suffix match), so listing both is
    pure waste of rule budget.
    """
    ordered = sorted(set(domains), key=lambda d: (d.count("."), d))
    kept: set[str] = set()
    for d in ordered:
        if not any(p in kept for p in parents(d)[1:]):
            kept.add(d)
    return sorted(kept)


def subtract(blocked: Iterable[str], allowed: Iterable[str]) -> list[str]:
    """Remove blocked domains that an allow rule covers (exact or parent)."""
    allow = set(allowed)
    return [d for d in blocked if not any(p in allow for p in parents(d))]
