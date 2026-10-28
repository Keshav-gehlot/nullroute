"""Scriptlet target: per-site JavaScript defusers run in the page's MAIN world.

Anti-adblock and ad-serving logic increasingly ships inside first-party
bundles and inline JSON, where URL blocking is too coarse (blocking the
bundle breaks the site). Scriptlets neutralise the specific property or call
instead: abort-on-property-read, set-constant, json-prune, and so on.

Output schema (scriptlets.json):

    {
      "byDomain": {domain: [[name, arg1, ...], ...]},
      "disabled": {domain: ["*" | "name|arg1|...", ...]}   # #@#+js exceptions
    }
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from ..abp import ScriptletFilter, is_valid_domain


def key(name: str, args: tuple[str, ...] | list[str]) -> str:
    return "|".join([name, *args])


def build(filters: Iterable[ScriptletFilter]) -> tuple[dict, dict]:
    by_domain: dict[str, dict[str, list[str]]] = defaultdict(dict)
    disabled: dict[str, set[str]] = defaultdict(set)
    for f in filters:
        k = "*" if f.name == "*" else key(f.name, f.args)
        if f.exception:
            for d in f.include_domains:
                disabled[d].add(k)
            continue
        for d in f.include_domains:
            if is_valid_domain(d):
                by_domain[d][k] = [f.name, *f.args]
        for d in f.exclude_domains:
            disabled[d].add(k)

    out = {
        "byDomain": {d: [v for _, v in sorted(entries.items())] for d, entries in sorted(by_domain.items())},
        "disabled": {d: sorted(s) for d, s in sorted(disabled.items()) if is_valid_domain(d)},
    }
    counts: dict[str, int] = defaultdict(int)
    for entries in out["byDomain"].values():
        for e in entries:
            counts[e[0]] += 1
    stats = {"domains": len(out["byDomain"]), "rules": sum(counts.values()), "by_scriptlet": dict(counts)}
    return out, stats
